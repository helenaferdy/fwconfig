"""AI Configuration Analysis Consultant via OpenCode / DeepSeek-V4-Flash.

Always calls the DeepSeek API (no offline stub answers).
Speed optimizations:
- Compact session digest (counts + samples, not full objects)
- Question-scoped LOOKUP injection for IPs / object names
- Compact JSON digests, short history; generous reply budget for long lists
- Strip reasoning dumps / schema echo from replies
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import httpx

from config import Settings, get_settings
from session.store import MigrationSession

logger = logging.getLogger(__name__)

# Post-parse safety caps (characters). High enough for multi-bullet policy/interface lists.
_MAX_REPLY_CHARS = 8000
_MAX_BRIEF_CHARS = 6000
# Ceiling on API max_tokens regardless of settings (avoid runaway completions).
_MAX_TOKENS_CEILING = 4000

SYSTEM_PROMPT = """You are FWConfig-AI, an expert firewall configuration analyst helping with migration review.

Rules:
- Use ONLY the DIGEST and LOOKUP JSON provided. Never invent objects, IPs, or rules.
- If LOOKUP is present, prioritize it for the answer. Hits with role "reference" or
  "match_snippet" show where a name is used (e.g. policies with av-profile).
- When LOOKUP lists policies that reference a profile/object, name those policies
  (and policy id if present). Do NOT say associations are missing if LOOKUP has them.
- Formatting: prefer bullet points whenever the answer is long or lists multiple items
  (policies, objects, IPs, interfaces, section counts, warnings, properties, etc.).
  Use a short lead sentence, then bullets (• or -), one fact per line. Avoid dense
  paragraphs of many facts. Short single-fact answers may stay as 1–2 sentences.
- Be concise but useful; for multi-item answers, bullets over prose.
- When relevant, include a highlight action for the UI section.
- Reply with a single JSON object only. No markdown fences, no chain-of-thought, no XML tags.
- Put the real answer text in the "reply" field (never placeholders like <answer>).
  Newlines in reply are fine (use \\n in JSON).

Schema:
{"reply":"Lead sentence.\\n• item one\\n• item two","actions":[{"type":"highlight","section":"network_interfaces","note":"optional note"}]}

Valid section leaf ids: system_general, system_management, network_interfaces, network_dhcp,
objects_addresses, objects_address_groups, objects_services, objects_service_groups,
policies_security, policies_nat, routing_static, routing_dynamic, vpn_ipsec, vpn_ssl,
users_users, users_groups, security_profiles, diagnostics_logging, other_unclassified
"""

_SECTION_KEYWORDS: list[tuple[list[str], str]] = [
    (["address group", "addrgrp"], "objects_address_groups"),
    (["service group"], "objects_service_groups"),
    (["firewall policy", "security polic"], "policies_security"),
    (["web filter", "webfilter"], "security_profiles"),
    (["anti virus", "antivirus"], "security_profiles"),
    (["ssl vpn", "sslvpn"], "vpn_ssl"),
    (["static route"], "routing_static"),
    (["user group"], "users_groups"),
    (["interface", "wan", "lan", "dmz"], "network_interfaces"),
    (["address", "subnet"], "objects_addresses"),
    (["service"], "objects_services"),
    (["policy", "policies"], "policies_security"),
    (["nat", "vip"], "policies_nat"),
    (["route"], "routing_static"),
    (["bgp", "ospf"], "routing_dynamic"),
    (["ipsec"], "vpn_ipsec"),
    (["user"], "users_users"),
    (["admin", "management"], "system_management"),
    (["dhcp"], "network_dhcp"),
    (["profile", "ips", "utm"], "security_profiles"),
    (["log"], "diagnostics_logging"),
    (["hostname", "system"], "system_general"),
]

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_BAD_REPLY_RE = re.compile(
    r"(1-3 short sentences|max 2 short|json only|never invent|use only the|"
    r"output json|valid section keys|do not write reasoning|"
    r"i need to be careful|the instruction says|user is asking|we are asked|"
    r"i must only use|let me think|my instructions|as an ai|"
    r"assistant was cut off|the user now says|appears the assistant|"
    r"your actual answer text here|your concise answer|"
    r"looking at the digest|according to (the )?rules|the digest (shows|provided))",
    re.I,
)

# Model sometimes echoes schema placeholders literally
_PLACEHOLDER_REPLY_RE = re.compile(
    r"^\s*(?:<answer>|</?answer>|<leaf_id>|<optional>|your actual answer text here)\s*$",
    re.I,
)


@dataclass
class AIAction:
    type: str
    section: str | None = None
    content: str | None = None
    object_count: int | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type}
        if self.section is not None:
            d["section"] = self.section
        if self.content is not None:
            d["content"] = self.content
        if self.object_count is not None:
            d["object_count"] = self.object_count
        if self.note is not None:
            d["note"] = self.note
        return d


@dataclass
class AIChatResult:
    reply: str
    actions: list[AIAction] = field(default_factory=list)
    raw: str = ""
    offline: bool = False


class AIClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self.settings.ai_enabled and self.settings.opencode_api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.settings.opencode_api_key}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Fast local helpers (for LOOKUP injection — not user-facing answers)
    # ------------------------------------------------------------------

    def _iter_objects(self, session: MigrationSession):
        for sec in session.parsed_sections or []:
            for obj in sec.objects or []:
                yield sec, obj

    def _object_blob(self, obj: dict[str, Any]) -> str:
        parts = [str(obj.get("name") or "")]
        props = obj.get("properties") or {}
        if isinstance(props, dict):
            for k, v in props.items():
                parts.append(f"{k}:{v}")
        raw = str(obj.get("raw") or "")
        if raw:
            parts.append(raw[:4000])
        if obj.get("preview"):
            parts.append(str(obj["preview"]))
        return "\n".join(parts)

    def _profile_category(self, obj: dict[str, Any]) -> str:
        props = obj.get("properties") or {}
        for key in ("Category", "Profile Type", "Type", "category"):
            if props.get(key):
                return str(props[key]).lower()
        return str(obj.get("preview") or "").lower()

    def _match_snippet(self, obj: dict[str, Any], term: str) -> str | None:
        """Return the first raw/property line that contains the term."""
        term_l = term.lower()
        props = obj.get("properties") or {}
        if isinstance(props, dict):
            # Prefer scalar property hits (avoid nested-dict string dumps)
            for k, v in props.items():
                if isinstance(v, (dict, list)):
                    continue
                if term_l in str(v).lower() or term_l in str(k).lower():
                    return f"{k}: {v}"[:200]
        raw = str(obj.get("raw") or "")
        for line in raw.splitlines():
            if term_l in line.lower():
                return line.strip()[:200]
        return None

    def _matched_prop_keys(self, obj: dict[str, Any], term: str) -> list[str]:
        term_l = term.lower()
        keys: list[str] = []
        props = obj.get("properties") or {}
        if isinstance(props, dict):
            for k, v in props.items():
                if term_l in str(v).lower() or term_l in str(k).lower():
                    keys.append(str(k))
        return keys[:8]

    def _search_term(
        self,
        session: MigrationSession,
        term: str,
        limit: int = 40,
        prefer_references: bool = False,
    ) -> list[dict[str, Any]]:
        term_l = term.lower().strip().strip('"').strip("'")
        if not term_l:
            return []
        hits: list[dict[str, Any]] = []
        for sec, obj in self._iter_objects(session):
            name = str(obj.get("name") or "")
            blob_l = self._object_blob(obj).lower()
            name_l = name.lower()
            if not (term_l == name_l or term_l in name_l or term_l in blob_l):
                continue
            if term_l == name_l:
                role = "definition"
            elif term_l in name_l:
                role = "name"
            else:
                role = "reference"
            props = {
                k: v
                for k, v in list((obj.get("properties") or {}).items())[:16]
                if v not in (None, "", [])
            }
            # Prefer keys that mention the term
            matched_keys = self._matched_prop_keys(obj, term_l)
            snippet = self._match_snippet(obj, term_l)
            hits.append(
                {
                    "section": sec.section_type,
                    "section_display": sec.display_name,
                    "category": sec.category_display,
                    "name": name,
                    "role": role,
                    "preview": (obj.get("preview") or "")[:100],
                    "match_snippet": snippet,
                    "matched_fields": matched_keys,
                    "properties": props,
                }
            )

        def _rank(h: dict[str, Any]) -> tuple:
            sec = h.get("section") or ""
            role = h.get("role") or ""
            # Usage questions: policies that reference the term first
            if prefer_references:
                ref_first = 0 if role == "reference" else 1
                policy_first = 0 if sec in ("policies_security", "policies_nat") else 1
                return (ref_first, policy_first, h.get("name") or "")
            role_ord = {"definition": 0, "name": 1, "reference": 2}.get(role, 3)
            return (role_ord, h.get("name") or "")

        hits.sort(key=_rank)
        return hits[:limit]

    _LOOKUP_STOPWORDS = frozenset(
        {
            "what",
            "which",
            "where",
            "who",
            "when",
            "how",
            "the",
            "a",
            "an",
            "is",
            "are",
            "was",
            "were",
            "does",
            "do",
            "did",
            "this",
            "that",
            "these",
            "those",
            "it",
            "its",
            "me",
            "my",
            "we",
            "our",
            "you",
            "your",
            "policy",
            "policies",
            "rule",
            "rules",
            "firewall",
            "security",
            "profile",
            "profiles",
            "object",
            "objects",
            "config",
            "configuration",
            "section",
            "use",
            "uses",
            "used",
            "using",
            "usage",
            "reference",
            "references",
            "referenced",
            "apply",
            "applied",
            "find",
            "show",
            "list",
            "tell",
            "about",
            "please",
            "from",
            "with",
            "for",
            "and",
            "or",
            "in",
            "on",
            "to",
            "of",
            "any",
            "all",
        }
    )

    def _extract_lookup_term(self, user_message: str) -> str | None:
        q = user_message.strip()
        ql = q.lower()

        ip_m = _IP_RE.search(q)
        if ip_m:
            return ip_m.group(0)

        # "what/which policy uses X", "which policies use X"
        m = re.search(
            r"(?:what|which)\s+polic(?:y|ies)\s+(?:use|uses|using|reference|references?)\s+(.+?)(?:\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?.,")
            if term and term.lower() not in self._LOOKUP_STOPWORDS:
                return term

        # "what uses X" / "who uses X"
        m = re.search(
            r"(?:what|who|which)\s+(?:objects?\s+)?(?:use|uses|using)\s+(.+?)(?:\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?.,")
            if term and term.lower() not in self._LOOKUP_STOPWORDS:
                return term

        # "where is X used/referenced/applied"
        m = re.search(
            r"where\s+(?:is|are|does)\s+(.+?)\s+(?:used|referenced|applied|defined)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?.,")
            if term and term.lower() not in self._LOOKUP_STOPWORDS:
                return term

        # "policies using X" / "rules with X"
        m = re.search(
            r"(?:polic(?:y|ies)|rules?)\s+(?:that\s+)?(?:use|uses|using|with|reference)\s+(.+?)(?:\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?.,")
            if term and term.lower() not in self._LOOKUP_STOPWORDS:
                return term

        m = re.search(
            r"(?:where\s+(?:is|are)|find|locate|search|explain|describe|what\s+is|what's|tell me about)\s+(.+?)(?:\s+referenced|\s+used|\s+defined|\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?")
            # strip leading "policy/profile" filler
            term = re.sub(
                r"^(?:the\s+)?(?:firewall\s+)?(?:policy|policies|profile|object)\s+",
                "",
                term,
                flags=re.I,
            ).strip()
            if term and term.lower() not in self._LOOKUP_STOPWORDS:
                return term

        m = re.search(r'"([^"]+)"|\'([^\']+)\'', q)
        if m:
            return m.group(1) or m.group(2)

        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]{2,80})\??$", q.strip())
        if m and ("_" in m.group(1) or "-" in m.group(1) or any(c.isupper() for c in m.group(1)[1:])):
            return m.group(1)

        # Fallback: object-like token (hyphen/underscore/mixed case) in the question
        tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,80}", q)
        for tok in reversed(tokens):
            tl = tok.lower()
            if tl in self._LOOKUP_STOPWORDS:
                continue
            if "-" in tok or "_" in tok or any(c.isupper() for c in tok[1:]):
                return tok

        return None

    def _is_usage_question(self, user_message: str) -> bool:
        return bool(
            re.search(
                r"\b(use|uses|used|using|usage|reference|references|referenced|"
                r"applied|which\s+polic|what\s+polic|who\s+uses)\b",
                user_message,
                re.I,
            )
        )

    def _answer_usage_locally(
        self,
        term: str,
        hits: list[dict[str, Any]],
    ) -> AIChatResult | None:
        """Deterministic answer for 'what/which policies use X' from search hits."""
        refs = [h for h in hits if h.get("role") == "reference"]
        if not refs:
            return None

        # Prefer security policies when present
        policy_refs = [
            h
            for h in refs
            if h.get("section") in ("policies_security", "policies_nat")
        ]
        primary = policy_refs or refs
        total = len(primary)
        show = primary[:25]

        lines: list[str] = []
        if policy_refs:
            lines.append(
                f"**{term}** is used by **{len(policy_refs)}** security "
                f"polic{'ies' if len(policy_refs) != 1 else 'y'}:"
            )
        else:
            lines.append(
                f"**{term}** is referenced by **{total}** object"
                f"{'s' if total != 1 else ''}:"
            )

        for h in show:
            props = h.get("properties") or {}
            pid = props.get("Policy ID") or props.get("Policy Id")
            match = h.get("match_snippet") or ""
            # Clean match line for display
            if match.lower().startswith("set "):
                how = match
            elif ":" in match:
                how = match
            else:
                fields = h.get("matched_fields") or []
                how = ", ".join(fields) if fields else "referenced in config"
            label = h.get("name") or "unnamed"
            if pid is not None:
                lines.append(f"• Policy #{pid} — {label} ({how})")
            else:
                sec = h.get("section_display") or h.get("section") or ""
                lines.append(f"• {label}" + (f" [{sec}]" if sec else "") + f" ({how})")

        if total > len(show):
            lines.append(f"…and {total - len(show)} more.")

        other = [h for h in refs if h not in primary]
        defs = [h for h in hits if h.get("role") in ("definition", "name")]
        if defs:
            d = defs[0]
            lines.append(
                f"Defined in {d.get('section_display') or d.get('section')}: "
                f"**{d.get('name')}**."
            )

        section = "policies_security" if policy_refs else (primary[0].get("section") or None)
        actions: list[AIAction] = []
        if section:
            actions.append(AIAction(type="highlight", section=section))
        return AIChatResult(reply="\n".join(lines), actions=actions)

    def _scoped_section(self, user_message: str) -> str | None:
        t = user_message.lower()
        for keys, section in _SECTION_KEYWORDS:
            if any(k in t for k in keys):
                return section
        return None

    def _section_detail(
        self,
        session: MigrationSession,
        section_type: str,
        limit: int = 25,
        profile_filter: str | None = None,
    ) -> dict[str, Any] | None:
        sec = next(
            (s for s in session.parsed_sections if s.section_type == section_type),
            None,
        )
        if not sec:
            return None

        objs = list(sec.objects or [])
        breakdown: dict[str, int] = {}
        if section_type == "security_profiles":
            for o in objs:
                cat = self._profile_category(o) or "other"
                breakdown[cat] = breakdown.get(cat, 0) + 1
            if profile_filter:
                objs = [
                    o
                    for o in objs
                    if profile_filter in self._profile_category(o)
                    or profile_filter in str(o.get("name") or "").lower()
                ]

        items = []
        for o in objs[:limit]:
            props = {
                k: v
                for k, v in list((o.get("properties") or {}).items())[:8]
                if v not in (None, "", [])
            }
            items.append(
                {
                    "name": o.get("name"),
                    "preview": (o.get("preview") or "")[:80],
                    "properties": props,
                }
            )
        return {
            "section": section_type,
            "display_name": sec.display_name,
            "count": len(objs) if profile_filter else sec.object_count,
            "total_section_count": sec.object_count,
            "profile_filter": profile_filter,
            "items": items,
            "profile_breakdown": breakdown or None,
        }

    def _compact_hit(self, h: dict[str, Any], *, full: bool = False) -> dict[str, Any]:
        """Shrink a search hit for the DIGEST payload."""
        props = h.get("properties") or {}
        out: dict[str, Any] = {
            "section": h.get("section"),
            "name": h.get("name"),
            "role": h.get("role"),
        }
        if h.get("match_snippet"):
            out["match"] = h["match_snippet"]
        if h.get("matched_fields"):
            out["fields"] = h["matched_fields"]
        # Keep only high-signal properties
        keep_keys = (
            "Policy ID",
            "Policy Id",
            "Action",
            "AV Profile",
            "IPS Sensor",
            "Web Filter",
            "SSL/SSH Profile",
            "Source Interfaces",
            "Destination Interfaces",
            "Source Addresses",
            "Destination Addresses",
            "Services",
            "UTM",
            "Utm Status",
            "Category",
            "Profile Type",
        )
        slim: dict[str, Any] = {}
        for k in keep_keys:
            if k in props and props[k] not in (None, "", []):
                slim[k] = props[k]
        if full:
            for k, v in list(props.items())[:8]:
                if k not in slim and v not in (None, "", []) and not isinstance(v, (dict, list)):
                    slim[k] = v
        if slim:
            out["properties"] = slim
        if h.get("preview") and full:
            out["preview"] = h["preview"]
        return out

    def _build_digest(
        self,
        session: MigrationSession,
        user_message: str,
    ) -> dict[str, Any]:
        """Compact but useful context for DeepSeek."""
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        for s in session.parsed_sections or []:
            if not s.object_count:
                continue
            counts[s.section_type] = s.object_count
            samples[s.section_type] = [
                o.get("name", "") for o in (s.objects or [])[:6] if o.get("name")
            ]

        digest: dict[str, Any] = {
            "vendor": session.source_vendor.value if session.source_vendor else "unknown",
            "vendor_display": (
                session.source_vendor.display_name if session.source_vendor else "Unknown"
            ),
            "file": session.filename,
            "hostname": session.common_model.hostname if session.common_model else None,
            "total_objects": session.statistics.total_objects if session.statistics else 0,
            "counts": counts,
            "samples": samples,
            "warnings": [
                {
                    "sev": w.severity.value if hasattr(w.severity, "value") else str(w.severity),
                    "msg": w.message[:120],
                    "section": w.section,
                }
                for w in (session.warnings or [])[:10]
            ],
        }

        # Scoped detail for the section the user is asking about
        scoped = self._scoped_section(user_message)
        ql = user_message.lower()
        profile_filter = None
        if scoped == "security_profiles":
            for key, subtype in [
                ("web filter", "webfilter"),
                ("webfilter", "webfilter"),
                ("antivirus", "antivirus"),
                ("anti virus", "antivirus"),
                ("ips", "ips"),
                ("dns filter", "dnsfilter"),
                ("dnsfilter", "dnsfilter"),
                ("application", "application"),
                ("dlp", "dlp"),
            ]:
                if key in ql:
                    profile_filter = subtype
                    break
        if scoped:
            detail = self._section_detail(
                session, scoped, limit=30, profile_filter=profile_filter
            )
            if detail:
                digest["focus_section"] = detail

        # LOOKUP for IP / object name / "what uses X" questions
        term = self._extract_lookup_term(user_message)
        if term:
            usage = self._is_usage_question(user_message)
            hits = self._search_term(
                session, term, limit=80, prefer_references=usage
            )
            refs = [h for h in hits if h.get("role") == "reference"]
            defs = [h for h in hits if h.get("role") in ("definition", "name")]
            digest["lookup_term"] = term
            # Compact hits — full property dumps blow the context budget
            digest["lookup"] = [
                self._compact_hit(h, full=(h.get("role") != "reference"))
                for h in hits[:35]
            ]
            if refs:
                compact_refs = [self._compact_hit(h) for h in refs]
                digest["lookup_reference_count"] = len(refs)
                # Cap list; include total so model can say "N policies use …"
                digest["lookup_references"] = compact_refs[:30]
                if len(refs) > 30:
                    digest["lookup_references_note"] = (
                        f"Showing 30 of {len(refs)} referencing objects; more exist."
                    )
            if defs:
                digest["lookup_definitions"] = [
                    self._compact_hit(h, full=True) for h in defs[:5]
                ]
            if usage and refs:
                # Avoid flooding with unfiltered policy list when we already have hits
                digest.pop("focus_section", None)

        # Light graph unused sample only if asked
        if "unused" in ql and session.dependency_graph:
            digest["unused_sample"] = [
                {"name": n.name, "kind": n.kind, "section": n.section}
                for n in session.dependency_graph.unused_nodes()[:20]
            ]

        return digest

    def _digest_blob(self, digest: dict[str, Any], max_chars: int = 22000) -> str:
        """Serialize digest; shrink lookup lists rather than mid-JSON truncate."""
        blob = json.dumps(digest, default=str, separators=(",", ":"))
        if len(blob) <= max_chars:
            return blob
        # Progressively trim large arrays
        for key in ("lookup_references", "lookup", "focus_section", "samples", "warnings"):
            if key not in digest:
                continue
            if key == "focus_section" and isinstance(digest[key], dict):
                items = digest[key].get("items") or []
                while len(blob) > max_chars and len(items) > 5:
                    items = items[: max(5, len(items) // 2)]
                    digest[key]["items"] = items
                    blob = json.dumps(digest, default=str, separators=(",", ":"))
                continue
            if not isinstance(digest.get(key), list):
                continue
            arr = digest[key]
            while len(blob) > max_chars and len(arr) > 3:
                arr = arr[: max(3, len(arr) // 2)]
                digest[key] = arr
                blob = json.dumps(digest, default=str, separators=(",", ":"))
        if len(blob) > max_chars:
            # last resort: drop samples/warnings
            digest.pop("samples", None)
            digest.pop("warnings", None)
            blob = json.dumps(digest, default=str, separators=(",", ":"))
        if len(blob) > max_chars:
            blob = blob[: max_chars - 2] + "]}"
        return blob

    def _build_messages(
        self, session: MigrationSession, user_message: str
    ) -> list[dict[str, str]]:
        digest = self._build_digest(session, user_message)
        blob = self._digest_blob(digest)

        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": f"DIGEST:{blob}"},
        ]
        # Only last clean Q/A pairs (skip greetings-only / corrupted turns)
        clean_turns: list[dict[str, str]] = []
        for msg in session.chat_history[-8:]:
            if msg.role not in ("user", "assistant") or not msg.content:
                continue
            content = msg.content.strip()
            if self._is_bad_reply(content):
                continue
            # drop truncated JSON debris
            if content.startswith("{") and '"reply"' in content and not content.rstrip().endswith("}"):
                continue
            clean_turns.append({"role": msg.role, "content": content[:500]})
        # Keep at most last 4 clean messages
        messages.extend(clean_turns[-4:])
        messages.append({"role": "user", "content": user_message[:2000]})
        return messages

    def _is_bad_reply(self, text: str) -> bool:
        if not text or not text.strip():
            return True
        stripped = text.strip()
        if _PLACEHOLDER_REPLY_RE.match(stripped):
            return True
        # Bare XML/placeholder tags with little real content
        if re.fullmatch(r"</?[A-Za-z_][\w:-]*>", stripped):
            return True
        if stripped.lower() in {"<answer>", "answer", "null", "none", "n/a", "..."}:
            return True
        if _BAD_REPLY_RE.search(text):
            return True
        t = text.lower()
        if re.match(r"^(fortigate|palo|check point|cisco ftd):\s*\d+\s+objects\.", t):
            return True
        return False

    # ------------------------------------------------------------------
    # API chat (always DeepSeek)
    # ------------------------------------------------------------------

    async def chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AIChatResult:
        # Fast local path for "what/which policy uses X" — search is authoritative
        term = self._extract_lookup_term(user_message)
        if term and self._is_usage_question(user_message):
            hits = self._search_term(
                session, term, limit=80, prefer_references=True
            )
            local = self._answer_usage_locally(term, hits)
            if local and local.reply:
                return local

        if not self.enabled:
            return AIChatResult(
                reply="AI is not configured (missing OPENCODE_API_KEY).",
                actions=[],
            )

        messages = self._build_messages(session, user_message)
        url = f"{self.settings.opencode_base_url.rstrip('/')}/chat/completions"
        max_tokens = max(
            256,
            min(int(self.settings.ai_max_tokens or 2000), _MAX_TOKENS_CEILING),
        )

        payload: dict[str, Any] = {
            "model": self.settings.opencode_model,
            "messages": messages,
            "temperature": min(float(self.settings.ai_temperature), 0.3),
            "max_tokens": max_tokens,
            "stream": False,
            "reasoning_effort": "low",
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
                if resp.status_code >= 400:
                    logger.error("AI API error %s: %s", resp.status_code, resp.text[:400])
                    return AIChatResult(
                        reply=f"DeepSeek API error HTTP {resp.status_code}. Check API key and OpenCode balance.",
                        actions=[],
                    )

                data = resp.json()
                text = self._extract_content(data)
                result = self.parse_ai_response(text)

                if self._is_bad_reply(result.reply):
                    # Fallback: local usage answer if we can search
                    if term:
                        hits = self._search_term(
                            session, term, limit=80, prefer_references=True
                        )
                        local = self._answer_usage_locally(term, hits)
                        if local and local.reply:
                            return local
                    # One retry without history, even smaller prompt
                    logger.warning("Bad AI reply filtered; retrying once")
                    retry_messages = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "system",
                            "content": f"DIGEST:{self._digest_blob(self._build_digest(session, user_message), max_chars=18000)}",
                        },
                        {"role": "user", "content": user_message[:2000]},
                    ]
                    resp2 = await client.post(
                        url,
                        headers=self._headers(),
                        json={
                            **payload,
                            "messages": retry_messages,
                            "max_tokens": min(max_tokens, 1500),
                        },
                    )
                    if resp2.status_code < 400:
                        result = self.parse_ai_response(self._extract_content(resp2.json()))
                    if self._is_bad_reply(result.reply):
                        return AIChatResult(
                            reply="I couldn't form a clean answer. Try a more specific question (object name, IP, or section).",
                            actions=[],
                        )

                return self._merge_actions(session, user_message, result)

        except httpx.HTTPError as exc:
            logger.exception("AI request failed")
            return AIChatResult(
                reply=f"Unable to reach DeepSeek API ({exc}).",
                actions=[],
            )

    def parse_ai_response(self, text: str) -> AIChatResult:
        raw = (text or "").strip()
        if not raw:
            return AIChatResult(reply="", actions=[], raw=raw)

        candidates: list[str] = []
        for fence in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", raw):
            candidates.append(fence.group(1).strip())
        start, end = raw.find("{"), raw.rfind("}")
        if start != -1 and end > start:
            candidates.append(raw[start : end + 1])

        seen: set[str] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                data = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict) or "reply" not in data:
                continue
            reply = str(data.get("reply") or "").strip()
            if self._is_bad_reply(reply):
                continue
            if len(reply) > _MAX_REPLY_CHARS:
                reply = reply[: _MAX_REPLY_CHARS - 1].rstrip() + "…"
            actions: list[AIAction] = []
            for item in data.get("actions") or []:
                if not isinstance(item, dict):
                    continue
                atype = str(item.get("type") or "").strip()
                if not atype or atype == "patch_section":
                    continue
                actions.append(
                    AIAction(
                        type=atype,
                        section=item.get("section"),
                        note=item.get("note"),
                    )
                )
            return AIChatResult(reply=reply or "OK.", actions=actions, raw=text)

        # Truncated JSON: pull "reply":"..." with regex
        m = re.search(r'"reply"\s*:\s*"((?:\\.|[^"\\])*)', raw)
        if m:
            try:
                reply = json.loads(f'"{m.group(1)}"')
            except json.JSONDecodeError:
                reply = m.group(1).encode().decode("unicode_escape", errors="ignore")
            reply = str(reply).strip()
            if reply and not self._is_bad_reply(reply):
                # optional actions section id
                actions: list[AIAction] = []
                sm = re.search(r'"section"\s*:\s*"([^"]+)"', raw)
                if sm:
                    actions.append(
                        AIAction(type="highlight", section=sm.group(1))
                    )
                if len(reply) > _MAX_REPLY_CHARS:
                    reply = reply[: _MAX_REPLY_CHARS - 1].rstrip() + "…"
                return AIChatResult(reply=reply, actions=actions, raw=text)

        # plain text fallback if not JSON-looking and not bad
        brief = re.sub(r"\s+", " ", raw).strip()
        if brief.startswith("{") or self._is_bad_reply(brief):
            return AIChatResult(reply="", actions=[], raw=text)
        if len(brief) > _MAX_BRIEF_CHARS:
            brief = brief[: _MAX_BRIEF_CHARS - 1].rstrip() + "…"
        return AIChatResult(reply=brief, actions=[], raw=text)

    def apply_actions(
        self, session: MigrationSession, actions: list[AIAction]
    ) -> list[dict[str, Any]]:
        """Apply UI actions only — do not write pipeline log noise."""
        applied: list[dict[str, Any]] = []
        for action in actions or []:
            if action.type == "patch_section":
                continue
            applied.append(action.to_dict())
        return applied

    def _intro_facts(self, session: MigrationSession) -> dict[str, Any]:
        """Structured facts for the post-analysis intro (always real data)."""
        counts: list[dict[str, Any]] = []
        for s in session.parsed_sections or []:
            if s.object_count:
                counts.append(
                    {
                        "section": s.section_type,
                        "name": s.display_name,
                        "count": s.object_count,
                    }
                )
        counts.sort(key=lambda x: -int(x["count"]))
        stats = session.statistics
        model = session.common_model
        host = model.hostname if model else None
        vendor = (
            session.source_vendor.display_name
            if session.source_vendor
            else "Unknown"
        )

        # Engaging but compact highlights from the model
        highlights: list[str] = []
        if model:
            if model.interfaces:
                with_ip = [
                    i
                    for i in model.interfaces
                    if i.ip_addresses
                    and not str(i.name).lower().startswith("lo")
                ]
                if with_ip:
                    samples = ", ".join(
                        f"{i.name} ({i.ip_addresses[0]})" for i in with_ip[:3]
                    )
                    more = f" +{len(with_ip) - 3} more" if len(with_ip) > 3 else ""
                    highlights.append(f"{len(with_ip)} interfaces with IPs: {samples}{more}")
            if model.policies:
                names = [p.name for p in model.policies[:4] if p.name]
                highlights.append(
                    f"{len(model.policies)} security policies"
                    + (f" (e.g. {', '.join(names)})" if names else "")
                )
            if model.nat_rules:
                highlights.append(f"{len(model.nat_rules)} NAT rule(s)")
            if model.addresses:
                highlights.append(f"{len(model.addresses)} address objects")
            if model.static_routes:
                highlights.append(f"{len(model.static_routes)} static route(s)")
            if model.ipsec_tunnels:
                highlights.append(f"{len(model.ipsec_tunnels)} IPsec tunnel(s)")

        # Prefer section counts when model highlights thin
        if len(highlights) < 2:
            for s in counts[:5]:
                highlights.append(f"{s['name']}: {s['count']}")

        return {
            "filename": session.filename,
            "vendor": vendor,
            "hostname": host or "unknown",
            "total_objects": stats.total_objects if stats else 0,
            "warning_count": stats.warning_count if stats else 0,
            "error_count": stats.error_count if stats else 0,
            "top_sections": counts[:8],
            "highlights": highlights[:6],
            "warnings": [
                (w.message or "")[:120]
                for w in (session.warnings or [])
                if (w.severity.value if hasattr(w.severity, "value") else str(w.severity))
                in ("warning", "error", "critical")
                and not str(w.code or "").startswith("CP_")
            ][:3],
        }

    def build_intro_summary(self, session: MigrationSession) -> str:
        """One-line intro: vendor, host, object count + invite to ask."""
        f = self._intro_facts(session)
        host = f["hostname"] if f["hostname"] != "unknown" else "unknown host"
        vendor = f.get("vendor") or "unknown"
        total = f.get("total_objects")
        if total is None:
            total = "—"
        return (
            f"This is a **{vendor}** configuration for host **{host}** "
            f"with **{total}** objects in total. "
            f"Ask me questions to dig deeper."
        )

    async def generate_intro(self, session: MigrationSession) -> AIChatResult:
        """Super-brief deterministic intro (no model call)."""
        return AIChatResult(reply=self.build_intro_summary(session), actions=[])

    def _merge_actions(
        self,
        session: MigrationSession,
        user_message: str,
        result: AIChatResult,
    ) -> AIChatResult:
        if not result.actions:
            # Usage questions about a profile/object → open policies, not profiles
            if self._is_usage_question(user_message):
                term = self._extract_lookup_term(user_message)
                if term:
                    hits = self._search_term(
                        session, term, limit=20, prefer_references=True
                    )
                    if any(h.get("section") == "policies_security" for h in hits):
                        result.actions = [
                            AIAction(type="highlight", section="policies_security")
                        ]
                        return result
            sec = self._scoped_section(user_message)
            if sec:
                result.actions = [AIAction(type="highlight", section=sec)]
        return result

    def _extract_content(self, data: dict[str, Any]) -> str:
        choices = data.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return content
            if isinstance(content, list):
                parts = []
                for p in content:
                    if isinstance(p, dict) and p.get("text"):
                        parts.append(p["text"])
                    elif isinstance(p, str):
                        parts.append(p)
                if parts:
                    return "\n".join(parts)
            # Only use reasoning if it embeds JSON reply
            reasoning = msg.get("reasoning_content") or msg.get("reasoning")
            if isinstance(reasoning, str) and '"reply"' in reasoning:
                return reasoning
            return ""
        if "error" in data:
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            return json.dumps({"reply": f"DeepSeek API error: {msg}"})
        return ""

    async def stream_chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AsyncIterator[str]:
        result = await self.chat(session, user_message, include_raw=include_raw)
        yield result.reply
