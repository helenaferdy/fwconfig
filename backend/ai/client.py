"""AI Configuration Analysis Consultant via OpenCode (DeepSeek-V4-Flash).

Speed-first with accurate local lookup:
- Tiny digest for open-ended AI questions
- Offline search for IP / object explain / references (uses full session data)
- Never surface model reasoning dumps to the user
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, AsyncIterator

import httpx

from config import Settings, get_settings
from session.store import MigrationSession

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are FWM-AI, a brief firewall config analyst.
Use ONLY the provided DIGEST and LOOKUP data. Never invent objects/IPs.
If LOOKUP is present, base your answer on it.
Output JSON only (no prose outside JSON):
{"reply":"1-3 short sentences","actions":[{"type":"highlight","section":"objects_addresses","note":"optional"}]}
Valid section keys include: system_general,system_management,network_interfaces,network_dhcp,objects_addresses,objects_address_groups,objects_services,objects_service_groups,policies_security,policies_nat,routing_static,routing_dynamic,vpn_ipsec,vpn_ssl,users_users,users_groups,security_profiles,diagnostics_logging,other_unclassified
"""

_SECTION_KEYWORDS: list[tuple[list[str], str]] = [
    (["interface", "wan", "lan", "dmz", "port"], "network_interfaces"),
    (["address group", "addrgrp"], "objects_address_groups"),
    (["address", "subnet", "host object"], "objects_addresses"),
    (["service group"], "objects_service_groups"),
    (["service", "port "], "objects_services"),
    (["policy", "policies", "firewall rule"], "policies_security"),
    (["nat", "vip", "snat", "dnat"], "policies_nat"),
    (["static route", "default route", "route"], "routing_static"),
    (["bgp", "ospf", "dynamic routing"], "routing_dynamic"),
    (["ipsec", "phase1", "phase2"], "vpn_ipsec"),
    (["ssl vpn", "sslvpn", "web portal"], "vpn_ssl"),
    (["user local", "local user", "users"], "users_users"),
    (["user group", "groups"], "users_groups"),
    (["admin", "accprofile", "management"], "system_management"),
    (["hostname", "system global"], "system_general"),
    (["dhcp"], "network_dhcp"),
    (["ips", "antivirus", "webfilter", "profile"], "security_profiles"),
    (["log", "logging"], "diagnostics_logging"),
]

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
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
    actions: list[AIAction] | None = None
    raw: str = ""
    offline: bool = False

    def __post_init__(self) -> None:
        if self.actions is None:
            self.actions = []


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
    # Local search (full session — not the tiny digest)
    # ------------------------------------------------------------------

    def _iter_objects(self, session: MigrationSession):
        for sec in session.parsed_sections or []:
            for i, obj in enumerate(sec.objects or []):
                yield sec, obj, i

    def _object_blob(self, obj: dict[str, Any]) -> str:
        parts = [str(obj.get("name") or "")]
        props = obj.get("properties") or {}
        if isinstance(props, dict):
            for k, v in props.items():
                parts.append(f"{k}:{v}")
        if obj.get("raw"):
            parts.append(str(obj["raw"]))
        if obj.get("preview"):
            parts.append(str(obj["preview"]))
        return "\n".join(parts)

    def _search_term(
        self, session: MigrationSession, term: str, limit: int = 40
    ) -> list[dict[str, Any]]:
        """Search name/properties/raw for an IP or object name."""
        term_l = term.lower().strip().strip('"').strip("'")
        if not term_l:
            return []
        hits: list[dict[str, Any]] = []
        for sec, obj, _i in self._iter_objects(session):
            name = str(obj.get("name") or "")
            blob = self._object_blob(obj)
            blob_l = blob.lower()
            name_l = name.lower()
            if term_l == name_l or term_l in name_l or term_l in blob_l:
                # role of match
                role = "contains"
                if term_l == name_l:
                    role = "exact_name"
                elif term_l in name_l:
                    role = "name"
                elif term_l in str(obj.get("raw") or "").lower():
                    role = "raw"
                elif any(
                    term_l in str(v).lower()
                    for v in (obj.get("properties") or {}).values()
                ):
                    role = "property"
                hits.append(
                    {
                        "section": sec.section_type,
                        "section_display": sec.display_name,
                        "category": sec.category_display,
                        "name": name,
                        "role": role,
                        "preview": (obj.get("preview") or "")[:120],
                        "properties": {
                            k: v
                            for k, v in list((obj.get("properties") or {}).items())[:12]
                            if v not in (None, "", [])
                        },
                    }
                )
                if len(hits) >= limit:
                    break
        # Prefer exact name matches first
        hits.sort(key=lambda h: (0 if h["role"] == "exact_name" else 1, h["name"]))
        return hits

    def _format_hits(self, term: str, hits: list[dict[str, Any]], mode: str) -> AIChatResult:
        if not hits:
            return AIChatResult(
                reply=f'No references to "{term}" found in parsed configuration.',
                actions=[],
                offline=True,
            )

        # Primary section to highlight
        primary = hits[0]["section"]
        # Group by section
        by_sec: dict[str, list[str]] = {}
        for h in hits:
            key = f"{h.get('category') or ''} / {h['section_display']}".strip(" /")
            by_sec.setdefault(key, []).append(h["name"])

        if mode == "explain":
            # Prefer exact object
            exact = next((h for h in hits if h["role"] == "exact_name"), hits[0])
            props = exact.get("properties") or {}
            bits = [f"{k}: {v}" for k, v in list(props.items())[:8]]
            # Also where referenced (other hits with same term in raw of policies etc.)
            others = [
                h
                for h in hits
                if h["name"] != exact["name"] or h["section"] != exact["section"]
            ][:8]
            reply = f"{exact['name']} ({exact['section_display']})"
            if bits:
                reply += " — " + "; ".join(bits)
            if others:
                ref_names = []
                for h in others:
                    ref_names.append(f"{h['name']} in {h['section_display']}")
                reply += ". Also seen in: " + "; ".join(ref_names[:6])
            return AIChatResult(
                reply=reply[:700],
                actions=[
                    AIAction(
                        type="highlight",
                        section=exact["section"],
                        note=exact["name"],
                    )
                ],
                offline=True,
            )

        # reference mode
        lines = []
        for sec_label, names in list(by_sec.items())[:10]:
            uniq = list(dict.fromkeys(names))[:8]
            lines.append(f"{sec_label}: {', '.join(uniq)}")
        reply = f'"{term}" found in {len(hits)} place(s). ' + " | ".join(lines)
        return AIChatResult(
            reply=reply[:700],
            actions=[AIAction(type="highlight", section=primary, note=term)],
            offline=True,
        )

    def _extract_lookup_term(self, user_message: str) -> tuple[str, str] | None:
        """Return (mode, term) for reference/explain queries."""
        q = user_message.strip()
        ql = q.lower()

        # IP anywhere
        ip_m = _IP_RE.search(q)
        if ip_m and re.search(
            r"\b(where|reference|referenced|used|find|search|look|locate)\b", ql
        ):
            return ("reference", ip_m.group(0))
        if ip_m and len(q.strip()) < 40:
            # bare IP or "172.x?"
            return ("reference", ip_m.group(0))

        # where is X referenced / where is X used
        m = re.search(
            r"(?:where\s+(?:is|are)|find|locate|search)\s+(.+?)(?:\s+referenced|\s+used|\s+defined|\?|$)",
            ql,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?")
            # recover original casing from original message if possible
            m2 = re.search(
                r"(?:where\s+(?:is|are)|find|locate|search)\s+(.+?)(?:\s+referenced|\s+used|\s+defined|\?|$)",
                q,
                re.I,
            )
            if m2:
                term = m2.group(1).strip(" \"'?")
            if term and term not in ("this", "it", "that"):
                return ("reference", term)

        # explain / what is / describe
        m = re.search(
            r"(?:explain|describe|what\s+is|what's|tell me about|details?\s+(?:on|for))\s+(.+?)(?:\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'")
            if term:
                return ("explain", term)

        # Quoted name
        m = re.search(r'"([^"]+)"|\'([^\']+)\'', q)
        if m:
            term = m.group(1) or m.group(2)
            if re.search(r"\b(where|reference|used|find)\b", ql):
                return ("reference", term)
            if re.search(r"\b(explain|what|describe)\b", ql):
                return ("explain", term)
            return ("explain", term)

        # Bare object-like token (contains underscore / mixed)
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]{2,80})\??$", q.strip())
        if m and ("_" in m.group(1) or any(c.isupper() for c in m.group(1)[1:])):
            return ("explain", m.group(1))

        return None

    # ------------------------------------------------------------------
    # Compact context
    # ------------------------------------------------------------------

    def _tiny_digest(
        self, session: MigrationSession, lookup: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        for s in session.parsed_sections:
            if not s.object_count:
                continue
            counts[s.section_type] = s.object_count
            names = [o.get("name", "") for o in (s.objects or [])[:5] if o.get("name")]
            if names:
                samples[s.section_type] = names

        warns = [
            {
                "sev": w.severity.value if hasattr(w.severity, "value") else str(w.severity),
                "msg": w.message[:100],
                "section": w.section,
            }
            for w in (session.warnings or [])[:8]
        ]

        digest: dict[str, Any] = {
            "vendor": session.source_vendor.value,
            "file": session.filename,
            "total_objects": session.statistics.total_objects if session.statistics else 0,
            "counts": counts,
            "samples": samples,
            "warnings": warns,
        }
        if lookup:
            # Cap lookup payload
            digest["lookup"] = lookup[:25]
        return digest

    def _build_messages(
        self,
        session: MigrationSession,
        user_message: str,
        lookup: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, str]]:
        digest = self._tiny_digest(session, lookup=lookup)
        blob = json.dumps(digest, default=str, separators=(",", ":"))
        if len(blob) > 14000:
            blob = blob[:14000] + "…]}"

        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": f"DIGEST:{blob}"},
        ]
        for msg in session.chat_history[-6:]:
            if msg.role in ("user", "assistant") and msg.content:
                # never feed prior reasoning dumps back
                content = msg.content.strip()
                if self._looks_like_reasoning(content):
                    continue
                messages.append({"role": msg.role, "content": content[:400]})
        messages.append({"role": "user", "content": user_message[:1000]})
        return messages

    def _looks_like_reasoning(self, text: str) -> bool:
        t = text.lower()
        markers = [
            "i need to be careful",
            "the instruction says",
            "user is asking",
            "i must only use",
            "let me think",
            "reasoning",
            "as an ai",
            "my instructions",
        ]
        if any(m in t for m in markers):
            return True
        # long stream-of-consciousness without structure
        if len(text) > 400 and text.count(".") > 8 and "{" not in text:
            return True
        return False

    # ------------------------------------------------------------------
    # Offline shortcuts
    # ------------------------------------------------------------------

    def _try_offline(self, session: MigrationSession, user_message: str) -> AIChatResult | None:
        q = user_message.lower().strip()
        if not q or not session.parsed_sections:
            return None

        # --- IP / object reference & explain (full local search) ---
        lookup = self._extract_lookup_term(user_message)
        if lookup:
            mode, term = lookup
            # If term is very generic, skip
            if term.lower() not in {
                "this",
                "it",
                "that",
                "config",
                "configuration",
                "firewall",
            }:
                hits = self._search_term(session, term)
                return self._format_hits(term, hits, mode)

        counts = {
            s.section_type: s.object_count
            for s in session.parsed_sections
            if s.object_count
        }

        def highlight(section: str, note: str = "") -> list[AIAction]:
            return [AIAction(type="highlight", section=section, note=note or None)]

        # how many X?
        m = re.search(r"(?:how many|count|number of|# of)\s+(.+?)(?:\?|$)", q)
        if m or re.match(r"^(interfaces|addresses|policies|users|services|routes)\??$", q):
            topic = m.group(1).strip() if m else q.rstrip("?")
            topic = re.sub(r"\b(are|is|do we have|are there)\b", "", topic).strip()
            section = self._match_section(topic) or self._match_section(q)
            if section and section in counts:
                n = counts[section]
                labels = {
                    "users_users": "local users",
                    "users_groups": "user groups",
                    "network_interfaces": "interfaces",
                    "objects_addresses": "address objects",
                    "objects_address_groups": "address groups",
                    "objects_services": "services",
                    "objects_service_groups": "service groups",
                    "policies_security": "security policies",
                    "policies_nat": "NAT objects",
                    "routing_static": "static routes",
                    "routing_dynamic": "dynamic routing objects",
                    "vpn_ipsec": "IPsec tunnels",
                    "vpn_ssl": "SSL VPN objects",
                    "system_management": "admin/management objects",
                    "security_profiles": "security profiles",
                }
                label = labels.get(section, section.replace("_", " ").split()[-1])
                return AIChatResult(
                    reply=f"{n} {label}.",
                    actions=highlight(section, "count"),
                    offline=True,
                )
            if "object" in topic or "total" in topic:
                total = (
                    session.statistics.total_objects
                    if session.statistics
                    else sum(counts.values())
                )
                return AIChatResult(
                    reply=f"{total} total parsed objects.",
                    actions=[],
                    offline=True,
                )

        # list names
        m = re.search(r"(?:list|show|name)\s+(?:all\s+)?(.+?)(?:\?|$)", q)
        if m:
            topic = m.group(1).strip()
            # don't treat "show interfaces" as list if we want jump - still ok as list
            section = self._match_section(topic)
            if section:
                sec = next(
                    (s for s in session.parsed_sections if s.section_type == section),
                    None,
                )
                if sec and sec.objects:
                    names = [o.get("name", "") for o in sec.objects[:20] if o.get("name")]
                    more = sec.object_count - len(names)
                    reply = ", ".join(names)
                    if more > 0:
                        reply += f" (+{more} more)"
                    return AIChatResult(
                        reply=reply[:500],
                        actions=highlight(section, "list"),
                        offline=True,
                    )

        # unused
        if "unused" in q:
            unused = []
            if session.dependency_graph:
                unused = session.dependency_graph.unused_nodes()[:12]
            if not unused:
                return AIChatResult(
                    reply="No unused objects flagged.", actions=[], offline=True
                )
            bits = [f"{n.name} ({n.kind})" for n in unused]
            sec = unused[0].section or "objects_addresses"
            return AIChatResult(
                reply=f"Unused: {', '.join(bits)}",
                actions=highlight(
                    sec if isinstance(sec, str) else "objects_addresses", "unused"
                ),
                offline=True,
            )

        # vendor / hostname / file
        if re.search(r"\b(vendor|hostname|filename|what file)\b", q):
            host = session.common_model.hostname if session.common_model else None
            return AIChatResult(
                reply=(
                    f"Vendor: {session.source_vendor.display_name}. "
                    f"File: {session.filename or '—'}. "
                    f"Hostname: {host or '—'}."
                ),
                actions=highlight("system_general"),
                offline=True,
            )

        # section jump
        m = re.search(r"(?:show|open|go to|highlight|focus)\s+(.+?)(?:\?|$)", q)
        if m:
            section = self._match_section(m.group(1))
            if section and section in counts:
                return AIChatResult(
                    reply=f"Opening {section.replace('_', ' ')} ({counts[section]} objects).",
                    actions=highlight(section),
                    offline=True,
                )

        return None

    def _match_section(self, text: str) -> str | None:
        t = text.lower().strip()
        for keys, section in _SECTION_KEYWORDS:
            if any(k in t for k in keys):
                return section
        t2 = t.replace(" ", "_").replace("·", "").replace("/", "_")
        for _, section in _SECTION_KEYWORDS:
            if section in t2 or section.replace("_", " ") in t:
                return section
        return None

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------

    async def chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AIChatResult:
        # 1) Offline first (includes IP/object search)
        offline = self._try_offline(session, user_message)
        if offline is not None:
            logger.info("AI offline shortcut: %s", user_message[:80])
            return offline

        if not self.enabled:
            return self._offline_result(session, user_message)

        # 2) If query looks like a name/IP but offline didn't fire, still attach lookup
        lookup_hits: list[dict[str, Any]] | None = None
        term_info = self._extract_lookup_term(user_message)
        ip_m = _IP_RE.search(user_message)
        if term_info:
            lookup_hits = self._search_term(session, term_info[1], limit=20)
        elif ip_m:
            lookup_hits = self._search_term(session, ip_m.group(0), limit=20)

        messages = self._build_messages(session, user_message, lookup=lookup_hits)
        url = f"{self.settings.opencode_base_url.rstrip('/')}/chat/completions"
        max_tokens = min(int(getattr(self.settings, "ai_max_tokens", 400) or 400), 512)
        payload: dict[str, Any] = {
            "model": self.settings.opencode_model,
            "messages": messages,
            "temperature": min(float(self.settings.ai_temperature), 0.2),
            "max_tokens": max_tokens,
            "stream": False,
            "reasoning_effort": "low",
        }

        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
                if resp.status_code >= 400:
                    logger.error("AI API error %s: %s", resp.status_code, resp.text[:300])
                    # If we have lookup hits, answer from them
                    if lookup_hits:
                        term = term_info[1] if term_info else (ip_m.group(0) if ip_m else "query")
                        mode = term_info[0] if term_info else "reference"
                        return self._format_hits(term, lookup_hits, mode)
                    fb = self._offline_result(session, user_message)
                    fb.reply = f"AI HTTP {resp.status_code}. {fb.reply}"
                    return fb

                data = resp.json()
                text = self._extract_content(data)
                result = self.parse_ai_response(text)

                # If model returned reasoning garbage, fall back to local lookup/summary
                if self._looks_like_reasoning(result.reply) or not result.reply.strip():
                    if lookup_hits:
                        term = (
                            term_info[1]
                            if term_info
                            else (ip_m.group(0) if ip_m else "query")
                        )
                        mode = term_info[0] if term_info else "reference"
                        return self._format_hits(term, lookup_hits, mode)
                    return self._offline_result(session, user_message)

                return self._merge_actions(session, user_message, result)
        except httpx.HTTPError as exc:
            logger.exception("AI request failed: %s", exc)
            if lookup_hits:
                term = term_info[1] if term_info else (ip_m.group(0) if ip_m else "query")
                mode = term_info[0] if term_info else "reference"
                return self._format_hits(term, lookup_hits, mode)
            fb = self._offline_result(session, user_message)
            fb.reply = f"AI unreachable. {fb.reply}"
            return fb

    def parse_ai_response(self, text: str) -> AIChatResult:
        raw = (text or "").strip()
        if not raw:
            return AIChatResult(reply="", actions=[], raw=raw)

        # Reject pure reasoning dumps early
        if self._looks_like_reasoning(raw) and "{" not in raw:
            return AIChatResult(reply="", actions=[], raw=raw)

        candidates: list[str] = []
        for fence in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", raw):
            candidates.append(fence.group(1).strip())
        start = raw.find("{")
        end = raw.rfind("}")
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
            if self._looks_like_reasoning(reply):
                continue
            if len(reply) > 400:
                reply = reply[:397].rstrip() + "…"
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

        # Non-JSON brief text only if not reasoning
        brief = re.sub(r"\s+", " ", raw).strip()
        if self._looks_like_reasoning(brief):
            return AIChatResult(reply="", actions=[], raw=text)
        if len(brief) > 280:
            brief = brief[:277].rstrip() + "…"
        return AIChatResult(reply=brief, actions=[], raw=text)

    def apply_actions(
        self,
        session: MigrationSession,
        actions: list[AIAction],
    ) -> list[dict[str, Any]]:
        applied: list[dict[str, Any]] = []
        for action in actions or []:
            if action.type == "patch_section":
                continue
            applied.append(action.to_dict())
            if action.type in ("highlight", "annotate") and action.section:
                session.add_log(
                    "ai_review",
                    f"AI focused: {action.section}"
                    + (f" — {action.note}" if action.note else ""),
                    level="info",
                )
        return applied

    def _merge_actions(
        self,
        session: MigrationSession,
        user_message: str,
        result: AIChatResult,
    ) -> AIChatResult:
        if not result.actions:
            sec = self._match_section(user_message.lower())
            if sec:
                result.actions = [AIAction(type="highlight", section=sec)]
        if result.reply and len(result.reply) > 400:
            result.reply = result.reply[:397].rstrip() + "…"
        return result

    def _extract_content(self, data: dict[str, Any]) -> str:
        """Prefer message.content; only use reasoning if it embeds JSON."""
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
            reasoning = msg.get("reasoning_content") or msg.get("reasoning")
            if isinstance(reasoning, str) and reasoning.strip():
                # Only if JSON reply is embedded
                if "{" in reasoning and '"reply"' in reasoning:
                    return reasoning
                # Do not return free-form reasoning to user path
                return ""
        if "error" in data:
            err = data["error"]
            if isinstance(err, dict):
                return f'{{"reply":"AI error: {err.get("message") or err}"}}'
            return f'{{"reply":"AI error: {err}"}}'
        return ""

    def _offline_result(self, session: MigrationSession, user_message: str) -> AIChatResult:
        offline = self._try_offline(session, user_message)
        if offline:
            return offline
        stats = session.statistics
        counts = {
            s.display_name: s.object_count
            for s in session.parsed_sections
            if s.object_count
        }
        top = ", ".join(f"{k}={v}" for k, v in list(counts.items())[:6])
        reply = (
            f"{session.source_vendor.display_name}: {stats.total_objects} objects. "
            f"{top or 'no sections'}."
        )
        sec = self._match_section(user_message.lower())
        actions = [AIAction(type="highlight", section=sec)] if sec else []
        return AIChatResult(reply=reply[:280], actions=actions, offline=True, raw=reply)

    async def stream_chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AsyncIterator[str]:
        result = await self.chat(session, user_message, include_raw=include_raw)
        yield result.reply
