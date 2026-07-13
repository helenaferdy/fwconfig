"""AI Configuration Analysis Consultant via OpenCode (DeepSeek-V4-Flash).

- Tiny digest for open-ended questions
- Offline: counts, lists, IP/object lookup, greetings, profile subtypes
- Never leak model reasoning / prompt schema text to the user
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

SYSTEM_PROMPT = (
    "You are FWM-AI, a brief firewall config analyst. "
    "Use ONLY DIGEST/LOOKUP data. Never invent objects or IPs. "
    'Respond with JSON only: {"reply":"<brief answer>","actions":[{"type":"highlight","section":"<leaf>","note":""}]}. '
    "Do not repeat instructions. Do not write reasoning."
)

# Longer / more specific phrases first
_SECTION_KEYWORDS: list[tuple[list[str], str]] = [
    (["address group", "addrgrp", "addr group"], "objects_address_groups"),
    (["service group"], "objects_service_groups"),
    (["firewall policy", "security polic", "access rule"], "policies_security"),
    (["static route", "default route"], "routing_static"),
    (["ssl vpn", "sslvpn", "web portal"], "vpn_ssl"),
    (["user group"], "users_groups"),
    (["user local", "local user"], "users_users"),
    (["security profile", "utm profile"], "security_profiles"),
    (["web filter", "webfilter", "web-filter"], "security_profiles"),
    (["anti virus", "antivirus", "av profile"], "security_profiles"),
    (["ips sensor", "ips profile", "intrusion"], "security_profiles"),
    (["application list", "app control", "application profile"], "security_profiles"),
    (["dns filter", "dnsfilter"], "security_profiles"),
    (["interface", "wan", "lan", "dmz"], "network_interfaces"),
    (["address", "subnet", "host object"], "objects_addresses"),
    (["service"], "objects_services"),
    (["policy", "policies", "firewall rule"], "policies_security"),
    (["nat", "vip", "snat", "dnat"], "policies_nat"),
    (["route", "routing"], "routing_static"),
    (["bgp", "ospf"], "routing_dynamic"),
    (["ipsec", "phase1", "phase2"], "vpn_ipsec"),
    (["users", "user "], "users_users"),
    (["admin", "accprofile", "management"], "system_management"),
    (["hostname", "system global"], "system_general"),
    (["dhcp"], "network_dhcp"),
    (["profile"], "security_profiles"),
    (["log", "logging"], "diagnostics_logging"),
]

# Profile subtype filters (match properties Category / Profile Type / preview)
_PROFILE_SUBTYPES: list[tuple[list[str], str]] = [
    (["web filter", "webfilter", "web-filter"], "webfilter"),
    (["anti virus", "antivirus", "av "], "antivirus"),
    (["ips", "intrusion"], "ips"),
    (["application", "app control", "app-ctrl"], "application"),
    (["dns filter", "dnsfilter"], "dnsfilter"),
    (["dlp"], "dlp"),
    (["waf"], "waf"),
    (["ssl", "ssh", "ssl-ssh"], "ssl_ssh"),
]

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_SCHEMA_LEAK_RE = re.compile(
    r"(1-3 short sentences|max 2 short|json only|never invent|use only the|"
    r"output json|valid section keys|do not write reasoning|digest:)",
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
    # Local object scan
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
            parts.append(str(obj["raw"])[:2000])
        if obj.get("preview"):
            parts.append(str(obj["preview"]))
        return "\n".join(parts)

    def _profile_category(self, obj: dict[str, Any]) -> str:
        props = obj.get("properties") or {}
        for key in ("Category", "Profile Type", "Type", "category", "profile_type"):
            if props.get(key):
                return str(props[key]).lower()
        return str(obj.get("preview") or "").lower()

    def _search_term(
        self, session: MigrationSession, term: str, limit: int = 40
    ) -> list[dict[str, Any]]:
        term_l = term.lower().strip().strip('"').strip("'")
        if not term_l:
            return []
        hits: list[dict[str, Any]] = []
        for sec, obj, _i in self._iter_objects(session):
            name = str(obj.get("name") or "")
            blob_l = self._object_blob(obj).lower()
            name_l = name.lower()
            if term_l == name_l or term_l in name_l or term_l in blob_l:
                role = "contains"
                if term_l == name_l:
                    role = "exact_name"
                elif term_l in name_l:
                    role = "name"
                elif term_l in str(obj.get("raw") or "").lower():
                    role = "raw"
                else:
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
        hits.sort(key=lambda h: (0 if h["role"] == "exact_name" else 1, h["name"]))
        return hits

    def _list_profile_subtype(
        self, session: MigrationSession, subtype: str
    ) -> AIChatResult:
        sec = next(
            (s for s in session.parsed_sections if s.section_type == "security_profiles"),
            None,
        )
        if not sec or not sec.objects:
            return AIChatResult(
                reply="No security profiles parsed.",
                actions=[],
                offline=True,
            )
        matched = []
        for o in sec.objects:
            cat = self._profile_category(o)
            if subtype in cat or cat in subtype:
                matched.append(o)
        # fallback: name contains subtype token
        if not matched:
            token = subtype.replace("_", " ")
            for o in sec.objects:
                blob = f"{o.get('name','')} {o.get('preview','')}".lower()
                if token in blob or subtype in blob:
                    matched.append(o)
        if not matched:
            return AIChatResult(
                reply=f"No {subtype} profiles found in security profiles ({sec.object_count} total profiles).",
                actions=[AIAction(type="highlight", section="security_profiles", note=subtype)],
                offline=True,
            )
        names = [str(o.get("name")) for o in matched[:25] if o.get("name")]
        more = len(matched) - len(names)
        reply = f"{len(matched)} {subtype} profile(s): " + ", ".join(names)
        if more > 0:
            reply += f" (+{more} more)"
        return AIChatResult(
            reply=reply[:600],
            actions=[AIAction(type="highlight", section="security_profiles", note=subtype)],
            offline=True,
        )

    def _format_hits(self, term: str, hits: list[dict[str, Any]], mode: str) -> AIChatResult:
        if not hits:
            return AIChatResult(
                reply=f'No references to "{term}" found in parsed configuration.',
                actions=[],
                offline=True,
            )
        primary = hits[0]["section"]
        by_sec: dict[str, list[str]] = {}
        for h in hits:
            key = f"{h.get('category') or ''} / {h['section_display']}".strip(" /")
            by_sec.setdefault(key, []).append(h["name"])

        if mode == "explain":
            exact = next((h for h in hits if h["role"] == "exact_name"), hits[0])
            props = exact.get("properties") or {}
            bits = [f"{k}: {v}" for k, v in list(props.items())[:8]]
            others = [
                h
                for h in hits
                if h["name"] != exact["name"] or h["section"] != exact["section"]
            ][:8]
            reply = f"{exact['name']} ({exact['section_display']})"
            if bits:
                reply += " — " + "; ".join(bits)
            if others:
                ref_names = [
                    f"{h['name']} in {h['section_display']}" for h in others[:6]
                ]
                reply += ". Also seen in: " + "; ".join(ref_names)
            return AIChatResult(
                reply=reply[:700],
                actions=[
                    AIAction(type="highlight", section=exact["section"], note=exact["name"])
                ],
                offline=True,
            )

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
        q = user_message.strip()
        ql = q.lower()

        ip_m = _IP_RE.search(q)
        if ip_m and (
            re.search(r"\b(where|reference|referenced|used|find|search|locate)\b", ql)
            or len(q.strip()) < 40
        ):
            return ("reference", ip_m.group(0))

        m = re.search(
            r"(?:where\s+(?:is|are)|find|locate|search)\s+(.+?)(?:\s+referenced|\s+used|\s+defined|\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?")
            if term and term.lower() not in {"this", "it", "that"}:
                return ("reference", term)

        m = re.search(
            r"(?:explain|describe|what\s+is|what's|tell me about|details?\s+(?:on|for))\s+(.+?)(?:\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'")
            if term:
                return ("explain", term)

        m = re.search(r'"([^"]+)"|\'([^\']+)\'', q)
        if m:
            term = m.group(1) or m.group(2)
            if re.search(r"\b(where|reference|used|find)\b", ql):
                return ("reference", term)
            return ("explain", term)

        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]{2,80})\??$", q.strip())
        if m and ("_" in m.group(1) or any(c.isupper() for c in m.group(1)[1:])):
            return ("explain", m.group(1))

        return None

    def _match_profile_subtype(self, text: str) -> str | None:
        t = text.lower()
        for keys, subtype in _PROFILE_SUBTYPES:
            if any(k in t for k in keys):
                return subtype
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
    # Offline
    # ------------------------------------------------------------------

    def _try_offline(self, session: MigrationSession, user_message: str) -> AIChatResult | None:
        q_raw = user_message.strip()
        q = q_raw.lower().strip()
        if not q:
            return None

        # Greetings — never dump stats
        if re.fullmatch(
            r"(hi|hello|hey|hallo|yo|good\s+(morning|afternoon|evening)|howdy)[!?.]*",
            q,
        ):
            vendor = session.source_vendor.display_name if session.source_vendor else "Firewall"
            n = session.statistics.total_objects if session.statistics else 0
            return AIChatResult(
                reply=(
                    f"Hi — {vendor} config loaded ({n} objects). "
                    f"Ask counts, list sections, explain an object, or where an IP is used."
                ),
                actions=[],
                offline=True,
            )

        if not session.parsed_sections:
            return AIChatResult(
                reply="No configuration loaded yet. Upload a config first.",
                actions=[],
                offline=True,
            )

        counts = {
            s.section_type: s.object_count
            for s in session.parsed_sections
            if s.object_count
        }

        def highlight(section: str, note: str = "") -> list[AIAction]:
            return [AIAction(type="highlight", section=section, note=note or None)]

        # Profile subtypes: "web filter", "show me web filter", "list antivirus"
        subtype = self._match_profile_subtype(q)
        if subtype and re.search(
            r"\b(web\s*filter|antivirus|ips|application|dns\s*filter|dlp|waf|profile)\b",
            q,
        ):
            # Avoid treating pure "show interfaces" etc.
            if re.search(
                r"\b(show|list|how many|count|open|go to|highlight|what|web\s*filter|antivirus|ips)\b",
                q,
            ) or q in {
                "web filter",
                "webfilter",
                "antivirus",
                "ips",
                "dns filter",
            }:
                if "how many" in q or "count" in q:
                    # count subtype
                    res = self._list_profile_subtype(session, subtype)
                    # rewrite to count-only
                    sec = next(
                        (
                            s
                            for s in session.parsed_sections
                            if s.section_type == "security_profiles"
                        ),
                        None,
                    )
                    n = 0
                    if sec:
                        for o in sec.objects or []:
                            if subtype in self._profile_category(o):
                                n += 1
                    return AIChatResult(
                        reply=f"{n} {subtype} profile(s).",
                        actions=highlight("security_profiles", subtype),
                        offline=True,
                    )
                return self._list_profile_subtype(session, subtype)

        # IP / object reference & explain
        lookup = self._extract_lookup_term(user_message)
        if lookup:
            mode, term = lookup
            if term.lower() not in {
                "this",
                "it",
                "that",
                "config",
                "configuration",
                "firewall",
                "web filter",  # handled as profile subtype
            }:
                hits = self._search_term(session, term)
                # if explain name not found as object, try profile subtype wording
                if not hits and mode == "explain":
                    st = self._match_profile_subtype(term)
                    if st:
                        return self._list_profile_subtype(session, st)
                return self._format_hits(term, hits, mode)

        # how many admins — special: count administrators only if possible
        if re.search(r"how many\s+admins?", q) or q in {"admins", "admin count"}:
            sec = next(
                (s for s in session.parsed_sections if s.section_type == "system_management"),
                None,
            )
            if sec:
                admins = [
                    o
                    for o in (sec.objects or [])
                    if "admin" in str((o.get("properties") or {}).get("Type", "")).lower()
                    or "admin" in str(o.get("preview") or "").lower()
                    or (o.get("properties") or {}).get("Type") == "administrator"
                ]
                # if type field missing, count objects that aren't accprofile
                if not admins:
                    admins = [
                        o
                        for o in (sec.objects or [])
                        if "accprofile" not in str((o.get("properties") or {}).get("Type", "")).lower()
                        and "profile" not in str(o.get("preview") or "").lower()
                    ]
                profiles = sec.object_count - len(admins)
                reply = f"{len(admins)} administrator(s)"
                if profiles > 0:
                    reply += f", {profiles} access profile(s)"
                reply += f" ({sec.object_count} management objects total)."
                return AIChatResult(
                    reply=reply,
                    actions=highlight("system_management", "admins"),
                    offline=True,
                )

        # how many X?
        m = re.search(r"(?:how many|count|number of|# of)\s+(.+?)(?:\?|$)", q)
        if m or re.match(r"^(interfaces|addresses|policies|users|services|routes)\??$", q):
            topic = m.group(1).strip() if m else q.rstrip("?")
            topic = re.sub(r"\b(are|is|do we have|are there)\b", "", topic).strip()
            # profile subtype count already handled
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
                    "system_management": "management objects",
                    "security_profiles": "security profiles",
                }
                label = labels.get(section, section.replace("_", " "))
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

        # list / show section
        m = re.search(
            r"(?:list|show|display|open|go to|highlight|focus)\s+(?:me\s+)?(?:all\s+)?(.+?)(?:\?|$)",
            q,
        )
        if m:
            topic = m.group(1).strip()
            # profile subtype
            st = self._match_profile_subtype(topic)
            if st:
                return self._list_profile_subtype(session, st)
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
                        reply=reply[:600],
                        actions=highlight(section, "list"),
                        offline=True,
                    )
                if section in counts:
                    return AIChatResult(
                        reply=f"{counts[section]} objects in {section.replace('_', ' ')} (no names extracted).",
                        actions=highlight(section),
                        offline=True,
                    )

        # bare section / profile topic: "web filter", "firewall policy"
        if len(q) < 40 and not q.endswith("?"):
            st = self._match_profile_subtype(q)
            if st:
                return self._list_profile_subtype(session, st)
            section = self._match_section(q)
            # Avoid matching too-generic single words poorly — require known section
            if section and section in counts and q not in {"system", "other", "network"}:
                sec = next(
                    (s for s in session.parsed_sections if s.section_type == section),
                    None,
                )
                if sec and sec.objects:
                    names = [o.get("name", "") for o in sec.objects[:15] if o.get("name")]
                    more = sec.object_count - len(names)
                    reply = f"{sec.object_count} {sec.display_name}: " + ", ".join(names)
                    if more > 0:
                        reply += f" (+{more} more)"
                    return AIChatResult(
                        reply=reply[:600],
                        actions=highlight(section, "browse"),
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

        return None

    # ------------------------------------------------------------------
    # Context / online
    # ------------------------------------------------------------------

    def _tiny_digest(
        self, session: MigrationSession, lookup: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        profile_breakdown: dict[str, int] = {}
        for s in session.parsed_sections:
            if not s.object_count:
                continue
            counts[s.section_type] = s.object_count
            names = [o.get("name", "") for o in (s.objects or [])[:5] if o.get("name")]
            if names:
                samples[s.section_type] = names
            if s.section_type == "security_profiles":
                for o in s.objects or []:
                    cat = self._profile_category(o) or "other"
                    profile_breakdown[cat] = profile_breakdown.get(cat, 0) + 1

        digest: dict[str, Any] = {
            "vendor": session.source_vendor.value,
            "file": session.filename,
            "total_objects": session.statistics.total_objects if session.statistics else 0,
            "counts": counts,
            "samples": samples,
            "profile_breakdown": profile_breakdown,
            "warnings": [
                {
                    "sev": w.severity.value if hasattr(w.severity, "value") else str(w.severity),
                    "msg": w.message[:100],
                }
                for w in (session.warnings or [])[:8]
            ],
        }
        if lookup:
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
                content = msg.content.strip()
                if self._is_bad_reply(content):
                    continue
                messages.append({"role": msg.role, "content": content[:400]})
        messages.append({"role": "user", "content": user_message[:1000]})
        return messages

    def _is_bad_reply(self, text: str) -> bool:
        if not text or not text.strip():
            return True
        t = text.lower()
        if _SCHEMA_LEAK_RE.search(text):
            return True
        markers = [
            "i need to be careful",
            "the instruction says",
            "user is asking",
            "i must only use",
            "let me think",
            "my instructions",
            "as an ai",
        ]
        if any(m in t for m in markers):
            return True
        # stats dump from old fallback (starts with Vendor: N objects.)
        if re.match(r"^(fortigate|palo|check point|cisco ftd):\s*\d+\s+objects\.", t):
            return True
        if len(text) > 400 and text.count(".") > 8 and "{" not in text:
            return True
        return False

    async def chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AIChatResult:
        offline = self._try_offline(session, user_message)
        if offline is not None:
            logger.info("AI offline: %s -> %s", user_message[:60], offline.reply[:80])
            return offline

        if not self.enabled:
            return self._offline_result(session, user_message)

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
                    if lookup_hits:
                        term = term_info[1] if term_info else ip_m.group(0)  # type: ignore
                        mode = term_info[0] if term_info else "reference"
                        return self._format_hits(term, lookup_hits, mode)
                    return self._offline_result(session, user_message)

                data = resp.json()
                text = self._extract_content(data)
                result = self.parse_ai_response(text)

                if self._is_bad_reply(result.reply):
                    if lookup_hits:
                        term = term_info[1] if term_info else (ip_m.group(0) if ip_m else "query")
                        mode = term_info[0] if term_info else "reference"
                        return self._format_hits(term, lookup_hits, mode)
                    # friendly fallback — not stats spam
                    return AIChatResult(
                        reply=(
                            "I can help with this config: try “how many policies”, "
                            "“show web filter”, “explain <object>”, or “where is <IP> referenced”."
                        ),
                        actions=[],
                        offline=True,
                    )

                return self._merge_actions(session, user_message, result)
        except httpx.HTTPError as exc:
            logger.exception("AI request failed: %s", exc)
            if lookup_hits:
                term = term_info[1] if term_info else (ip_m.group(0) if ip_m else "query")
                mode = term_info[0] if term_info else "reference"
                return self._format_hits(term, lookup_hits, mode)
            return AIChatResult(
                reply="AI service unreachable. Local lookup still works for counts, lists, and object/IP search.",
                actions=[],
                offline=True,
            )

    def parse_ai_response(self, text: str) -> AIChatResult:
        raw = (text or "").strip()
        if not raw:
            return AIChatResult(reply="", actions=[], raw=raw)

        if self._is_bad_reply(raw) and "{" not in raw:
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

        brief = re.sub(r"\s+", " ", raw).strip()
        if self._is_bad_reply(brief):
            return AIChatResult(reply="", actions=[], raw=text)
        if len(brief) > 280:
            brief = brief[:277].rstrip() + "…"
        return AIChatResult(reply=brief, actions=[], raw=text)

    def apply_actions(
        self, session: MigrationSession, actions: list[AIAction]
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
            reasoning = msg.get("reasoning_content") or msg.get("reasoning")
            if isinstance(reasoning, str) and '"reply"' in reasoning:
                return reasoning
            return ""
        if "error" in data:
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            return json.dumps({"reply": f"AI error: {msg}"})
        return ""

    def _offline_result(self, session: MigrationSession, user_message: str) -> AIChatResult:
        offline = self._try_offline(session, user_message)
        if offline:
            return offline
        return AIChatResult(
            reply=(
                "Try: “how many policies”, “show web filter”, “explain <name>”, "
                "or “where is <IP> referenced”."
            ),
            actions=[],
            offline=True,
        )

    async def stream_chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AsyncIterator[str]:
        result = await self.chat(session, user_message, include_raw=include_raw)
        yield result.reply
