"""AI Configuration Analysis Consultant via OpenCode / DeepSeek-V4-Flash.

Always calls the DeepSeek API (no offline stub answers).
Speed optimizations:
- Compact session digest (counts + samples, not full objects)
- Question-scoped LOOKUP injection for IPs / object names
- Low max_tokens, compact JSON, short history
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

SYSTEM_PROMPT = """You are FWM-AI, an expert firewall configuration analyst helping with migration review.

Rules:
- Use ONLY the DIGEST and LOOKUP JSON provided. Never invent objects, IPs, or rules.
- If LOOKUP is present, prioritize it for the answer.
- Be concise but useful (2–5 sentences, or a short bullet list when listing).
- When relevant, include a highlight action for the UI section.
- Reply with JSON only, no markdown fences, no chain-of-thought:
{"reply":"<answer>","actions":[{"type":"highlight","section":"<leaf_id>","note":"<optional>"}]}

Section leaf ids: system_general, system_management, network_interfaces, network_dhcp,
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
    r"i need to be careful|the instruction says|user is asking|i must only use|"
    r"let me think|my instructions|as an ai|"
    r"assistant was cut off|the user now says|appears the assistant)",
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
            parts.append(raw[:2500])
        if obj.get("preview"):
            parts.append(str(obj["preview"]))
        return "\n".join(parts)

    def _profile_category(self, obj: dict[str, Any]) -> str:
        props = obj.get("properties") or {}
        for key in ("Category", "Profile Type", "Type", "category"):
            if props.get(key):
                return str(props[key]).lower()
        return str(obj.get("preview") or "").lower()

    def _search_term(
        self, session: MigrationSession, term: str, limit: int = 30
    ) -> list[dict[str, Any]]:
        term_l = term.lower().strip().strip('"').strip("'")
        if not term_l:
            return []
        hits: list[dict[str, Any]] = []
        for sec, obj in self._iter_objects(session):
            name = str(obj.get("name") or "")
            blob_l = self._object_blob(obj).lower()
            name_l = name.lower()
            if term_l == name_l or term_l in name_l or term_l in blob_l:
                role = "contains"
                if term_l == name_l:
                    role = "exact_name"
                elif term_l in name_l:
                    role = "name"
                hits.append(
                    {
                        "section": sec.section_type,
                        "section_display": sec.display_name,
                        "category": sec.category_display,
                        "name": name,
                        "role": role,
                        "preview": (obj.get("preview") or "")[:100],
                        "properties": {
                            k: v
                            for k, v in list((obj.get("properties") or {}).items())[:10]
                            if v not in (None, "", [])
                        },
                    }
                )
                if len(hits) >= limit:
                    break
        hits.sort(key=lambda h: (0 if h["role"] == "exact_name" else 1, h["name"]))
        return hits

    def _extract_lookup_term(self, user_message: str) -> str | None:
        q = user_message.strip()
        ql = q.lower()

        ip_m = _IP_RE.search(q)
        if ip_m:
            return ip_m.group(0)

        m = re.search(
            r"(?:where\s+(?:is|are)|find|locate|search|explain|describe|what\s+is|what's|tell me about)\s+(.+?)(?:\s+referenced|\s+used|\s+defined|\?|$)",
            q,
            re.I,
        )
        if m:
            term = m.group(1).strip(" \"'?")
            if term and term.lower() not in {"this", "it", "that", "the"}:
                return term

        m = re.search(r'"([^"]+)"|\'([^\']+)\'', q)
        if m:
            return m.group(1) or m.group(2)

        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]{2,80})\??$", q.strip())
        if m and ("_" in m.group(1) or any(c.isupper() for c in m.group(1)[1:])):
            return m.group(1)

        return None

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
                o.get("name", "") for o in (s.objects or [])[:8] if o.get("name")
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
                for w in (session.warnings or [])[:15]
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
                session, scoped, limit=50, profile_filter=profile_filter
            )
            if detail:
                digest["focus_section"] = detail

        # LOOKUP for IP / object name questions
        term = self._extract_lookup_term(user_message)
        if term:
            hits = self._search_term(session, term, limit=30)
            digest["lookup_term"] = term
            digest["lookup"] = hits

        # Light graph unused sample only if asked
        if "unused" in ql and session.dependency_graph:
            digest["unused_sample"] = [
                {"name": n.name, "kind": n.kind, "section": n.section}
                for n in session.dependency_graph.unused_nodes()[:20]
            ]

        return digest

    def _build_messages(
        self, session: MigrationSession, user_message: str
    ) -> list[dict[str, str]]:
        digest = self._build_digest(session, user_message)
        blob = json.dumps(digest, default=str, separators=(",", ":"))
        # hard cap ~6–8k tokens-ish of context
        if len(blob) > 24000:
            blob = blob[:24000] + "…]}"

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
        if not self.enabled:
            return AIChatResult(
                reply="AI is not configured (missing OPENCODE_API_KEY).",
                actions=[],
            )

        messages = self._build_messages(session, user_message)
        url = f"{self.settings.opencode_base_url.rstrip('/')}/chat/completions"
        max_tokens = min(int(self.settings.ai_max_tokens or 600), 800)

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
                    # One retry without history, even smaller prompt
                    logger.warning("Bad AI reply filtered; retrying once")
                    retry_messages = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "system",
                            "content": f"DIGEST:{json.dumps(self._build_digest(session, user_message), default=str, separators=(',', ':'))[:20000]}",
                        },
                        {"role": "user", "content": user_message[:2000]},
                    ]
                    resp2 = await client.post(
                        url,
                        headers=self._headers(),
                        json={**payload, "messages": retry_messages, "max_tokens": 500},
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
            if len(reply) > 1200:
                reply = reply[:1197].rstrip() + "…"
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
                if len(reply) > 1200:
                    reply = reply[:1197].rstrip() + "…"
                return AIChatResult(reply=reply, actions=actions, raw=text)

        # plain text fallback if not JSON-looking and not bad
        brief = re.sub(r"\s+", " ", raw).strip()
        if brief.startswith("{") or self._is_bad_reply(brief):
            return AIChatResult(reply="", actions=[], raw=text)
        if len(brief) > 800:
            brief = brief[:797].rstrip() + "…"
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

    async def generate_intro(self, session: MigrationSession) -> AIChatResult:
        """AI-initiated welcome + configuration summary after analysis completes."""
        prompt = (
            "Analysis just finished. Write a short introduction for the engineer: "
            "greet them, summarize this firewall configuration (hostname, vendor, "
            "key section counts, important objects), call out critical warnings or "
            "migration risks, and suggest 2–3 useful next questions they could ask. "
            "Be clear and professional, 1 short paragraph plus optional short bullets."
        )
        return await self.chat(session, prompt)

    def _merge_actions(
        self,
        session: MigrationSession,
        user_message: str,
        result: AIChatResult,
    ) -> AIChatResult:
        if not result.actions:
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
