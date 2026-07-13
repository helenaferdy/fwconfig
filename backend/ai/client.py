"""AI Configuration Analysis Consultant via OpenCode (DeepSeek-V4-Flash).

Plan A (speed-first):
- Tiny workspace digest on every call
- Offline instant answers for simple count/list questions
- Low max_tokens, minimal reasoning
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

SYSTEM_PROMPT = """You are FWM-AI, a brief firewall config analyst.
Use ONLY the tiny workspace digest provided. Never invent objects/IPs.
Reply with JSON only:
{"reply":"1-2 short sentences max","actions":[{"type":"highlight","section":"network_interfaces","note":"optional"}]}
section keys: system_general,system_management,network_interfaces,network_dhcp,objects_addresses,objects_address_groups,objects_services,objects_service_groups,policies_security,policies_nat,routing_static,routing_dynamic,vpn_ipsec,vpn_ssl,users_users,users_groups,security_profiles,diagnostics_logging,other_unclassified
Be extremely brief. No markdown. No thinking dump.
"""

# Map keywords → taxonomy leaf for offline / scoped highlights
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
    (["hostname", "system global", "system"], "system_general"),
    (["dhcp"], "network_dhcp"),
    (["ips", "antivirus", "webfilter", "profile"], "security_profiles"),
    (["log", "logging"], "diagnostics_logging"),
]


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
    # Compact context (Plan A)
    # ------------------------------------------------------------------

    def _tiny_digest(self, session: MigrationSession) -> dict[str, Any]:
        """Minimal session digest — keep under ~2–4k tokens typically."""
        counts: dict[str, int] = {}
        samples: dict[str, list[str]] = {}
        for s in session.parsed_sections:
            if not s.object_count:
                continue
            counts[s.section_type] = s.object_count
            # 5 names max per section
            names = [o.get("name", "") for o in (s.objects or [])[:5] if o.get("name")]
            if names:
                samples[s.section_type] = names

        warns = [
            {
                "sev": w.severity.value if hasattr(w.severity, "value") else str(w.severity),
                "msg": w.message[:120],
                "section": w.section,
            }
            for w in (session.warnings or [])[:12]
        ]

        unused: list[str] = []
        if session.dependency_graph:
            for n in session.dependency_graph.unused_nodes()[:15]:
                unused.append(f"{n.kind}:{n.name}")

        return {
            "vendor": session.source_vendor.value,
            "file": session.filename,
            "total_objects": session.statistics.total_objects if session.statistics else 0,
            "counts": counts,
            "samples": samples,
            "warnings": warns,
            "unused_sample": unused,
            "errors": session.statistics.error_count if session.statistics else 0,
        }

    def _build_messages(
        self,
        session: MigrationSession,
        user_message: str,
    ) -> list[dict[str, str]]:
        digest = self._tiny_digest(session)
        # compact JSON (no indent)
        blob = json.dumps(digest, default=str, separators=(",", ":"))
        if len(blob) > 12000:
            blob = blob[:12000] + "…]"

        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": f"DIGEST:{blob}"},
        ]
        # last 4 turns only
        for msg in session.chat_history[-8:]:
            if msg.role in ("user", "assistant") and msg.content:
                # strip long assistant dumps
                content = msg.content[:500]
                messages.append({"role": msg.role, "content": content})
        messages.append({"role": "user", "content": user_message[:1000]})
        return messages

    # ------------------------------------------------------------------
    # Offline shortcuts (instant)
    # ------------------------------------------------------------------

    def _try_offline(self, session: MigrationSession, user_message: str) -> AIChatResult | None:
        """Answer simple factual questions without calling the API."""
        q = user_message.lower().strip()
        if not q or not session.parsed_sections:
            return None

        counts = {
            s.section_type: s.object_count
            for s in session.parsed_sections
            if s.object_count
        }
        by_display = {
            (s.display_name or "").lower(): s
            for s in session.parsed_sections
            if s.object_count
        }

        def highlight(section: str, note: str = "") -> list[AIAction]:
            return [AIAction(type="highlight", section=section, note=note or None)]

        # how many X?
        m = re.search(
            r"(?:how many|count|number of|# of)\s+(.+?)(?:\?|$)",
            q,
        )
        if m or re.match(r"^(interfaces|addresses|policies|users|services|routes)\??$", q):
            topic = m.group(1).strip() if m else q.rstrip("?")
            topic = re.sub(r"\b(are|is|do we have|are there)\b", "", topic).strip()
            section = self._match_section(topic) or self._match_section(q)
            if section and section in counts:
                n = counts[section]
                # Friendly labels
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
            # total objects
            if "object" in topic or "total" in topic:
                total = session.statistics.total_objects if session.statistics else sum(counts.values())
                return AIChatResult(
                    reply=f"{total} total parsed objects.",
                    actions=[],
                    offline=True,
                )

        # list names
        m = re.search(r"(?:list|show|name)\s+(?:all\s+)?(.+?)(?:\?|$)", q)
        if m:
            topic = m.group(1).strip()
            section = self._match_section(topic)
            if section:
                sec = next((s for s in session.parsed_sections if s.section_type == section), None)
                if sec and sec.objects:
                    names = [o.get("name", "") for o in sec.objects[:20] if o.get("name")]
                    more = sec.object_count - len(names)
                    reply = ", ".join(names)
                    if more > 0:
                        reply += f" (+{more} more)"
                    return AIChatResult(
                        reply=reply[:400],
                        actions=highlight(section, "list"),
                        offline=True,
                    )

        # unused
        if "unused" in q:
            unused = []
            if session.dependency_graph:
                unused = session.dependency_graph.unused_nodes()[:12]
            if not unused:
                return AIChatResult(reply="No unused objects flagged.", actions=[], offline=True)
            bits = [f"{n.name} ({n.kind})" for n in unused]
            sec = unused[0].section or "objects_addresses"
            return AIChatResult(
                reply=f"Unused: {', '.join(bits)}",
                actions=highlight(sec if isinstance(sec, str) else "objects_addresses", "unused"),
                offline=True,
            )

        # vendor / hostname / file
        if re.search(r"\b(vendor|hostname|filename|what file)\b", q):
            host = None
            if session.common_model:
                host = session.common_model.hostname
            return AIChatResult(
                reply=(
                    f"Vendor: {session.source_vendor.display_name}. "
                    f"File: {session.filename or '—'}. "
                    f"Hostname: {host or '—'}."
                ),
                actions=highlight("system_general"),
                offline=True,
            )

        # simple section jump: "show interfaces" / "go to policies"
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
        # direct leaf id
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
        include_raw: bool = False,  # ignored in Plan A (never send raw by default)
    ) -> AIChatResult:
        # 1) Instant offline path
        offline = self._try_offline(session, user_message)
        if offline is not None:
            logger.info("AI offline shortcut used for: %s", user_message[:80])
            return offline

        if not self.enabled:
            return self._offline_result(session, user_message)

        messages = self._build_messages(session, user_message)
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
                    offline_fb = self._offline_result(session, user_message)
                    offline_fb.reply = f"AI HTTP {resp.status_code}. {offline_fb.reply}"
                    return offline_fb

                data = resp.json()
                text = self._extract_content(data)
                if not text.strip():
                    return self._offline_result(session, user_message)
                result = self.parse_ai_response(text)
                return self._merge_actions(session, user_message, result)
        except httpx.HTTPError as exc:
            logger.exception("AI request failed")
            offline_fb = self._offline_result(session, user_message)
            offline_fb.reply = f"AI unreachable. {offline_fb.reply}"
            return offline_fb

    def parse_ai_response(self, text: str) -> AIChatResult:
        raw = text.strip()
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
            reply = str(data.get("reply") or "").strip() or "Done."
            if len(reply) > 280:
                reply = reply[:277].rstrip() + "…"
            actions: list[AIAction] = []
            for item in data.get("actions") or []:
                if not isinstance(item, dict):
                    continue
                atype = str(item.get("type") or "").strip()
                if not atype:
                    continue
                actions.append(
                    AIAction(
                        type=atype,
                        section=item.get("section"),
                        content=None,  # never accept patches in Plan A
                        object_count=item.get("object_count"),
                        note=item.get("note"),
                    )
                )
            return AIChatResult(reply=reply, actions=actions, raw=text)

        brief = re.sub(r"\s+", " ", raw).strip()
        if len(brief) > 220:
            brief = brief[:217].rstrip() + "…"
        return AIChatResult(reply=brief or "OK.", actions=[], raw=text)

    def apply_actions(
        self,
        session: MigrationSession,
        actions: list[AIAction],
    ) -> list[dict[str, Any]]:
        applied: list[dict[str, Any]] = []
        for action in actions:
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
        if len(result.reply) > 280:
            result.reply = result.reply[:277].rstrip() + "…"
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
            if isinstance(reasoning, str) and reasoning.strip():
                cleaned = reasoning.strip()
                if "{" in cleaned and '"reply"' in cleaned:
                    return cleaned
                # Prefer short tail
                if len(cleaned) > 400:
                    return cleaned[-400:]
                return cleaned
        if "error" in data:
            err = data["error"]
            if isinstance(err, dict):
                return f"AI error: {err.get('message') or err}"
            return f"AI error: {err}"
        return ""

    def _offline_result(self, session: MigrationSession, user_message: str) -> AIChatResult:
        """Generic offline summary when API unavailable or empty."""
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
