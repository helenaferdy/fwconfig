"""AI Configuration Analysis Consultant via OpenCode (DeepSeek-V4-Flash).

Helps engineers understand parsed firewall configurations.
Does NOT invent config values. References only session parsed data.
Can highlight / annotate middle-pane summary sections (IDE-style).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import httpx

from config import Settings, get_settings
from model.objects import GeneratedSection
from session.store import MigrationSession

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are FWM-AI, an expert firewall migration consultant for configuration ANALYSIS.

CONTEXT: The user uploaded a firewall config. It was deterministically parsed into a structured model
and human-readable section summaries. There is NO target vendor conversion.

YOUR JOB:
- Explain policies, NAT, VPN, interfaces, routes, objects
- Identify unused objects, duplicates, migration concerns
- Answer only from the provided workspace JSON
- Never fabricate IPs, object names, or rules

OUTPUT: raw JSON only. No markdown. No preamble.
Schema:
{"reply":"max 2 short sentences","actions":[{"type":"highlight|annotate|clear_highlights","section":"firewall_policies","note":"optional"}]}

section keys (taxonomy leaves): network_interfaces, network_zones, network_dhcp,
objects_addresses, objects_address_groups, objects_services, objects_service_groups,
policies_security, policies_nat, routing_static, routing_dynamic, vpn_ipsec, vpn_ssl,
users_users, users_groups, system_general, security_profiles, other_unclassified

Use highlight to focus the middle-pane summary. Be super brief. Low thinking effort.
"""


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

    def _build_workspace_context(self, session: MigrationSession) -> dict[str, Any]:
        ctx = session.summary_for_ai()

        # Include summary text (capped) for each section
        gen_sections = []
        for s in session.generated_sections:
            body = s.content or ""
            if len(body) > 4000:
                body = body[:4000] + "\n… truncated"
            gen_sections.append(
                {
                    "section_type": s.section_type,
                    "display_name": s.display_name,
                    "object_count": s.object_count,
                    "summary": body,
                }
            )
        ctx["human_readable_summaries"] = gen_sections

        src_sections = []
        for s in session.parsed_sections:
            if s.object_count == 0 and not s.errors:
                continue
            src_sections.append(
                {
                    "section_type": s.section_type,
                    "display_name": s.display_name,
                    "object_count": s.object_count,
                    "objects": s.objects[:30],
                    "errors": s.errors,
                }
            )
        ctx["source_sections"] = src_sections
        ctx["instruction"] = (
            "Workspace is authoritative. Explain configuration; highlight sections when relevant. "
            "JSON reply only."
        )
        return ctx

    def _build_messages(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> list[dict[str, str]]:
        context = self._build_workspace_context(session)
        if include_raw and session.original_config:
            context["original_config_excerpt"] = session.original_config[:12000]

        context_blob = json.dumps(context, indent=2, default=str)
        if len(context_blob) > 90000:
            context_blob = context_blob[:90000] + "\n... [truncated]"

        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "system",
                "content": f"CONFIGURATION WORKSPACE:\n{context_blob}",
            },
        ]
        for msg in session.chat_history[-12:]:
            if msg.role in ("user", "assistant"):
                messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": user_message})
        return messages

    async def chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AIChatResult:
        if not self.enabled:
            return self._offline_result(session, user_message)

        messages = self._build_messages(session, user_message, include_raw=include_raw)
        url = f"{self.settings.opencode_base_url.rstrip('/')}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.settings.opencode_model,
            "messages": messages,
            "temperature": min(self.settings.ai_temperature, 0.2),
            "max_tokens": min(self.settings.ai_max_tokens, 2048),
            "stream": False,
            "reasoning_effort": "low",
        }

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(url, headers=self._headers(), json=payload)
                if resp.status_code >= 400:
                    logger.error("AI API error %s: %s", resp.status_code, resp.text[:500])
                    alt = await self._try_alternate_endpoints(client, messages)
                    if alt:
                        return self._merge_actions(session, user_message, self.parse_ai_response(alt))
                    try:
                        err_body = resp.json()
                        err = err_body.get("error") or err_body
                        err_msg = err.get("message") if isinstance(err, dict) else str(err)
                    except Exception:  # noqa: BLE001
                        err_msg = resp.text[:300]
                    offline = self._offline_result(session, user_message)
                    offline.reply = f"AI HTTP {resp.status_code}: {err_msg}. {offline.reply}"
                    return offline

                data = resp.json()
                text = self._extract_content(data)
                if not text.strip():
                    return self._offline_result(session, user_message)
                return self._merge_actions(session, user_message, self.parse_ai_response(text))
        except httpx.HTTPError as exc:
            logger.exception("AI request failed")
            offline = self._offline_result(session, user_message)
            offline.reply = f"AI unreachable. {offline.reply}"
            return offline

    async def _try_alternate_endpoints(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
    ) -> str | None:
        candidates = [
            f"{self.settings.opencode_base_url.rstrip('/')}/chat/completions",
            "https://opencode.ai/zen/go/v1/chat/completions",
        ]
        payload = {
            "model": self.settings.opencode_model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 2048,
            "reasoning_effort": "low",
        }
        seen: set[str] = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = await client.post(url, headers=self._headers(), json=payload)
                if resp.status_code < 400:
                    text = self._extract_content(resp.json())
                    if text.strip():
                        return text
            except httpx.HTTPError:
                continue
        return None

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
                if len(cleaned) > 600:
                    paras = [p.strip() for p in cleaned.split("\n\n") if p.strip()]
                    if paras:
                        return paras[-1]
                return cleaned
        if "error" in data:
            err = data["error"]
            if isinstance(err, dict):
                return f"AI error: {err.get('message') or err}"
            return f"AI error: {err}"
        return ""

    def parse_ai_response(self, text: str) -> AIChatResult:
        raw = text.strip()
        candidates: list[str] = []
        for fence in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", raw):
            candidates.append(fence.group(1).strip())
        for i, ch in enumerate(raw):
            if ch != "{":
                continue
            depth = 0
            for j in range(i, len(raw)):
                if raw[j] == "{":
                    depth += 1
                elif raw[j] == "}":
                    depth -= 1
                    if depth == 0:
                        chunk = raw[i : j + 1]
                        if '"reply"' in chunk:
                            candidates.append(chunk)
                        break
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
                        content=item.get("content"),
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
        """Highlight/annotate only — analysis mode does not rewrite summaries via AI."""
        applied: list[dict[str, Any]] = []
        for action in actions:
            if action.type == "patch_section":
                # Ignore patches in analysis mode; summaries are deterministic
                continue
            applied.append(action.to_dict())
            if action.type in ("highlight", "annotate") and action.section:
                session.add_log(
                    "ai_review",
                    f"AI focused section: {action.section}"
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
        lower = user_message.lower()
        offline = self._offline_result(session, user_message)
        if not result.actions:
            result.actions = offline.actions
            if len(result.reply) > 220 or "we are" in result.reply.lower():
                result.reply = offline.reply
        if len(result.reply) > 280:
            result.reply = result.reply[:277].rstrip() + "…"
        # Keyword boosts when model skipped highlight
        if not result.actions:
            if "policy" in lower:
                result.actions = [AIAction(type="highlight", section="policies_security")]
            elif "interface" in lower or "wan" in lower:
                result.actions = [AIAction(type="highlight", section="network_interfaces")]
            elif "nat" in lower:
                result.actions = [AIAction(type="highlight", section="policies_nat")]
            elif "route" in lower:
                result.actions = [AIAction(type="highlight", section="routing_static")]
            elif "vpn" in lower or "ipsec" in lower:
                result.actions = [AIAction(type="highlight", section="vpn_ipsec")]
            elif "address" in lower:
                result.actions = [AIAction(type="highlight", section="objects_addresses")]
        return result

    def _offline_result(self, session: MigrationSession, user_message: str) -> AIChatResult:
        stats = session.statistics
        lines = []
        if not session.common_model:
            lines.append("No analysis yet — upload a configuration.")
        else:
            lines.append(
                f"{session.source_vendor.display_name}: {stats.total_objects} objects parsed."
            )
            if stats.error_count:
                lines.append(f"{stats.error_count} validation errors.")
            counts = session.common_model.section_counts()
            top = [f"{k}={v}" for k, v in counts.items() if v][:5]
            if top:
                lines.append("Top: " + ", ".join(top))
        reply = " ".join(lines)
        actions: list[AIAction] = []
        lower = user_message.lower()
        if "policy" in lower:
            actions = [AIAction(type="highlight", section="policies_security", note="policies")]
        elif "interface" in lower or "wan" in lower:
            actions = [AIAction(type="highlight", section="network_interfaces", note="interfaces")]
        elif "nat" in lower:
            actions = [AIAction(type="highlight", section="policies_nat", note="nat")]
        elif "unused" in lower and session.dependency_graph:
            unused = session.dependency_graph.unused_nodes()[:5]
            if unused:
                reply = f"{len(unused)}+ unused objects e.g. {unused[0].name} ({unused[0].kind})."
                section = unused[0].section or "addresses"
                actions = [AIAction(type="highlight", section=section, note="unused")]
        return AIChatResult(reply=reply, actions=actions, raw=reply)

    async def stream_chat(
        self,
        session: MigrationSession,
        user_message: str,
        include_raw: bool = False,
    ) -> AsyncIterator[str]:
        result = await self.chat(session, user_message, include_raw=include_raw)
        yield result.reply
