"""Check Point configuration parser.

Supports:
  - GAiA `show configuration` (gateway OS / network)
  - `migrate_server export` .tgz (management objects + policy)
  - Combined multi-file sessions (both)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from model.enums import SectionType, Vendor
from model.objects import CommonModel, ParsedSection
from parser.base import ParseResult, SectionParser, VendorParser, register_parser
from parser.checkpoint.gaia import is_gaia_show_config, parse_gaia_into_model
from parser.checkpoint.migrate_export import is_migrate_server_tgz, parse_migrate_tgz
from parser.common import StubSectionParser

logger = logging.getLogger(__name__)


def _stub(section: SectionType, patterns: list[str]) -> SectionParser:
    class _P(StubSectionParser):
        section_type = section
        search_patterns = patterns

    return _P()


def _merge_sections(sections: list[ParsedSection]) -> list[ParsedSection]:
    """Merge sections that share the same section_type (e.g. interfaces from both sources)."""
    by_type: dict[str, ParsedSection] = {}
    order: list[str] = []
    for sec in sections:
        key = sec.section_type
        if key not in by_type:
            by_type[key] = sec
            order.append(key)
            continue
        existing = by_type[key]
        # Deduplicate objects by name
        seen = {str(o.get("name")) for o in existing.objects}
        for o in sec.objects:
            n = str(o.get("name"))
            if n in seen:
                # Prefer GAiA raw (often more complete) when names collide
                for i, eo in enumerate(existing.objects):
                    if str(eo.get("name")) == n:
                        # keep the one with longer raw / more props
                        if len(str(o.get("raw") or "")) > len(str(eo.get("raw") or "")):
                            existing.objects[i] = o
                        break
            else:
                existing.objects.append(o)
                seen.add(n)
        existing.object_count = len(existing.objects)
        existing.parsed_ok = existing.parsed_ok and sec.parsed_ok
        if sec.raw_snippets:
            existing.raw_snippets = list(existing.raw_snippets or []) + list(
                sec.raw_snippets
            )
        if sec.errors:
            existing.errors = list(existing.errors or []) + list(sec.errors)
    return [by_type[k] for k in order]


@register_parser(Vendor.CHECKPOINT)
class CheckPointParser(VendorParser):
    vendor = Vendor.CHECKPOINT
    fingerprints = [
        r"set\s+interface\s+",
        r"GAiA\s+version",
        r"show configuration",
        r"add\s+access-rule",
        r"add\s+host\s+name",
        r"add\s+network\s+name",
        r"set\s+package\s+",
        r"cpconfig",
        r"##Check Point",
        r"add\s+service-tcp",
        r"mgmt_cli",
        r"uid\s*:\s*\"[0-9a-f-]{36}\"",
        r"com\.checkpoint\.management",
        r"migrate_server",
        r"set\s+static-route\s+",
        r"set\s+hostname\s+",
    ]

    def build_section_parsers(self) -> list[SectionParser]:
        # Used only for legacy single-text CLI paths; multi-source uses parse_sources().
        return [
            _stub(SectionType.INTERFACES, [r"set\s+interface\s+"]),
            _stub(SectionType.ADDRESSES, [r"add\s+host\s+name", r"add\s+network\s+name"]),
            _stub(SectionType.ADDRESS_GROUPS, [r"add\s+group\s+name"]),
            _stub(SectionType.SERVICES, [r"add\s+service-tcp", r"add\s+service-udp"]),
            _stub(SectionType.SERVICE_GROUPS, [r"add\s+service-group"]),
            _stub(SectionType.FIREWALL_POLICIES, [r"add\s+access-rule", r"AccessCtrlRule"]),
            _stub(SectionType.NAT, [r"add\s+nat-rule", r"NatRule"]),
            _stub(SectionType.STATIC_ROUTES, [r"set\s+static-route"]),
            _stub(SectionType.OSPF, [r"set\s+ospf"]),
            _stub(SectionType.DNS, [r"set\s+dns"]),
            _stub(SectionType.SYSTEM_SETTINGS, [r"set\s+hostname", r"GAiA\s+version"]),
        ]

    def detect_score(self, raw: str) -> float:
        if is_gaia_show_config(raw or ""):
            return 1.0
        if raw and "com.checkpoint.management" in raw:
            return 0.9
        return super().detect_score(raw or "")

    def parse(self, raw: str) -> ParseResult:
        """Parse GAiA text (or fallback stubs for other CLI dumps)."""
        model = CommonModel(source_vendor=self.vendor.value)
        warnings: list[dict] = []
        sections: list[ParsedSection] = []

        if is_gaia_show_config(raw or ""):
            try:
                sections.extend(parse_gaia_into_model(raw, model))
            except Exception as exc:  # noqa: BLE001
                logger.exception("GAiA parse failed")
                warnings.append(
                    {
                        "code": "CP_GAIA_FAIL",
                        "message": f"GAiA parse failed: {exc}",
                        "severity": "error",
                    }
                )
        else:
            # Legacy path: run stub section parsers so detection still works
            return super().parse(raw)

        return self._finalize(model, sections, warnings)

    def parse_sources(
        self,
        *,
        gaia_text: str | None = None,
        migrate_tgz: bytes | None = None,
        extra_text: str | None = None,
    ) -> ParseResult:
        """Parse GAiA CLI and/or migrate_server tgz into one CommonModel."""
        model = CommonModel(source_vendor=self.vendor.value)
        warnings: list[dict] = []
        sections: list[ParsedSection] = []

        if gaia_text and is_gaia_show_config(gaia_text):
            try:
                sections.extend(parse_gaia_into_model(gaia_text, model))
                warnings.append(
                    {
                        "code": "CP_GAIA_OK",
                        "message": "Parsed GAiA show configuration (gateway OS)",
                        "severity": "info",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("GAiA parse failed")
                warnings.append(
                    {
                        "code": "CP_GAIA_FAIL",
                        "message": f"GAiA parse failed: {exc}",
                        "severity": "error",
                    }
                )
        elif gaia_text and not migrate_tgz:
            # plain text fallback
            return self.parse(gaia_text)

        if migrate_tgz and is_migrate_server_tgz(migrate_tgz):
            try:
                mgmt_sections, mgmt_warns = parse_migrate_tgz(migrate_tgz, model)
                sections.extend(mgmt_sections)
                warnings.extend(mgmt_warns)
            except Exception as exc:  # noqa: BLE001
                logger.exception("migrate_server parse failed")
                warnings.append(
                    {
                        "code": "CP_MIGRATE_FAIL",
                        "message": f"migrate_server parse failed: {exc}",
                        "severity": "error",
                    }
                )
        elif migrate_tgz:
            warnings.append(
                {
                    "code": "CP_TGZ_UNKNOWN",
                    "message": "Uploaded archive does not look like a migrate_server export",
                    "severity": "warning",
                }
            )

        if extra_text and not gaia_text:
            if is_gaia_show_config(extra_text):
                sections.extend(parse_gaia_into_model(extra_text, model))

        if not sections and not model.total_objects():
            warnings.append(
                {
                    "code": "CP_EMPTY",
                    "message": "No Check Point configuration could be parsed from uploads",
                    "severity": "error",
                }
            )

        return self._finalize(model, sections, warnings)

    def _finalize(
        self,
        model: CommonModel,
        sections: list[ParsedSection],
        warnings: list[dict],
    ) -> ParseResult:
        from model.enums import SECTION_ORDER

        sections = _merge_sections(sections)
        present = {s.section_type for s in sections}
        for st in SECTION_ORDER:
            if st.value not in present:
                sections.append(
                    ParsedSection(
                        section_type=st.value,
                        display_name=st.display_name,
                        object_count=0,
                        parsed_ok=True,
                    )
                )
        order_map = {st.value: i for i, st in enumerate(SECTION_ORDER)}
        sections.sort(key=lambda s: order_map.get(s.section_type, 999))
        return ParseResult(
            model=model, sections=sections, vendor=self.vendor, warnings=warnings
        )


def build_display_config(
    gaia_text: str | None,
    migrate_summary: str | None = None,
    filenames: list[str] | None = None,
) -> str:
    """Combined text shown in the left raw pane for multi-source CP sessions."""
    parts: list[str] = []
    if filenames:
        parts.append("# Check Point sources: " + ", ".join(filenames))
        parts.append("")
    if gaia_text:
        parts.append("# ===== GAiA show configuration (gateway) =====")
        parts.append(gaia_text.strip())
        parts.append("")
    if migrate_summary:
        parts.append("# ===== Management export summary =====")
        parts.append(migrate_summary.strip())
    return "\n".join(parts).strip() + "\n"
