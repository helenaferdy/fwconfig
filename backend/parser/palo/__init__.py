"""Palo Alto Networks PAN-OS configuration parser package.

Supports:
  - Full running-config XML (primary, comprehensive)
  - Legacy CLI/set fingerprints for auto-detection (XML path preferred)
"""

from __future__ import annotations

import logging
import re

from model.enums import SectionType, Vendor
from model.objects import CommonModel, ParsedSection
from parser.base import ParseResult, SectionParser, VendorParser, register_parser
from parser.common import StubSectionParser
from parser.palo.xml_export import is_palo_xml, parse_palo_xml

logger = logging.getLogger(__name__)


def _stub(section: SectionType, patterns: list[str]) -> SectionParser:
    class _P(StubSectionParser):
        section_type = section
        search_patterns = patterns

    return _P()


@register_parser(Vendor.PALO_ALTO)
class PaloAltoParser(VendorParser):
    vendor = Vendor.PALO_ALTO
    fingerprints = [
        r"<config\s+version=",
        r"urldb\s*=\s*[\"']paloaltonetworks[\"']",
        r"<devices\s*>",
        r"<deviceconfig\s*>",
        r"<vsys\s*>",
        r"<rulebase\s*>",
        r"<entry\s+name=.*</entry>",
        r"set\s+deviceconfig\s+system",
        r"set\s+rulebase\s+security",
        r"set\s+network\s+interface",
        r"set\s+address\s+",
        r"deviceconfig\s*\{",
        r"vsys\s*\{",
        r"#\s*PAN-OS",
        r"set\s+zone\s+",
    ]

    def detect_score(self, raw: str) -> float:
        if is_palo_xml(raw or ""):
            return 1.0
        return super().detect_score(raw or "")

    def build_section_parsers(self) -> list[SectionParser]:
        # Used only for non-XML CLI dumps; XML uses parse() override.
        return [
            _stub(
                SectionType.INTERFACES,
                [r"set\s+network\s+interface", r"<interface>", r"ethernet\d+/\d+"],
            ),
            _stub(SectionType.ZONES, [r"set\s+zone\s+", r"<zone>"]),
            _stub(SectionType.ADDRESSES, [r"set\s+address\s+", r"<address>"]),
            _stub(
                SectionType.ADDRESS_GROUPS,
                [r"set\s+address-group\s+", r"<address-group>"],
            ),
            _stub(SectionType.SERVICES, [r"set\s+service\s+", r"<service>"]),
            _stub(
                SectionType.SERVICE_GROUPS,
                [r"set\s+service-group\s+", r"<service-group>"],
            ),
            _stub(SectionType.APPLICATIONS, [r"set\s+application\s+", r"<application>"]),
            _stub(
                SectionType.FIREWALL_POLICIES,
                [r"set\s+rulebase\s+security", r"<security>", r"rules\s*\{"],
            ),
            _stub(SectionType.NAT, [r"set\s+rulebase\s+nat", r"<nat>"]),
            _stub(SectionType.VIP, [r"destination-translation", r"static-ip"]),
            _stub(
                SectionType.STATIC_ROUTES,
                [r"set\s+network\s+virtual-router", r"<routing-table>"],
            ),
            _stub(SectionType.BGP, [r"protocol\s+bgp", r"<bgp>"]),
            _stub(SectionType.OSPF, [r"protocol\s+ospf", r"<ospf>"]),
            _stub(SectionType.DHCP, [r"set\s+network\s+dhcp", r"<dhcp>"]),
            _stub(
                SectionType.DNS,
                [r"dns-setting", r"set\s+deviceconfig\s+system\s+dns-setting"],
            ),
            _stub(SectionType.SSL_VPN, [r"global-protect", r"<global-protect>"]),
            _stub(SectionType.IPSEC, [r"set\s+network\s+tunnel\s+ipsec", r"<ipsec>"]),
            _stub(SectionType.USERS, [r"set\s+shared\s+local-user", r"<local-user>", r"<mgt-config>"]),
            _stub(SectionType.GROUPS, [r"set\s+shared\s+local-user-group", r"<user-group>"]),
            _stub(SectionType.SCHEDULES, [r"set\s+schedule\s+", r"<schedule>"]),
            _stub(SectionType.CERTIFICATES, [r"set\s+shared\s+certificate", r"<certificate>"]),
            _stub(
                SectionType.SYSTEM_SETTINGS,
                [r"set\s+deviceconfig\s+system", r"<deviceconfig>"],
            ),
        ]

    def parse(self, raw: str) -> ParseResult:
        """Prefer comprehensive XML parse; fall back to stubs for set/CLI."""
        if is_palo_xml(raw or ""):
            model = CommonModel(source_vendor=self.vendor.value)
            try:
                sections, warnings = parse_palo_xml(raw, model)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Palo Alto XML parse failed")
                return ParseResult(
                    model=model,
                    sections=[],
                    vendor=self.vendor,
                    warnings=[
                        {
                            "code": "PALO_XML_FAIL",
                            "message": f"Palo Alto XML parse failed: {exc}",
                            "severity": "error",
                        }
                    ],
                )
            # Ensure taxonomy explorer shows empty known sections too
            from model.enums import SECTION_ORDER

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

        # Non-XML: stub section parsers (limited CLI support)
        return super().parse(raw)
