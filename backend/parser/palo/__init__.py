"""Palo Alto Networks PAN-OS configuration parser package."""

from __future__ import annotations

from model.enums import SectionType, Vendor
from parser.base import SectionParser, VendorParser, register_parser
from parser.common import StubSectionParser


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

    def build_section_parsers(self) -> list[SectionParser]:
        return [
            _stub(SectionType.INTERFACES, [r"set\s+network\s+interface", r"<interface>", r"ethernet\d+/\d+"]),
            _stub(SectionType.ZONES, [r"set\s+zone\s+", r"<zone>"]),
            _stub(SectionType.ADDRESSES, [r"set\s+address\s+", r"<address>"]),
            _stub(SectionType.ADDRESS_GROUPS, [r"set\s+address-group\s+", r"<address-group>"]),
            _stub(SectionType.SERVICES, [r"set\s+service\s+", r"<service>"]),
            _stub(SectionType.SERVICE_GROUPS, [r"set\s+service-group\s+", r"<service-group>"]),
            _stub(SectionType.APPLICATIONS, [r"set\s+application\s+", r"<application>"]),
            _stub(SectionType.FIREWALL_POLICIES, [r"set\s+rulebase\s+security", r"<security>", r"rules\s*\{"]),
            _stub(SectionType.NAT, [r"set\s+rulebase\s+nat", r"<nat>"]),
            _stub(SectionType.VIP, [r"destination-translation", r"static-ip"]),
            _stub(SectionType.STATIC_ROUTES, [r"set\s+network\s+virtual-router", r"<routing-table>"]),
            _stub(SectionType.BGP, [r"protocol\s+bgp", r"<bgp>"]),
            _stub(SectionType.OSPF, [r"protocol\s+ospf", r"<ospf>"]),
            _stub(SectionType.DHCP, [r"set\s+network\s+dhcp", r"<dhcp>"]),
            _stub(SectionType.DNS, [r"dns-setting", r"set\s+deviceconfig\s+system\s+dns-setting"]),
            _stub(SectionType.SSL_VPN, [r"global-protect", r"<global-protect>"]),
            _stub(SectionType.IPSEC, [r"set\s+network\s+tunnel\s+ipsec", r"<ipsec>"]),
            _stub(SectionType.USERS, [r"set\s+shared\s+local-user", r"<local-user>"]),
            _stub(SectionType.GROUPS, [r"set\s+shared\s+local-user-group", r"<user-group>"]),
            _stub(SectionType.SCHEDULES, [r"set\s+schedule\s+", r"<schedule>"]),
            _stub(SectionType.CERTIFICATES, [r"set\s+shared\s+certificate", r"<certificate>"]),
            _stub(SectionType.SYSTEM_SETTINGS, [r"set\s+deviceconfig\s+system", r"<deviceconfig>"]),
        ]
