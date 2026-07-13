"""Check Point configuration parser package."""

from __future__ import annotations

from model.enums import SectionType, Vendor
from parser.base import SectionParser, VendorParser, register_parser
from parser.common import StubSectionParser


def _stub(section: SectionType, patterns: list[str]) -> SectionParser:
    class _P(StubSectionParser):
        section_type = section
        search_patterns = patterns

    return _P()


@register_parser(Vendor.CHECKPOINT)
class CheckPointParser(VendorParser):
    vendor = Vendor.CHECKPOINT
    fingerprints = [
        r"set\s+interface\s+",
        r"add\s+access-rule",
        r"add\s+host\s+name",
        r"add\s+network\s+name",
        r"set\s+package\s+",
        r"cpconfig",
        r"##Check Point",
        r"add\s+service-tcp",
        r"mgmt_cli",
        r"uid\s*:\s*\"[0-9a-f-]{36}\"",
    ]

    def build_section_parsers(self) -> list[SectionParser]:
        return [
            _stub(SectionType.INTERFACES, [r"set\s+interface\s+", r"add\s+interface\s+"]),
            _stub(SectionType.ADDRESSES, [r"add\s+host\s+name", r"add\s+network\s+name", r"add\s+address-range"]),
            _stub(SectionType.ADDRESS_GROUPS, [r"add\s+group\s+name", r"set\s+group\s+"]),
            _stub(SectionType.SERVICES, [r"add\s+service-tcp", r"add\s+service-udp", r"add\s+service-icmp"]),
            _stub(SectionType.SERVICE_GROUPS, [r"add\s+service-group"]),
            _stub(SectionType.FIREWALL_POLICIES, [r"add\s+access-rule", r"set\s+access-rule"]),
            _stub(SectionType.NAT, [r"add\s+nat-rule", r"set\s+nat-rule"]),
            _stub(SectionType.VIP, [r"add\s+static-nat"]),
            _stub(SectionType.STATIC_ROUTES, [r"set\s+static-route", r"add\s+static-route"]),
            _stub(SectionType.BGP, [r"set\s+bgp", r"add\s+bgp"]),
            _stub(SectionType.OSPF, [r"set\s+ospf", r"add\s+ospf"]),
            _stub(SectionType.DHCP, [r"set\s+dhcp"]),
            _stub(SectionType.DNS, [r"set\s+dns"]),
            _stub(SectionType.SSL_VPN, [r"mobile-access", r"set\s+vpn\s+community"]),
            _stub(SectionType.IPSEC, [r"vpn\s+community", r"add\s+vpn-community"]),
            _stub(SectionType.USERS, [r"add\s+user\s+name", r"set\s+user\s+"]),
            _stub(SectionType.GROUPS, [r"add\s+user-group"]),
            _stub(SectionType.SCHEDULES, [r"add\s+time\s+", r"add\s+time-group"]),
            _stub(SectionType.CERTIFICATES, [r"certificate"]),
            _stub(SectionType.SYSTEM_SETTINGS, [r"set\s+hostname", r"set\s+ntp"]),
        ]
