"""Cisco FTD / FMC configuration parser package."""

from __future__ import annotations

from model.enums import SectionType, Vendor
from parser.base import SectionParser, VendorParser, register_parser
from parser.common import StubSectionParser


def _stub(section: SectionType, patterns: list[str]) -> SectionParser:
    class _P(StubSectionParser):
        section_type = section
        search_patterns = patterns

    return _P()


@register_parser(Vendor.CISCO_FTD)
class CiscoFTDParser(VendorParser):
    vendor = Vendor.CISCO_FTD
    fingerprints = [
        r"Cisco\s+Firepower",
        r"access-list\s+\S+\s+extended",
        r"object\s+network\s+",
        r"object-group\s+network\s+",
        r"object\s+service\s+",
        r"nat\s+\(.*\)\s+",
        r"interface\s+GigabitEthernet",
        r"ftd\s*#",
        r"configure\s+manager",
        r"ASA\s+Version|FTD\s+Version",
    ]

    def build_section_parsers(self) -> list[SectionParser]:
        return [
            _stub(SectionType.INTERFACES, [r"^interface\s+\S+", r"nameif\s+", r"ip\s+address\s+"]),
            _stub(SectionType.ZONES, [r"security-zone", r"zone\s+"]),
            _stub(SectionType.ADDRESSES, [r"object\s+network\s+", r"object\s+network"]),
            _stub(SectionType.ADDRESS_GROUPS, [r"object-group\s+network\s+"]),
            _stub(SectionType.SERVICES, [r"object\s+service\s+", r"object-group\s+service\s+"]),
            _stub(SectionType.SERVICE_GROUPS, [r"object-group\s+service\s+"]),
            _stub(SectionType.FIREWALL_POLICIES, [r"access-list\s+\S+\s+extended", r"access-group\s+"]),
            _stub(SectionType.NAT, [r"nat\s+\(", r"object\s+network.*\nnat"]),
            _stub(SectionType.VIP, [r"static\s+\(", r"destination\s+static"]),
            _stub(SectionType.STATIC_ROUTES, [r"^route\s+\S+", r"ipv6\s+route"]),
            _stub(SectionType.BGP, [r"router\s+bgp\s+"]),
            _stub(SectionType.OSPF, [r"router\s+ospf\s+"]),
            _stub(SectionType.DHCP, [r"dhcpd\s+", r"dhcprelay"]),
            _stub(SectionType.DNS, [r"dns\s+domain-lookup", r"name-server"]),
            _stub(SectionType.SSL_VPN, [r"webvpn", r"anyconnect"]),
            _stub(SectionType.IPSEC, [r"crypto\s+ipsec", r"crypto\s+map", r"tunnel-group"]),
            _stub(SectionType.USERS, [r"username\s+\S+", r"aaa-server"]),
            _stub(SectionType.GROUPS, [r"group-policy\s+"]),
            _stub(SectionType.SCHEDULES, [r"time-range\s+"]),
            _stub(SectionType.CERTIFICATES, [r"crypto\s+ca\s+", r"ssl\s+trust-point"]),
            _stub(SectionType.SYSTEM_SETTINGS, [r"hostname\s+\S+", r"domain-name\s+"]),
        ]
