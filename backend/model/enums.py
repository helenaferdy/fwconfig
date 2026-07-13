"""Shared enumerations for vendors, sections, and pipeline state."""

from __future__ import annotations

from enum import Enum

from model.taxonomy import LEAF_DISPLAY, LEAF_ORDER


class Vendor(str, Enum):
    FORTIGATE = "fortigate"
    PALO_ALTO = "palo"
    CHECKPOINT = "checkpoint"
    CISCO_FTD = "ftd"
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        return {
            Vendor.FORTIGATE: "Fortigate",
            Vendor.PALO_ALTO: "Palo Alto",
            Vendor.CHECKPOINT: "Check Point",
            Vendor.CISCO_FTD: "Cisco FTD",
            Vendor.UNKNOWN: "Unknown",
        }[self]


class SectionType(str, Enum):
    """Logical configuration sections.

    Values remain the legacy parser keys for compatibility. Taxonomy mapping
    (System / Network / Objects / …) is applied when building the UI tree.
    """

    INTERFACES = "interfaces"
    ADDRESSES = "addresses"
    ADDRESS_GROUPS = "address_groups"
    SERVICES = "services"
    SERVICE_GROUPS = "service_groups"
    FIREWALL_POLICIES = "firewall_policies"
    NAT = "nat"
    VIP = "vip"
    STATIC_ROUTES = "static_routes"
    BGP = "bgp"
    OSPF = "ospf"
    DHCP = "dhcp"
    DNS = "dns"
    SSL_VPN = "ssl_vpn"
    IPSEC = "ipsec"
    USERS = "users"
    GROUPS = "groups"
    SCHEDULES = "schedules"
    CERTIFICATES = "certificates"
    SYSTEM_SETTINGS = "system_settings"
    ZONES = "zones"
    APPLICATIONS = "applications"
    OTHER = "other"

    @property
    def display_name(self) -> str:
        return {
            SectionType.INTERFACES: "Interfaces",
            SectionType.ADDRESSES: "Addresses",
            SectionType.ADDRESS_GROUPS: "Address Groups",
            SectionType.SERVICES: "Services",
            SectionType.SERVICE_GROUPS: "Service Groups",
            SectionType.FIREWALL_POLICIES: "Security Policies",
            SectionType.NAT: "NAT",
            SectionType.VIP: "VIP",
            SectionType.STATIC_ROUTES: "Static",
            SectionType.BGP: "Dynamic",
            SectionType.OSPF: "Dynamic",
            SectionType.DHCP: "DHCP",
            SectionType.DNS: "Services",
            SectionType.SSL_VPN: "SSL VPN",
            SectionType.IPSEC: "IPsec",
            SectionType.USERS: "Users",
            SectionType.GROUPS: "Groups",
            SectionType.SCHEDULES: "Other",
            SectionType.CERTIFICATES: "Other",
            SectionType.SYSTEM_SETTINGS: "General",
            SectionType.ZONES: "Zones",
            SectionType.APPLICATIONS: "Profiles",
            SectionType.OTHER: "Unclassified",
        }[self]


# Canonical order for raw parser output (pre-taxonomy)
SECTION_ORDER: list[SectionType] = [
    SectionType.SYSTEM_SETTINGS,
    SectionType.INTERFACES,
    SectionType.ZONES,
    SectionType.DHCP,
    SectionType.ADDRESSES,
    SectionType.ADDRESS_GROUPS,
    SectionType.SERVICES,
    SectionType.SERVICE_GROUPS,
    SectionType.APPLICATIONS,
    SectionType.STATIC_ROUTES,
    SectionType.BGP,
    SectionType.OSPF,
    SectionType.FIREWALL_POLICIES,
    SectionType.NAT,
    SectionType.VIP,
    SectionType.IPSEC,
    SectionType.SSL_VPN,
    SectionType.USERS,
    SectionType.GROUPS,
    SectionType.SCHEDULES,
    SectionType.CERTIFICATES,
    SectionType.DNS,
    SectionType.OTHER,
]

# Taxonomy leaf order (post-categorization)
TAXONOMY_LEAF_ORDER: list[str] = list(LEAF_ORDER)
TAXONOMY_LEAF_DISPLAY: dict[str, str] = dict(LEAF_DISPLAY)


class PipelineStage(str, Enum):
    PENDING = "pending"
    READING = "reading"
    DETECTING_VENDOR = "detecting_vendor"
    PARSING = "parsing"
    RESOLVING_REFERENCES = "resolving_references"
    BUILDING_MODEL = "building_model"
    BUILDING_GRAPH = "building_graph"
    GENERATING = "generating"
    VALIDATING = "validating"
    DONE = "done"
    FAILED = "failed"


class WarningSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    DROP = "drop"
    RESET = "reset"


class AddressType(str, Enum):
    IP_HOST = "ip_host"
    IP_NETWORK = "ip_network"
    IP_RANGE = "ip_range"
    FQDN = "fqdn"
    GEOGRAPHY = "geography"
    WILDCARD = "wildcard"
    DYNAMIC = "dynamic"
    OTHER = "other"


class ServiceProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMP6 = "icmp6"
    SCTP = "sctp"
    IP = "ip"
    OTHER = "other"
