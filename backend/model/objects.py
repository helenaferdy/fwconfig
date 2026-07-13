"""Vendor-neutral configuration objects.

Generators must only consume these types. Parsers are the only components
that know how to map vendor syntax into these objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .base import ModelObject, NamedReference
from .enums import AddressType, PolicyAction, ServiceProtocol


class Interface(ModelObject):
    interface_type: str = "physical"  # physical | vlan | loopback | tunnel | aggregate | other
    ip_addresses: list[str] = Field(default_factory=list)
    netmask: str | None = None
    vlan_id: int | None = None
    parent: str | None = None
    zone: str | None = None
    mtu: int | None = None
    enabled: bool = True
    secondary_ips: list[str] = Field(default_factory=list)


class Zone(ModelObject):
    interfaces: list[str] = Field(default_factory=list)
    zone_type: str = "layer3"


class Address(ModelObject):
    address_type: AddressType = AddressType.IP_HOST
    value: str  # IP, CIDR, FQDN, range, etc.
    start_ip: str | None = None
    end_ip: str | None = None
    interface: str | None = None


class AddressGroup(ModelObject):
    members: list[NamedReference] = Field(default_factory=list)
    exclude_members: list[NamedReference] = Field(default_factory=list)


class Service(ModelObject):
    protocol: ServiceProtocol = ServiceProtocol.TCP
    source_ports: list[str] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    icmp_type: int | None = None
    icmp_code: int | None = None
    protocol_number: int | None = None


class ServiceGroup(ModelObject):
    members: list[NamedReference] = Field(default_factory=list)


class Application(ModelObject):
    category: str | None = None
    risk: int | None = None
    ports: list[str] = Field(default_factory=list)


class Schedule(ModelObject):
    schedule_type: str = "recurring"  # recurring | one-time
    start: str | None = None
    end: str | None = None
    days: list[str] = Field(default_factory=list)


class FirewallPolicy(ModelObject):
    policy_id: str | None = None
    enabled: bool = True
    action: PolicyAction = PolicyAction.ALLOW
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    source_interfaces: list[str] = Field(default_factory=list)
    destination_interfaces: list[str] = Field(default_factory=list)
    source_addresses: list[NamedReference] = Field(default_factory=list)
    destination_addresses: list[NamedReference] = Field(default_factory=list)
    services: list[NamedReference] = Field(default_factory=list)
    applications: list[NamedReference] = Field(default_factory=list)
    users: list[NamedReference] = Field(default_factory=list)
    schedule: NamedReference | None = None
    log: bool = True
    nat_enabled: bool = False
    position: int | None = None
    comments: str | None = None


class NATRule(ModelObject):
    rule_id: str | None = None
    enabled: bool = True
    nat_type: str = "source"  # source | destination | static | bi-directional
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    source_addresses: list[NamedReference] = Field(default_factory=list)
    destination_addresses: list[NamedReference] = Field(default_factory=list)
    services: list[NamedReference] = Field(default_factory=list)
    translated_source: NamedReference | None = None
    translated_destination: NamedReference | None = None
    translated_service: NamedReference | None = None
    interface: str | None = None
    position: int | None = None


class VIP(ModelObject):
    external_ip: str
    mapped_ip: str
    external_port: str | None = None
    mapped_port: str | None = None
    protocol: ServiceProtocol | None = None
    interface: str | None = None
    source_filter: list[NamedReference] = Field(default_factory=list)


class StaticRoute(ModelObject):
    destination: str
    gateway: str | None = None
    interface: str | None = None
    metric: int | None = None
    distance: int | None = None
    enabled: bool = True
    blackhole: bool = False


class BGPNeighbor(ModelObject):
    remote_as: int
    neighbor_ip: str
    local_as: int | None = None
    description_text: str | None = None
    update_source: str | None = None
    enabled: bool = True


class OSPFProcess(ModelObject):
    process_id: int | str = 1
    router_id: str | None = None
    areas: list[dict[str, Any]] = Field(default_factory=list)
    networks: list[dict[str, Any]] = Field(default_factory=list)
    interfaces: list[dict[str, Any]] = Field(default_factory=list)


class DHCPServer(ModelObject):
    interface: str | None = None
    network: str | None = None
    gateway: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    lease_time: int | None = None
    range_start: str | None = None
    range_end: str | None = None
    enabled: bool = True


class DNSConfig(ModelObject):
    primary: str | None = None
    secondary: str | None = None
    servers: list[str] = Field(default_factory=list)
    domain: str | None = None
    forwarders: list[str] = Field(default_factory=list)


class IPSecTunnel(ModelObject):
    local_gateway: str | None = None
    remote_gateway: str | None = None
    local_proxy_ids: list[str] = Field(default_factory=list)
    remote_proxy_ids: list[str] = Field(default_factory=list)
    ike_version: str = "v2"
    phase1_proposal: dict[str, Any] = Field(default_factory=dict)
    phase2_proposal: dict[str, Any] = Field(default_factory=dict)
    psk_set: bool = False
    enabled: bool = True
    interface: str | None = None


class SSLVPN(ModelObject):
    portal_name: str | None = None
    listen_interface: str | None = None
    listen_port: int | None = None
    address_pool: NamedReference | None = None
    dns_servers: list[str] = Field(default_factory=list)
    split_tunnel: bool = True
    enabled: bool = True
    users: list[NamedReference] = Field(default_factory=list)
    groups: list[NamedReference] = Field(default_factory=list)


class User(ModelObject):
    user_type: str = "local"  # local | ldap | radius | saml
    email: str | None = None
    groups: list[NamedReference] = Field(default_factory=list)
    enabled: bool = True


class UserGroup(ModelObject):
    members: list[NamedReference] = Field(default_factory=list)
    group_type: str = "local"


class Certificate(ModelObject):
    cert_type: str = "local"  # local | ca | remote
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    fingerprint: str | None = None


class SystemConfig(ModelObject):
    hostname: str | None = None
    timezone: str | None = None
    ntp_servers: list[str] = Field(default_factory=list)
    admin_ports: list[int] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)


class ParsedSection(BaseModel):
    """A categorized slice of the source configuration for the explorer UI."""

    section_type: str  # taxonomy leaf id (e.g. network_interfaces)
    display_name: str
    category: str | None = None  # e.g. network
    category_display: str | None = None  # e.g. Network
    object_count: int = 0
    parsed_ok: bool = True
    objects: list[dict[str, Any]] = Field(default_factory=list)
    raw_snippets: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class GeneratedSection(BaseModel):
    """Human-readable summary for one logical section (middle pane).

    Historically named for generators; now holds deterministic narrative
    summaries rather than target vendor syntax.
    """

    section_type: str
    display_name: str
    category: str | None = None
    category_display: str | None = None
    content: str = ""
    object_count: int = 0
    success: bool = True
    errors: list[str] = Field(default_factory=list)


# Semantic alias
SummarySection = GeneratedSection


class CommonModel(BaseModel):
    """Complete vendor-neutral representation of a firewall configuration."""

    source_vendor: str = "unknown"
    hostname: str | None = None

    interfaces: list[Interface] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    addresses: list[Address] = Field(default_factory=list)
    address_groups: list[AddressGroup] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    service_groups: list[ServiceGroup] = Field(default_factory=list)
    applications: list[Application] = Field(default_factory=list)
    policies: list[FirewallPolicy] = Field(default_factory=list)
    nat_rules: list[NATRule] = Field(default_factory=list)
    vips: list[VIP] = Field(default_factory=list)
    static_routes: list[StaticRoute] = Field(default_factory=list)
    bgp_neighbors: list[BGPNeighbor] = Field(default_factory=list)
    ospf_processes: list[OSPFProcess] = Field(default_factory=list)
    dhcp_servers: list[DHCPServer] = Field(default_factory=list)
    dns_configs: list[DNSConfig] = Field(default_factory=list)
    ipsec_tunnels: list[IPSecTunnel] = Field(default_factory=list)
    ssl_vpns: list[SSLVPN] = Field(default_factory=list)
    users: list[User] = Field(default_factory=list)
    groups: list[UserGroup] = Field(default_factory=list)
    schedules: list[Schedule] = Field(default_factory=list)
    certificates: list[Certificate] = Field(default_factory=list)
    system: SystemConfig | None = None

    # Catch-all for objects that don't map cleanly yet
    unmapped: list[dict[str, Any]] = Field(default_factory=list)

    def section_counts(self) -> dict[str, int]:
        return {
            "interfaces": len(self.interfaces),
            "zones": len(self.zones),
            "addresses": len(self.addresses),
            "address_groups": len(self.address_groups),
            "services": len(self.services),
            "service_groups": len(self.service_groups),
            "applications": len(self.applications),
            "firewall_policies": len(self.policies),
            "nat": len(self.nat_rules),
            "vip": len(self.vips),
            "static_routes": len(self.static_routes),
            "bgp": len(self.bgp_neighbors),
            "ospf": len(self.ospf_processes),
            "dhcp": len(self.dhcp_servers),
            "dns": len(self.dns_configs),
            "ipsec": len(self.ipsec_tunnels),
            "ssl_vpn": len(self.ssl_vpns),
            "users": len(self.users),
            "groups": len(self.groups),
            "schedules": len(self.schedules),
            "certificates": len(self.certificates),
            "system_settings": 1 if self.system else 0,
        }

    def total_objects(self) -> int:
        return sum(self.section_counts().values())
