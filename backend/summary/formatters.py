"""Deterministic human-readable section formatters.

No AI. Each formatter turns CommonModel objects into concise engineering
summaries for migration review.
"""

from __future__ import annotations

from typing import Any, Callable

from model.objects import CommonModel, GeneratedSection
from model.taxonomy import (
    CATEGORY_DISPLAY,
    CATEGORY_OF_LEAF,
    LEAF_DISPLAY,
    LEAF_ORDER,
)


def _refs(items: list[Any], attr: str = "name") -> str:
    if not items:
        return "—"
    names = []
    for it in items:
        if isinstance(it, str):
            names.append(it)
        else:
            names.append(getattr(it, attr, None) or getattr(it, "name", str(it)))
    return ", ".join(names) if names else "—"


def _bullets(lines: list[str], indent: str = "  ") -> str:
    return "\n".join(f"{indent}• {ln}" for ln in lines if ln)


def format_interfaces(model: CommonModel) -> str:
    items = model.interfaces
    if not items:
        return "No interfaces detected."
    parts = [f"{len(items)} interface{'s' if len(items) != 1 else ''} detected.\n"]
    for iface in items:
        role = iface.zone or iface.interface_type or "—"
        ip = ", ".join(iface.ip_addresses) if iface.ip_addresses else "Not set"
        if iface.netmask and iface.ip_addresses:
            ip = f"{iface.ip_addresses[0]}/{iface.netmask}" if len(iface.ip_addresses) == 1 else ip
        status = "Up" if iface.enabled else "Down"
        lines = [
            f"Role / Type: {role}",
            f"IP: {ip}",
            f"Administrative Status: {status}",
        ]
        if iface.vlan_id is not None:
            lines.append(f"VLAN ID: {iface.vlan_id}")
        if iface.parent:
            lines.append(f"Parent: {iface.parent}")
        if iface.mtu:
            lines.append(f"MTU: {iface.mtu}")
        if iface.description:
            lines.append(f"Description: {iface.description}")
        # management access from metadata if present
        allow = iface.metadata.get("allowaccess") or iface.metadata.get("management_access")
        if allow:
            if isinstance(allow, list):
                lines.append("Management Access:")
                for a in allow:
                    lines.append(f"  - {a}")
            else:
                lines.append(f"Management Access: {allow}")
        if iface.metadata.get("alias"):
            lines.insert(1, f"Alias: {iface.metadata['alias']}")
        parts.append(f"{iface.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_zones(model: CommonModel) -> str:
    items = model.zones
    if not items:
        return "No zones detected."
    parts = [f"{len(items)} zone{'s' if len(items) != 1 else ''} detected.\n"]
    for z in items:
        lines = [
            f"Type: {z.zone_type}",
            f"Interfaces: {_refs(z.interfaces) if z.interfaces else '—'}",
        ]
        parts.append(f"{z.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_addresses(model: CommonModel) -> str:
    items = model.addresses
    if not items:
        return "No address objects detected."
    parts = [f"{len(items)} address object{'s' if len(items) != 1 else ''}.\n"]
    for a in items:
        lines = [
            f"Type: {a.address_type.value if hasattr(a.address_type, 'value') else a.address_type}",
            f"Value: {a.value}",
        ]
        if a.start_ip and a.end_ip:
            lines.append(f"Range: {a.start_ip} – {a.end_ip}")
        if a.interface:
            lines.append(f"Bound Interface: {a.interface}")
        if a.description:
            lines.append(f"Description: {a.description}")
        parts.append(f"{a.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_address_groups(model: CommonModel) -> str:
    items = model.address_groups
    if not items:
        return "No address groups detected."
    parts = [f"{len(items)} address group{'s' if len(items) != 1 else ''}.\n"]
    for g in items:
        members = _refs(g.members)
        lines = [f"Members ({len(g.members)}): {members}"]
        if g.exclude_members:
            lines.append(f"Excludes: {_refs(g.exclude_members)}")
        if g.description:
            lines.append(f"Description: {g.description}")
        parts.append(f"{g.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_services(model: CommonModel) -> str:
    items = model.services
    if not items:
        return "No services detected."
    parts = [f"{len(items)} service object{'s' if len(items) != 1 else ''}.\n"]
    for s in items:
        proto = s.protocol.value if hasattr(s.protocol, "value") else s.protocol
        ports = ", ".join(s.destination_ports) if s.destination_ports else "—"
        lines = [
            f"Protocol: {proto.upper() if isinstance(proto, str) else proto}",
            f"Destination Ports: {ports}",
        ]
        if s.source_ports:
            lines.append(f"Source Ports: {', '.join(s.source_ports)}")
        if s.icmp_type is not None:
            lines.append(f"ICMP Type: {s.icmp_type}")
        parts.append(f"{s.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_service_groups(model: CommonModel) -> str:
    items = model.service_groups
    if not items:
        return "No service groups detected."
    parts = [f"{len(items)} service group{'s' if len(items) != 1 else ''}.\n"]
    for g in items:
        lines = [f"Members ({len(g.members)}): {_refs(g.members)}"]
        parts.append(f"{g.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_applications(model: CommonModel) -> str:
    items = model.applications
    if not items:
        return "No application objects detected."
    parts = [f"{len(items)} application{'s' if len(items) != 1 else ''}.\n"]
    for a in items:
        lines = []
        if a.category:
            lines.append(f"Category: {a.category}")
        if a.risk is not None:
            lines.append(f"Risk: {a.risk}")
        if a.ports:
            lines.append(f"Ports: {', '.join(a.ports)}")
        parts.append(f"{a.name}\n{_bullets(lines) if lines else '  • (no details)'}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_policies(model: CommonModel) -> str:
    items = model.policies
    if not items:
        return "No firewall policies detected."
    parts = [f"{len(items)} firewall polic{'ies' if len(items) != 1 else 'y'} detected.\n"]
    for p in items:
        pid = p.policy_id or "—"
        action = p.action.value if hasattr(p.action, "value") else p.action
        src_z = ", ".join(p.source_zones or p.source_interfaces) or "any"
        dst_z = ", ".join(p.destination_zones or p.destination_interfaces) or "any"
        narrative = f"Traffic from {src_z} to {dst_z}"
        lines = [
            f"Policy ID: {pid}",
            f"Enabled: {'Yes' if p.enabled else 'No'}",
            narrative,
            f"Source: {_refs(p.source_addresses)}",
            f"Destination: {_refs(p.destination_addresses)}",
            f"Services: {_refs(p.services)}",
            f"Action: {str(action).title()}",
            f"NAT: {'Enabled' if p.nat_enabled else 'Disabled'}",
            f"Logging: {'Enabled' if p.log else 'Disabled'}",
        ]
        if p.schedule:
            lines.append(f"Schedule: {p.schedule.name}")
        # Security profiles / UTM bindings (av-profile, ips-sensor, …)
        meta = p.metadata or {}
        profiles = meta.get("profiles") if isinstance(meta.get("profiles"), dict) else None
        if profiles:
            for label, val in profiles.items():
                if val:
                    lines.append(f"{label}: {val}")
        else:
            for key in (
                "AV Profile",
                "IPS Sensor",
                "Web Filter",
                "DNS Filter",
                "Application Control",
                "SSL/SSH Profile",
            ):
                if meta.get(key):
                    lines.append(f"{key}: {meta[key]}")
        if p.comments or p.description:
            lines.append(f"Comment: {p.comments or p.description}")
        parts.append(f"Policy {pid} — {p.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_nat(model: CommonModel) -> str:
    items = model.nat_rules
    if not items:
        return "No NAT rules detected."
    parts = [f"{len(items)} NAT rule{'s' if len(items) != 1 else ''} detected.\n"]
    for n in items:
        lines = [
            f"Type: {n.nat_type}",
            f"Enabled: {'Yes' if n.enabled else 'No'}",
            f"Source: {_refs(n.source_addresses)}",
            f"Destination: {_refs(n.destination_addresses)}",
            f"Services: {_refs(n.services)}",
        ]
        if n.translated_source:
            lines.append(f"Translated Source: {n.translated_source.name}")
        if n.translated_destination:
            lines.append(f"Translated Destination: {n.translated_destination.name}")
        if n.interface:
            lines.append(f"Interface: {n.interface}")
        parts.append(f"{n.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_vip(model: CommonModel) -> str:
    items = model.vips
    if not items:
        return "No VIP / DNAT objects detected."
    parts = [f"{len(items)} VIP object{'s' if len(items) != 1 else ''}.\n"]
    for v in items:
        lines = [
            f"External IP: {v.external_ip}",
            f"Mapped IP: {v.mapped_ip}",
        ]
        if v.external_port or v.mapped_port:
            lines.append(f"Ports: {v.external_port or '*'} → {v.mapped_port or '*'}")
        if v.interface:
            lines.append(f"Interface: {v.interface}")
        parts.append(f"{v.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_routes(model: CommonModel) -> str:
    items = model.static_routes
    if not items:
        return "No static routes detected."
    parts = [f"{len(items)} static route{'s' if len(items) != 1 else ''} configured.\n"]
    for r in items:
        title = "Default Route" if r.destination in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "default") else r.name
        lines = [
            f"Destination: {r.destination}",
            f"Gateway: {r.gateway or '—'}",
            f"Interface: {r.interface or '—'}",
            f"Enabled: {'Yes' if r.enabled else 'No'}",
        ]
        if r.metric is not None:
            lines.append(f"Metric: {r.metric}")
        if r.distance is not None:
            lines.append(f"Distance: {r.distance}")
        if r.blackhole:
            lines.append("Blackhole: Yes")
        parts.append(f"{title}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_bgp(model: CommonModel) -> str:
    items = model.bgp_neighbors
    if not items:
        return "No BGP neighbors detected."
    parts = [f"{len(items)} BGP neighbor{'s' if len(items) != 1 else ''}.\n"]
    for n in items:
        lines = [
            f"Neighbor IP: {n.neighbor_ip}",
            f"Remote AS: {n.remote_as}",
            f"Local AS: {n.local_as or '—'}",
            f"Enabled: {'Yes' if n.enabled else 'No'}",
        ]
        if n.update_source:
            lines.append(f"Update Source: {n.update_source}")
        parts.append(f"{n.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_ospf(model: CommonModel) -> str:
    items = model.ospf_processes
    if not items:
        return "No OSPF processes detected."
    parts = [f"{len(items)} OSPF process{'es' if len(items) != 1 else ''}.\n"]
    for o in items:
        lines = [
            f"Process ID: {o.process_id}",
            f"Router ID: {o.router_id or '—'}",
            f"Areas: {len(o.areas)}",
            f"Networks: {len(o.networks)}",
        ]
        parts.append(f"{o.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_dhcp(model: CommonModel) -> str:
    items = model.dhcp_servers
    if not items:
        return "No DHCP servers detected."
    parts = [f"{len(items)} DHCP server{'s' if len(items) != 1 else ''}.\n"]
    for d in items:
        lines = [
            f"Interface: {d.interface or '—'}",
            f"Network: {d.network or '—'}",
            f"Gateway: {d.gateway or '—'}",
            f"Range: {d.range_start or '—'} – {d.range_end or '—'}",
            f"Enabled: {'Yes' if d.enabled else 'No'}",
        ]
        if d.dns_servers:
            lines.append(f"DNS: {', '.join(d.dns_servers)}")
        parts.append(f"{d.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_dns(model: CommonModel) -> str:
    items = model.dns_configs
    if not items:
        return "No DNS configuration detected."
    parts = [f"{len(items)} DNS configuration{'s' if len(items) != 1 else ''}.\n"]
    for d in items:
        servers = d.servers or ([d.primary] if d.primary else []) + ([d.secondary] if d.secondary else [])
        lines = [
            f"Servers: {', '.join(s for s in servers if s) or '—'}",
            f"Domain: {d.domain or '—'}",
        ]
        if d.forwarders:
            lines.append(f"Forwarders: {', '.join(d.forwarders)}")
        parts.append(f"{d.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_ssl_vpn(model: CommonModel) -> str:
    items = model.ssl_vpns
    if not items:
        return "No SSL VPN configuration detected."
    parts = [f"{len(items)} SSL VPN portal{'s' if len(items) != 1 else ''}.\n"]
    for v in items:
        lines = [
            f"Portal: {v.portal_name or v.name}",
            f"Listen: {v.listen_interface or '—'}{':' + str(v.listen_port) if v.listen_port else ''}",
            f"Split Tunnel: {'Yes' if v.split_tunnel else 'No'}",
            f"Enabled: {'Yes' if v.enabled else 'No'}",
        ]
        if v.address_pool:
            lines.append(f"Address Pool: {v.address_pool.name}")
        if v.dns_servers:
            lines.append(f"DNS: {', '.join(v.dns_servers)}")
        parts.append(f"{v.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_ipsec(model: CommonModel) -> str:
    items = model.ipsec_tunnels
    if not items:
        return "No IPSec tunnels detected."
    parts = [f"{len(items)} IPSec tunnel{'s' if len(items) != 1 else ''}.\n"]
    for t in items:
        lines = [
            f"Local Gateway: {t.local_gateway or '—'}",
            f"Remote Gateway: {t.remote_gateway or '—'}",
            f"IKE: {t.ike_version}",
            f"Interface: {t.interface or '—'}",
            f"PSK Configured: {'Yes' if t.psk_set else 'No / Unknown'}",
            f"Enabled: {'Yes' if t.enabled else 'No'}",
        ]
        if t.local_proxy_ids:
            lines.append(f"Local Proxy IDs: {', '.join(t.local_proxy_ids)}")
        if t.remote_proxy_ids:
            lines.append(f"Remote Proxy IDs: {', '.join(t.remote_proxy_ids)}")
        parts.append(f"{t.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_users(model: CommonModel) -> str:
    items = model.users
    if not items:
        return "No users detected."
    parts = [f"{len(items)} user{'s' if len(items) != 1 else ''}.\n"]
    for u in items:
        lines = [
            f"Type: {u.user_type}",
            f"Enabled: {'Yes' if u.enabled else 'No'}",
        ]
        if u.email:
            lines.append(f"Email: {u.email}")
        if u.groups:
            lines.append(f"Groups: {_refs(u.groups)}")
        parts.append(f"{u.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_groups(model: CommonModel) -> str:
    items = model.groups
    if not items:
        return "No user groups detected."
    parts = [f"{len(items)} group{'s' if len(items) != 1 else ''}.\n"]
    for g in items:
        lines = [
            f"Type: {g.group_type}",
            f"Members ({len(g.members)}): {_refs(g.members)}",
        ]
        parts.append(f"{g.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_schedules(model: CommonModel) -> str:
    items = model.schedules
    if not items:
        return "No schedules detected."
    parts = [f"{len(items)} schedule{'s' if len(items) != 1 else ''}.\n"]
    for s in items:
        lines = [
            f"Type: {s.schedule_type}",
            f"Start: {s.start or '—'}",
            f"End: {s.end or '—'}",
        ]
        if s.days:
            lines.append(f"Days: {', '.join(s.days)}")
        parts.append(f"{s.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_certificates(model: CommonModel) -> str:
    items = model.certificates
    if not items:
        return "No certificates detected."
    parts = [f"{len(items)} certificate{'s' if len(items) != 1 else ''}.\n"]
    for c in items:
        lines = [
            f"Type: {c.cert_type}",
            f"Subject: {c.subject or '—'}",
            f"Issuer: {c.issuer or '—'}",
        ]
        if c.not_after:
            lines.append(f"Expires: {c.not_after}")
        parts.append(f"{c.name}\n{_bullets(lines)}\n")
    return "\n".join(parts).rstrip() + "\n"


def format_system(model: CommonModel) -> str:
    sys = model.system
    if not sys and not model.hostname:
        return "No system settings detected."
    name = (sys.name if sys else None) or "System"
    lines = []
    hostname = (sys.hostname if sys else None) or model.hostname
    if hostname:
        lines.append(f"Hostname: {hostname}")
    if sys:
        if sys.timezone:
            lines.append(f"Timezone: {sys.timezone}")
        if sys.ntp_servers:
            lines.append(f"NTP: {', '.join(sys.ntp_servers)}")
        if sys.admin_ports:
            lines.append(f"Admin Ports: {', '.join(str(p) for p in sys.admin_ports)}")
        for k, v in (sys.settings or {}).items():
            lines.append(f"{k}: {v}")
    return f"System settings\n\n{name}\n{_bullets(lines) if lines else '  • (minimal data)'}\n"


def format_other(model: CommonModel) -> str:
    if not model.unmapped:
        return "No additional unmapped objects."
    parts = [f"{len(model.unmapped)} unmapped element{'s' if len(model.unmapped) != 1 else ''}.\n"]
    for u in model.unmapped[:50]:
        name = u.get("name") or u.get("type") or "item"
        parts.append(f"{name}\n{_bullets([f'{k}: {v}' for k, v in list(u.items())[:8]])}\n")
    return "\n".join(parts).rstrip() + "\n"


def _join_blocks(*blocks: str) -> str:
    parts = [b.strip() for b in blocks if b and b.strip() and not b.strip().startswith("No ")]
    if not parts:
        return blocks[0] if blocks else ""
    return "\n\n".join(parts) + "\n"


def format_routing_dynamic(model: CommonModel) -> str:
    return _join_blocks(format_bgp(model), format_ospf(model)) or "No dynamic routing detected."


def format_policies_nat(model: CommonModel) -> str:
    return _join_blocks(format_nat(model), format_vip(model)) or "No NAT rules detected."


def format_objects_other(model: CommonModel) -> str:
    return _join_blocks(format_schedules(model), format_certificates(model)) or "No additional objects."


def format_system_services(model: CommonModel) -> str:
    return format_dns(model)


def format_empty(msg: str) -> Callable[[CommonModel], str]:
    def _f(_model: CommonModel) -> str:
        return msg

    return _f


# Taxonomy leaf → formatter
LEAF_FORMATTERS: dict[str, Callable[[CommonModel], str]] = {
    "system_general": format_system,
    "system_management": format_empty("No management settings extracted."),
    "system_services": format_system_services,
    "system_other": format_empty("No additional system items."),
    "network_interfaces": format_interfaces,
    "network_zones": format_zones,
    "network_dhcp": format_dhcp,
    "network_other": format_empty("No additional network items."),
    "objects_addresses": format_addresses,
    "objects_address_groups": format_address_groups,
    "objects_services": format_services,
    "objects_service_groups": format_service_groups,
    "objects_other": format_objects_other,
    "routing_static": format_routes,
    "routing_dynamic": format_routing_dynamic,
    "routing_policy": format_empty("No policy-based routing detected."),
    "routing_other": format_empty("No additional routing items."),
    "policies_security": format_policies,
    "policies_nat": format_policies_nat,
    "policies_auth": format_empty("No authentication policies detected."),
    "policies_other": format_empty("No additional policy items."),
    "vpn_ipsec": format_ipsec,
    "vpn_ssl": format_ssl_vpn,
    "vpn_other": format_empty("No additional VPN items."),
    "security_profiles": format_applications,
    "security_inspection": format_empty("No inspection profiles detected."),
    "security_other": format_empty("No additional security items."),
    "users_users": format_users,
    "users_groups": format_groups,
    "users_external_auth": format_empty("No external authentication servers detected."),
    "users_other": format_empty("No additional user items."),
    "diagnostics_logging": format_empty("No logging configuration extracted."),
    "diagnostics_monitoring": format_empty("No monitoring configuration extracted."),
    "diagnostics_ha": format_empty("No high-availability configuration extracted."),
    "diagnostics_other": format_empty("No additional diagnostics items."),
    "other_unclassified": format_other,
    "other_unsupported": format_empty("No unsupported features flagged."),
    "other_unknown": format_empty("No unknown items."),
}

LEAF_COUNTS: dict[str, Callable[[CommonModel], int]] = {
    "system_general": lambda m: 1 if m.system or m.hostname else 0,
    "system_management": lambda _m: 0,
    "system_services": lambda m: len(m.dns_configs),
    "system_other": lambda m: len(m.certificates),
    "network_interfaces": lambda m: len(m.interfaces),
    "network_zones": lambda m: len(m.zones),
    "network_dhcp": lambda m: len(m.dhcp_servers),
    "network_other": lambda _m: 0,
    "objects_addresses": lambda m: len(m.addresses),
    "objects_address_groups": lambda m: len(m.address_groups),
    "objects_services": lambda m: len(m.services),
    "objects_service_groups": lambda m: len(m.service_groups),
    "objects_other": lambda m: len(m.schedules),
    "routing_static": lambda m: len(m.static_routes),
    "routing_dynamic": lambda m: len(m.bgp_neighbors) + len(m.ospf_processes),
    "routing_policy": lambda _m: 0,
    "routing_other": lambda _m: 0,
    "policies_security": lambda m: len(m.policies),
    "policies_nat": lambda m: len(m.nat_rules) + len(m.vips),
    "policies_auth": lambda _m: 0,
    "policies_other": lambda _m: 0,
    "vpn_ipsec": lambda m: len(m.ipsec_tunnels),
    "vpn_ssl": lambda m: len(m.ssl_vpns),
    "vpn_other": lambda _m: 0,
    "security_profiles": lambda m: len(m.applications),
    "security_inspection": lambda _m: 0,
    "security_other": lambda _m: 0,
    "users_users": lambda m: len(m.users),
    "users_groups": lambda m: len(m.groups),
    "users_external_auth": lambda _m: 0,
    "users_other": lambda _m: 0,
    "diagnostics_logging": lambda _m: 0,
    "diagnostics_monitoring": lambda _m: 0,
    "diagnostics_ha": lambda _m: 0,
    "diagnostics_other": lambda _m: 0,
    "other_unclassified": lambda m: len(m.unmapped),
    "other_unsupported": lambda _m: 0,
    "other_unknown": lambda _m: 0,
}


def build_summary_sections(model: CommonModel) -> list[GeneratedSection]:
    """Build human-readable summary sections keyed by taxonomy leaf."""
    sections: list[GeneratedSection] = []
    for leaf in LEAF_ORDER:
        formatter = LEAF_FORMATTERS.get(leaf, format_empty("No data."))
        count = LEAF_COUNTS.get(leaf, lambda _m: 0)(model)
        content = formatter(model)
        cat = CATEGORY_OF_LEAF.get(leaf, "other")
        sections.append(
            GeneratedSection(
                section_type=leaf,
                display_name=LEAF_DISPLAY.get(leaf, leaf),
                category=cat,
                category_display=CATEGORY_DISPLAY.get(cat, "Other"),
                content=content,
                object_count=count,
                success=True,
            )
        )
    return sections


def build_full_summary_document(model: CommonModel, sections: list[GeneratedSection] | None = None) -> str:
    sections = sections or build_summary_sections(model)
    parts = [
        "# Configuration Analysis Summary",
        f"# Source vendor: {model.source_vendor}",
        f"# Hostname: {model.hostname or 'unknown'}",
        f"# Total objects: {model.total_objects()}",
        "",
    ]
    current_cat = None
    for s in sections:
        if s.object_count == 0:
            continue
        if s.category_display and s.category_display != current_cat:
            current_cat = s.category_display
            parts.append(f"# {current_cat}")
            parts.append("")
        parts.append(f"## {s.display_name}")
        parts.append("")
        parts.append(s.content.rstrip())
        parts.append("")
    return "\n".join(parts)
