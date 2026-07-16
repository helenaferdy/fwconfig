"""Parse Palo Alto PAN-OS `running-config` XML into CommonModel + sections.

Comprehensive coverage for firewall analysis:
  system, interfaces, zones, addresses/groups, services/groups,
  security rules, NAT (incl. DNAT/VIP-style translations), static routes,
  DHCP, management users, and protocol stubs when configured.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any
from xml.dom import minidom

from model.enums import AddressType, PolicyAction, SectionType, ServiceProtocol, Vendor
from model.objects import (
    Address,
    AddressGroup,
    Application,
    CommonModel,
    DHCPServer,
    DNSConfig,
    FirewallPolicy,
    Interface,
    NamedReference,
    NATRule,
    ParsedSection,
    Service,
    ServiceGroup,
    StaticRoute,
    SystemConfig,
    User,
    VIP,
    Zone,
)

# Security profile containers in PAN-OS XML (custom profiles when present)
_SECURITY_PROFILE_PATHS: list[tuple[str, str]] = [
    ("virus", "Antivirus"),
    ("spyware", "Anti-Spyware"),
    ("vulnerability", "Vulnerability Protection"),
    ("url-filtering", "URL Filtering"),
    ("file-blocking", "File Blocking"),
    ("wildfire-analysis", "WildFire Analysis"),
    ("data-filtering", "Data Filtering"),
    ("dos-protection", "DoS Protection"),
    ("gtp", "GTP Protection"),
    ("sctp", "SCTP Protection"),
    ("mka", "MKA"),
]

logger = logging.getLogger(__name__)

_VENDOR = Vendor.PALO_ALTO.value


def is_palo_xml(raw: str | bytes) -> bool:
    if raw is None:
        return False
    if isinstance(raw, bytes):
        try:
            text = raw[:4000].decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return False
    else:
        text = raw[:4000]
    t = text.lstrip()
    if not t.startswith("<"):
        return False
    return bool(
        re.search(r"<config\b", t, re.I)
        and (
            re.search(r"urldb\s*=\s*[\"']paloaltonetworks[\"']", t, re.I)
            or re.search(r"<devices\b", t, re.I)
            or re.search(r"<deviceconfig\b", t, re.I)
            or re.search(r"<vsys\b", t, re.I)
            or re.search(r"version\s*=\s*[\"']\d+\.\d+", t)
        )
    )


def _local(tag: str | None) -> str:
    if not tag:
        return ""
    return tag.split("}")[-1]


def _txt(el: ET.Element | None, default: str | None = None) -> str | None:
    if el is None or el.text is None:
        return default
    t = el.text.strip()
    return t if t else default


def _child_text(parent: ET.Element | None, path: str, default: str | None = None) -> str | None:
    if parent is None:
        return default
    return _txt(parent.find(path), default)


def _members(parent: ET.Element | None, path: str = "./member") -> list[str]:
    if parent is None:
        return []
    out: list[str] = []
    for m in parent.findall(path):
        t = _txt(m)
        if t:
            out.append(t)
    return out


def _member_list(parent: ET.Element | None, *paths: str) -> list[str]:
    """Collect members from first matching path (e.g. from/member, source/member)."""
    if parent is None:
        return []
    for path in paths:
        node = parent.find(path) if "/" in path.rstrip("member") else parent.find(path)
        # paths like "from" → from/member; "source" → source/member
        if path.endswith("member"):
            vals = _members(parent, path if path.startswith(".") else f"./{path}")
        else:
            vals = _members(parent.find(path))
        if vals:
            return vals
    return []


def _xml_snippet(el: ET.Element | None) -> str:
    if el is None:
        return ""
    try:
        rough = ET.tostring(el, encoding="unicode")
        # compact pretty for readability without exploding size
        parsed = minidom.parseString(rough.encode("utf-8"))
        pretty = parsed.toprettyxml(indent="  ")
        # drop xml declaration
        lines = [ln for ln in pretty.splitlines() if ln.strip() and not ln.startswith("<?xml")]
        return "\n".join(lines)
    except Exception:  # noqa: BLE001
        return ET.tostring(el, encoding="unicode")


def _obj(
    oid: str,
    name: str,
    raw: str,
    props: dict[str, Any],
    preview: str | None = None,
) -> dict[str, Any]:
    clean = {k: v for k, v in props.items() if v not in (None, "", [], {})}
    return {
        "id": oid,
        "name": name,
        "raw": raw,
        "properties": clean,
        "preview": preview or name,
    }


def _map_action(raw: str | None) -> PolicyAction:
    a = (raw or "allow").strip().lower()
    if a in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
        return PolicyAction.DENY
    if a in ("allow", "permit"):
        return PolicyAction.ALLOW
    return PolicyAction.ALLOW


def _first_device(root: ET.Element) -> ET.Element | None:
    dev = root.find("./devices/entry")
    if dev is not None:
        return dev
    # Some exports root under config with direct network
    if root.find("./network") is not None or root.find("./deviceconfig") is not None:
        return root
    return None


def _iter_vsys(dev: ET.Element) -> list[ET.Element]:
    vsys_list = list(dev.findall("./vsys/entry"))
    if vsys_list:
        return vsys_list
    # single-vsys style
    if dev.find("./zone") is not None or dev.find("./rulebase") is not None:
        return [dev]
    return []


def parse_palo_xml(raw: str | bytes, model: CommonModel) -> tuple[list[ParsedSection], list[dict]]:
    """Parse full PAN-OS XML into model + explorer sections."""
    warnings: list[dict] = []
    sections: list[ParsedSection] = []

    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        warnings.append(
            {
                "code": "PALO_XML_PARSE",
                "message": f"Invalid Palo Alto XML: {exc}",
                "severity": "error",
            }
        )
        return sections, warnings

    if _local(root.tag) != "config" and root.find(".//devices") is None:
        warnings.append(
            {
                "code": "PALO_XML_ROOT",
                "message": f"Unexpected root element <{_local(root.tag)}>",
                "severity": "warning",
            }
        )

    dev = _first_device(root)
    if dev is None:
        warnings.append(
            {
                "code": "PALO_NO_DEVICE",
                "message": "No devices/entry found in Palo Alto configuration",
                "severity": "error",
            }
        )
        return sections, warnings

    device_name = dev.get("name") or "device"
    version = root.get("version") or root.get("detail-version")

    # ---------- system ----------
    sys_objs: list[dict[str, Any]] = []
    sys_el = dev.find("./deviceconfig/system")
    hostname = _child_text(sys_el, "./hostname")
    timezone = _child_text(sys_el, "./timezone")
    ip_address = _child_text(sys_el, "./ip-address")
    netmask = _child_text(sys_el, "./netmask")
    gateway = _child_text(sys_el, "./default-gateway")
    dns_primary = _child_text(sys_el, "./dns-setting/servers/primary")
    dns_secondary = _child_text(sys_el, "./dns-setting/servers/secondary")
    if not dns_primary:
        dns_primary = _child_text(sys_el, "./dns-setting/primary")

    model.hostname = hostname or model.hostname
    model.system = SystemConfig(
        name="system",
        hostname=hostname,
        timezone=timezone,
        settings={
            k: v
            for k, v in {
                "device": device_name,
                "version": version,
                "ip-address": ip_address,
                "netmask": netmask,
                "default-gateway": gateway,
            }.items()
            if v
        },
        source_vendor=_VENDOR,
        source_raw=_xml_snippet(sys_el) if sys_el is not None else "",
    )
    sys_objs.append(
        _obj(
            "palo-system",
            "system",
            _xml_snippet(sys_el) if sys_el is not None else "",
            {
                "Hostname": hostname,
                "Timezone": timezone,
                "Management IP": ip_address,
                "Netmask": netmask,
                "Default Gateway": gateway,
                "Device": device_name,
                "PAN-OS": version,
            },
            preview=hostname or device_name,
        )
    )
    sections.append(
        ParsedSection(
            section_type=SectionType.SYSTEM_SETTINGS.value,
            display_name=SectionType.SYSTEM_SETTINGS.display_name,
            object_count=len(sys_objs),
            parsed_ok=True,
            objects=sys_objs,
            raw_snippets=[sys_objs[0]["raw"]] if sys_objs and sys_objs[0].get("raw") else [],
        )
    )

    # DNS
    dns_servers = [s for s in (dns_primary, dns_secondary) if s]
    if dns_servers:
        dns = DNSConfig(
            name="dns",
            servers=dns_servers,
            source_vendor=_VENDOR,
            source_raw=_xml_snippet(sys_el.find("./dns-setting") if sys_el is not None else None),
        )
        model.dns_configs.append(dns)
        sections.append(
            ParsedSection(
                section_type=SectionType.DNS.value,
                display_name=SectionType.DNS.display_name,
                object_count=1,
                parsed_ok=True,
                objects=[
                    _obj(
                        dns.id,
                        "dns",
                        dns.source_raw or "",
                        {"Name": "dns", "Servers": dns_servers},
                        preview=", ".join(dns_servers),
                    )
                ],
                raw_snippets=[dns.source_raw] if dns.source_raw else [],
            )
        )

    # ---------- interfaces ----------
    iface_objs: list[dict[str, Any]] = []
    iface_root = dev.find("./network/interface")
    if iface_root is not None:
        for kind_el in list(iface_root):
            kind = _local(kind_el.tag)  # ethernet, loopback, vlan, tunnel, aggregate-ethernet
            for entry in kind_el.findall("./entry"):
                name = entry.get("name") or "iface"
                comment = _child_text(entry, "./comment")
                # layer3 / layer2 / virtual-wire / tap
                mode = None
                ips: list[str] = []
                for mode_name in ("layer3", "layer2", "virtual-wire", "tap", "ha"):
                    mode_el = entry.find(f"./{mode_name}")
                    if mode_el is not None:
                        mode = mode_name
                        for ip_e in mode_el.findall("./ip/entry"):
                            ipn = ip_e.get("name")
                            if ipn:
                                ips.append(ipn)
                        break
                # units (subinterfaces)
                units = entry.findall("./layer3/units/entry") or entry.findall(
                    "./units/entry"
                )
                raw_snip = _xml_snippet(entry)
                iface = Interface(
                    name=name,
                    interface_type=kind or "physical",
                    ip_addresses=ips,
                    enabled=True,
                    description=comment,
                    source_vendor=_VENDOR,
                    source_ref=name,
                    source_raw=raw_snip,
                    metadata={
                        "source": "palo_xml",
                        "mode": mode,
                        "device": device_name,
                    },
                )
                model.interfaces.append(iface)
                iface_objs.append(
                    _obj(
                        iface.id,
                        name,
                        raw_snip,
                        {
                            "Name": name,
                            "Type": kind,
                            "Mode": mode,
                            "IPv4": ips,
                            "Description": comment,
                        },
                        preview=", ".join(ips) if ips else kind or name,
                    )
                )
                for unit in units:
                    uname = unit.get("name") or f"{name}.unit"
                    uips = [e.get("name") for e in unit.findall("./ip/entry") if e.get("name")]
                    uraw = _xml_snippet(unit)
                    uif = Interface(
                        name=uname,
                        interface_type="vlan" if "." in uname else kind or "physical",
                        ip_addresses=uips,
                        parent=name,
                        source_vendor=_VENDOR,
                        source_ref=uname,
                        source_raw=uraw,
                        metadata={"source": "palo_xml", "parent": name},
                    )
                    model.interfaces.append(uif)
                    iface_objs.append(
                        _obj(
                            uif.id,
                            uname,
                            uraw,
                            {
                                "Name": uname,
                                "Type": "subinterface",
                                "Parent": name,
                                "IPv4": uips,
                            },
                            preview=", ".join(uips) if uips else uname,
                        )
                    )

    if iface_objs:
        sections.append(
            ParsedSection(
                section_type=SectionType.INTERFACES.value,
                display_name=SectionType.INTERFACES.display_name,
                object_count=len(iface_objs),
                parsed_ok=True,
                objects=iface_objs,
                raw_snippets=[o["raw"] for o in iface_objs if o.get("raw")],
            )
        )

    # ---------- DHCP ----------
    dhcp_objs: list[dict[str, Any]] = []
    for entry in dev.findall("./network/dhcp/interface/entry"):
        ifname = entry.get("name") or "dhcp"
        server = entry.find("./server")
        pools = _members(server.find("./ip-pool") if server is not None else None)
        mode = _child_text(server, "./mode")
        raw_snip = _xml_snippet(entry)
        dhcp = DHCPServer(
            name=ifname,
            interface=ifname,
            network=pools[0] if pools else None,
            source_vendor=_VENDOR,
            source_raw=raw_snip,
            metadata={"pools": pools, "mode": mode, "source": "palo_xml"},
        )
        model.dhcp_servers.append(dhcp)
        dhcp_objs.append(
            _obj(
                dhcp.id,
                ifname,
                raw_snip,
                {
                    "Name": ifname,
                    "Interface": ifname,
                    "Pools": pools,
                    "Mode": mode,
                },
                preview=pools[0] if pools else ifname,
            )
        )
    if dhcp_objs:
        sections.append(
            ParsedSection(
                section_type=SectionType.DHCP.value,
                display_name=SectionType.DHCP.display_name,
                object_count=len(dhcp_objs),
                parsed_ok=True,
                objects=dhcp_objs,
                raw_snippets=[o["raw"] for o in dhcp_objs if o.get("raw")],
            )
        )

    # ---------- static routes (+ dynamic protocol presence) ----------
    route_objs: list[dict[str, Any]] = []
    dyn_objs: list[dict[str, Any]] = []
    for vr in dev.findall("./network/virtual-router/entry"):
        vr_name = vr.get("name") or "default"
        for entry in vr.findall("./routing-table/ip/static-route/entry"):
            rname = entry.get("name") or "route"
            dest = _child_text(entry, "./destination") or "0.0.0.0/0"
            nh = _child_text(entry, "./nexthop/ip-address") or _child_text(
                entry, "./nexthop/next-vr"
            )
            iface = _child_text(entry, "./interface")
            metric = _child_text(entry, "./metric")
            raw_snip = _xml_snippet(entry)
            route = StaticRoute(
                name=rname,
                destination=dest,
                gateway=nh,
                interface=iface,
                metric=int(metric) if metric and metric.isdigit() else None,
                source_vendor=_VENDOR,
                source_ref=rname,
                source_raw=raw_snip,
                metadata={"virtual_router": vr_name, "source": "palo_xml"},
            )
            model.static_routes.append(route)
            route_objs.append(
                _obj(
                    route.id,
                    rname,
                    raw_snip,
                    {
                        "Name": rname,
                        "Destination": dest,
                        "Gateway": nh,
                        "Interface": iface,
                        "Metric": metric,
                        "Virtual Router": vr_name,
                    },
                    preview=dest,
                )
            )
        # protocol enable flags / neighbors if any
        for proto_name in ("bgp", "ospf", "ospfv3", "rip"):
            proto = vr.find(f"./protocol/{proto_name}")
            if proto is None:
                continue
            enabled = (_child_text(proto, "./enable") or "").lower()
            peers = proto.findall(".//peer-group/entry") or proto.findall(
                "./peer-group/entry"
            )
            # Always surface configured protocol blocks for completeness
            raw_snip = _xml_snippet(proto)
            dyn_objs.append(
                _obj(
                    f"{vr_name}-{proto_name}",
                    f"{proto_name}@{vr_name}",
                    raw_snip,
                    {
                        "Name": f"{proto_name}@{vr_name}",
                        "Protocol": proto_name,
                        "Enabled": enabled or "n/a",
                        "Virtual Router": vr_name,
                        "Peer Groups": len(peers),
                    },
                    preview=f"{proto_name} enabled={enabled}",
                )
            )

    if route_objs:
        sections.append(
            ParsedSection(
                section_type=SectionType.STATIC_ROUTES.value,
                display_name=SectionType.STATIC_ROUTES.display_name,
                object_count=len(route_objs),
                parsed_ok=True,
                objects=route_objs,
                raw_snippets=[o["raw"] for o in route_objs if o.get("raw")],
            )
        )
    if dyn_objs:
        sections.append(
            ParsedSection(
                section_type=SectionType.BGP.value,
                display_name="Dynamic",
                object_count=len(dyn_objs),
                parsed_ok=True,
                objects=dyn_objs,
                raw_snippets=[o["raw"] for o in dyn_objs if o.get("raw")],
            )
        )

    # Aggregate objects across all vsys
    all_zone_objs: list[dict[str, Any]] = []
    all_addr_objs: list[dict[str, Any]] = []
    all_agrp_objs: list[dict[str, Any]] = []
    all_svc_objs: list[dict[str, Any]] = []
    all_sgrp_objs: list[dict[str, Any]] = []
    all_pol_objs: list[dict[str, Any]] = []
    all_nat_objs: list[dict[str, Any]] = []
    all_vip_objs: list[dict[str, Any]] = []

    for vsys in _iter_vsys(dev):
        vsys_name = vsys.get("name") or "vsys1"

        # Zones
        for entry in vsys.findall("./zone/entry"):
            zname = entry.get("name") or "zone"
            ifaces = _members(entry.find("./network/layer3"))
            if not ifaces:
                ifaces = _members(entry.find("./network/virtual-wire"))
            if not ifaces:
                ifaces = _members(entry.find("./network/tap"))
            raw_snip = _xml_snippet(entry)
            zone = Zone(
                name=zname,
                interfaces=ifaces,
                zone_type="layer3",
                source_vendor=_VENDOR,
                source_ref=zname,
                source_raw=raw_snip,
                metadata={"vsys": vsys_name, "source": "palo_xml"},
            )
            model.zones.append(zone)
            all_zone_objs.append(
                _obj(
                    zone.id,
                    zname,
                    raw_snip,
                    {
                        "Name": zname,
                        "Interfaces": ifaces,
                        "VSYS": vsys_name,
                    },
                    preview=", ".join(ifaces) if ifaces else zname,
                )
            )

        # Addresses
        for entry in vsys.findall("./address/entry"):
            aname = entry.get("name") or "address"
            ipn = _child_text(entry, "./ip-netmask")
            ipr = _child_text(entry, "./ip-range")
            fqdn = _child_text(entry, "./fqdn")
            desc = _child_text(entry, "./description")
            if fqdn:
                at, value = AddressType.FQDN, fqdn
                start_ip = end_ip = None
            elif ipr:
                at = AddressType.IP_RANGE
                value = ipr
                parts = ipr.split("-")
                start_ip = parts[0].strip() if parts else None
                end_ip = parts[1].strip() if len(parts) > 1 else None
            else:
                at = AddressType.IP_NETWORK
                value = ipn or aname
                start_ip = end_ip = None
            raw_snip = _xml_snippet(entry)
            addr = Address(
                name=aname,
                address_type=at,
                value=value,
                start_ip=start_ip,
                end_ip=end_ip,
                description=desc,
                source_vendor=_VENDOR,
                source_ref=aname,
                source_raw=raw_snip,
                metadata={"vsys": vsys_name, "source": "palo_xml"},
            )
            model.addresses.append(addr)
            all_addr_objs.append(
                _obj(
                    addr.id,
                    aname,
                    raw_snip,
                    {
                        "Name": aname,
                        "Type": at.value,
                        "Value": value,
                        "Description": desc,
                        "VSYS": vsys_name,
                    },
                    preview=value,
                )
            )

        # Address groups
        for entry in vsys.findall("./address-group/entry"):
            gname = entry.get("name") or "addr-group"
            static = _members(entry.find("./static"))
            desc = _child_text(entry, "./description")
            raw_snip = _xml_snippet(entry)
            grp = AddressGroup(
                name=gname,
                members=[NamedReference(name=m, kind="address") for m in static],
                description=desc,
                source_vendor=_VENDOR,
                source_ref=gname,
                source_raw=raw_snip,
                metadata={"vsys": vsys_name, "source": "palo_xml"},
            )
            model.address_groups.append(grp)
            all_agrp_objs.append(
                _obj(
                    grp.id,
                    gname,
                    raw_snip,
                    {
                        "Name": gname,
                        "Members": static,
                        "Description": desc,
                        "VSYS": vsys_name,
                    },
                    preview=f"{len(static)} members",
                )
            )

        # Services
        for entry in vsys.findall("./service/entry"):
            sname = entry.get("name") or "service"
            proto = ServiceProtocol.TCP
            ports: list[str] = []
            for ptag, penum in (
                ("tcp", ServiceProtocol.TCP),
                ("udp", ServiceProtocol.UDP),
                ("sctp", ServiceProtocol.SCTP),
            ):
                pel = entry.find(f"./protocol/{ptag}")
                if pel is not None:
                    proto = penum
                    port = _child_text(pel, "./port")
                    if port:
                        ports = [p.strip() for p in port.replace(",", " ").split() if p.strip()]
                    break
            raw_snip = _xml_snippet(entry)
            svc = Service(
                name=sname,
                protocol=proto,
                destination_ports=ports,
                source_vendor=_VENDOR,
                source_ref=sname,
                source_raw=raw_snip,
                metadata={"vsys": vsys_name, "source": "palo_xml"},
            )
            model.services.append(svc)
            all_svc_objs.append(
                _obj(
                    svc.id,
                    sname,
                    raw_snip,
                    {
                        "Name": sname,
                        "Protocol": proto.value,
                        "Ports": ports,
                        "VSYS": vsys_name,
                    },
                    preview=f"{proto.value}/{' '.join(ports)}" if ports else proto.value,
                )
            )

        # Service groups
        for entry in vsys.findall("./service-group/entry"):
            gname = entry.get("name") or "svc-group"
            members = _members(entry.find("./members"))
            raw_snip = _xml_snippet(entry)
            sg = ServiceGroup(
                name=gname,
                members=[NamedReference(name=m, kind="service") for m in members],
                source_vendor=_VENDOR,
                source_ref=gname,
                source_raw=raw_snip,
                metadata={"vsys": vsys_name, "source": "palo_xml"},
            )
            model.service_groups.append(sg)
            all_sgrp_objs.append(
                _obj(
                    sg.id,
                    gname,
                    raw_snip,
                    {"Name": gname, "Members": members, "VSYS": vsys_name},
                    preview=f"{len(members)} members",
                )
            )

        # Security rules
        for i, entry in enumerate(vsys.findall("./rulebase/security/rules/entry")):
            rname = entry.get("name") or f"rule_{i}"
            disabled = (entry.get("disabled") or "").lower() in ("yes", "true", "1")
            action_raw = _child_text(entry, "./action") or "allow"
            src_zones = _members(entry.find("./from"))
            dst_zones = _members(entry.find("./to"))
            src_addrs = _members(entry.find("./source"))
            dst_addrs = _members(entry.find("./destination"))
            services = _members(entry.find("./service"))
            apps = _members(entry.find("./application"))
            users = _members(entry.find("./source-user"))
            categories = _members(entry.find("./category"))
            desc = _child_text(entry, "./description")
            log_end = (_child_text(entry, "./log-end") or "").lower() in ("yes", "true")
            raw_snip = _xml_snippet(entry)
            pol = FirewallPolicy(
                name=rname,
                policy_id=entry.get("uuid") or rname,
                enabled=not disabled,
                action=_map_action(action_raw),
                source_zones=src_zones,
                destination_zones=dst_zones,
                source_addresses=[NamedReference(name=a, kind="address") for a in src_addrs],
                destination_addresses=[
                    NamedReference(name=a, kind="address") for a in dst_addrs
                ],
                services=[NamedReference(name=s, kind="service") for s in services],
                applications=[NamedReference(name=a, kind="application") for a in apps],
                users=[NamedReference(name=u, kind="user") for u in users],
                log=log_end,
                position=i,
                comments=desc,
                source_vendor=_VENDOR,
                source_ref=entry.get("uuid") or rname,
                source_raw=raw_snip,
                metadata={
                    "vsys": vsys_name,
                    "source": "palo_xml",
                    "categories": categories,
                    "uuid": entry.get("uuid"),
                },
            )
            model.policies.append(pol)
            all_pol_objs.append(
                _obj(
                    pol.id,
                    rname,
                    raw_snip,
                    {
                        "Name": rname,
                        "Action": action_raw,
                        "Enabled": not disabled,
                        "Source Zones": src_zones,
                        "Destination Zones": dst_zones,
                        "Source": src_addrs,
                        "Destination": dst_addrs,
                        "Services": services,
                        "Applications": apps,
                        "Users": users,
                        "Categories": categories,
                        "Log": log_end,
                        "Description": desc,
                        "VSYS": vsys_name,
                    },
                    preview=action_raw,
                )
            )

        # NAT rules (+ VIP-style destination translation)
        for i, entry in enumerate(vsys.findall("./rulebase/nat/rules/entry")):
            rname = entry.get("name") or f"nat_{i}"
            disabled = (entry.get("disabled") or "").lower() in ("yes", "true", "1")
            src_zones = _members(entry.find("./from"))
            dst_zones = _members(entry.find("./to"))
            src_addrs = _members(entry.find("./source"))
            dst_addrs = _members(entry.find("./destination"))
            service = _child_text(entry, "./service") or "any"
            to_if = _child_text(entry, "./to-interface")
            desc = _child_text(entry, "./description")
            dtr = entry.find("./destination-translation")
            strans = entry.find("./source-translation")
            t_dst = _child_text(dtr, "./translated-address") if dtr is not None else None
            t_port = _child_text(dtr, "./translated-port") if dtr is not None else None
            t_src = None
            nat_type = "source"
            if dtr is not None:
                nat_type = "destination"
            if strans is not None:
                # dynamic-ip-and-port / static-ip / dynamic-ip
                for child in list(strans):
                    t_src = _child_text(child, "./translated-address") or child.get(
                        "name"
                    )
                    if t_src:
                        break
                    # interface-address
                    t_src = _child_text(child, "./interface")
            raw_snip = _xml_snippet(entry)
            nat = NATRule(
                name=rname,
                rule_id=entry.get("uuid") or rname,
                nat_type=nat_type,
                enabled=not disabled,
                source_zones=src_zones,
                destination_zones=dst_zones,
                source_addresses=[NamedReference(name=a, kind="address") for a in src_addrs],
                destination_addresses=[
                    NamedReference(name=a, kind="address") for a in dst_addrs
                ],
                services=[NamedReference(name=service, kind="service")],
                translated_source=NamedReference(name=t_src, kind="address")
                if t_src
                else None,
                translated_destination=NamedReference(name=t_dst, kind="address")
                if t_dst
                else None,
                interface=to_if,
                position=i,
                source_vendor=_VENDOR,
                source_ref=entry.get("uuid") or rname,
                source_raw=raw_snip,
                metadata={
                    "vsys": vsys_name,
                    "source": "palo_xml",
                    "translated_port": t_port,
                    "description": desc,
                },
            )
            model.nat_rules.append(nat)
            all_nat_objs.append(
                _obj(
                    nat.id,
                    rname,
                    raw_snip,
                    {
                        "Name": rname,
                        "Method": nat_type,
                        "Enabled": not disabled,
                        "Source Zones": src_zones,
                        "Destination Zones": dst_zones,
                        "Source": src_addrs,
                        "Destination": dst_addrs,
                        "Service": service,
                        "Translated Source": t_src,
                        "Translated Destination": t_dst,
                        "Translated Port": t_port,
                        "Interface": to_if,
                        "Description": desc,
                        "VSYS": vsys_name,
                    },
                    preview=t_dst or t_src or nat_type,
                )
            )
            # Surface destination-translation as VIP-like object for mid-pane NAT leaf
            if t_dst and dst_addrs:
                vip = VIP(
                    name=rname,
                    external_ip=dst_addrs[0],
                    mapped_ip=t_dst,
                    external_port=None,
                    mapped_port=t_port,
                    interface=to_if,
                    source_vendor=_VENDOR,
                    source_ref=rname,
                    source_raw=raw_snip,
                    metadata={"vsys": vsys_name, "from_nat": True},
                )
                model.vips.append(vip)
                all_vip_objs.append(
                    _obj(
                        vip.id,
                        rname,
                        raw_snip,
                        {
                            "Name": rname,
                            "External": dst_addrs[0],
                            "Mapped": t_dst,
                            "Port": t_port,
                            "Interface": to_if,
                            "Type": "destination-translation",
                        },
                        preview=f"{dst_addrs[0]}→{t_dst}",
                    )
                )

    def _sec(st: SectionType | str, display: str, objs: list[dict[str, Any]]) -> None:
        if not objs:
            return
        key = st.value if isinstance(st, SectionType) else st
        sections.append(
            ParsedSection(
                section_type=key,
                display_name=display,
                object_count=len(objs),
                parsed_ok=True,
                objects=objs,
                raw_snippets=[o["raw"] for o in objs if o.get("raw")],
            )
        )

    _sec(SectionType.ZONES, SectionType.ZONES.display_name, all_zone_objs)
    _sec(SectionType.ADDRESSES, SectionType.ADDRESSES.display_name, all_addr_objs)
    _sec(
        SectionType.ADDRESS_GROUPS,
        SectionType.ADDRESS_GROUPS.display_name,
        all_agrp_objs,
    )
    _sec(SectionType.SERVICES, SectionType.SERVICES.display_name, all_svc_objs)
    _sec(
        SectionType.SERVICE_GROUPS,
        SectionType.SERVICE_GROUPS.display_name,
        all_sgrp_objs,
    )
    _sec(
        SectionType.FIREWALL_POLICIES,
        SectionType.FIREWALL_POLICIES.display_name,
        all_pol_objs,
    )
    _sec(SectionType.NAT, SectionType.NAT.display_name, all_nat_objs)
    if all_vip_objs:
        # VIP objects merge into NAT leaf via taxonomy; keep section for raw/parser fold
        _sec(SectionType.VIP, SectionType.VIP.display_name, all_vip_objs)

    # ---------- security profiles (AV / IPS / URL / WildFire / …) ----------
    # Custom profiles appear under shared/profiles or vsys/profiles (and variants).
    # Pre-defined platform profiles are often absent from running-config XML.
    profile_objs: list[dict[str, Any]] = []
    seen_profile_keys: set[str] = set()

    def _add_profile(
        *,
        name: str,
        kind: str,
        raw_snip: str,
        props: dict[str, Any] | None = None,
        scope: str = "",
    ) -> None:
        key = f"{kind}|{name}|{scope}"
        if key in seen_profile_keys:
            return
        seen_profile_keys.add(key)
        pdict = {
            "Name": name,
            "Profile Type": kind,
            "Scope": scope or None,
        }
        if props:
            pdict.update(props)
        app = Application(
            name=name,
            category=kind,
            source_vendor=_VENDOR,
            source_ref=name,
            source_raw=raw_snip,
            metadata={
                "source": "palo_xml",
                "kind": "security_profile",
                "profile_type": kind,
                "scope": scope,
            },
        )
        model.applications.append(app)
        profile_objs.append(
            _obj(
                app.id,
                name,
                raw_snip,
                pdict,
                preview=kind,
            )
        )

    def _harvest_profile_entries(container: ET.Element | None, scope: str) -> None:
        if container is None:
            return
        # Direct children: <virus><entry name=…>, or <profiles><virus>…
        roots = [container]
        profiles_wrap = container.find("./profiles")
        if profiles_wrap is not None:
            roots.append(profiles_wrap)
        for base in roots:
            for tag, label in _SECURITY_PROFILE_PATHS:
                node = base.find(f"./{tag}")
                if node is None:
                    continue
                for entry in node.findall("./entry"):
                    pname = entry.get("name") or label
                    _add_profile(
                        name=pname,
                        kind=label,
                        raw_snip=_xml_snippet(entry),
                        scope=scope,
                    )
            # Profile groups (attach multiple profile types)
            for entry in base.findall("./profile-group/entry"):
                gname = entry.get("name") or "profile-group"
                members: dict[str, Any] = {}
                for tag, label in _SECURITY_PROFILE_PATHS:
                    vals = _members(entry.find(f"./{tag}"))
                    if not vals:
                        # sometimes single text child
                        t = _child_text(entry, f"./{tag}")
                        if t:
                            vals = [t]
                    if vals:
                        members[label] = vals
                _add_profile(
                    name=gname,
                    kind="Profile Group",
                    raw_snip=_xml_snippet(entry),
                    props={"Members": members} if members else None,
                    scope=scope,
                )

    # shared + each vsys + device-level
    _harvest_profile_entries(root.find("./shared"), "shared")
    if dev is not None:
        _harvest_profile_entries(dev, device_name)
        for vsys in _iter_vsys(dev):
            _harvest_profile_entries(vsys, vsys.get("name") or "vsys")

    # Profile names referenced on security rules (even if pre-defined / not exported)
    for vsys in _iter_vsys(dev) if dev is not None else []:
        vsys_name = vsys.get("name") or "vsys1"
        for entry in vsys.findall("./rulebase/security/rules/entry"):
            ps = entry.find("./profile-setting")
            if ps is None:
                continue
            # group profile
            g = _child_text(ps, "./group") or _child_text(ps, "./group/member")
            groups = _members(ps.find("./group"))
            if g and g not in groups:
                groups.append(g)
            for gname in groups:
                _add_profile(
                    name=gname,
                    kind="Profile Group",
                    raw_snip=_xml_snippet(ps),
                    props={"Referenced By": entry.get("name"), "VSYS": vsys_name},
                    scope=f"ref:{vsys_name}",
                )
            # individual profiles
            profiles_el = ps.find("./profiles")
            if profiles_el is not None:
                for tag, label in _SECURITY_PROFILE_PATHS:
                    vals = _members(profiles_el.find(f"./{tag}"))
                    t = _child_text(profiles_el, f"./{tag}")
                    if t and t not in vals:
                        vals.append(t)
                    for pname in vals:
                        _add_profile(
                            name=pname,
                            kind=label,
                            raw_snip=_xml_snippet(ps),
                            props={
                                "Referenced By": entry.get("name"),
                                "VSYS": vsys_name,
                            },
                            scope=f"ref:{vsys_name}",
                        )

    # Botnet report configuration (threat-related when custom AV/IPS profiles absent)
    botnet = root.find("./shared/botnet") or (
        dev.find("./shared/botnet") if dev is not None else None
    )
    if botnet is not None:
        _add_profile(
            name="botnet_report",
            kind="Botnet Report",
            raw_snip=_xml_snippet(botnet),
            props={"Name": "botnet_report", "Profile Type": "Botnet Report"},
            scope="shared",
        )

    # Threat content update schedule under deviceconfig
    threats = dev.find("./deviceconfig/system/update-schedule/threats") if dev is not None else None
    if threats is None and dev is not None:
        threats = dev.find("./deviceconfig/system/update-schedule")
    # More specific path seen in sample
    for el in root.iter():
        if _local(el.tag) == "threats" and el.find("./recurring") is not None:
            threats = el
            break
    if threats is not None:
        _add_profile(
            name="threat_content_update",
            kind="Threat Content Update",
            raw_snip=_xml_snippet(threats),
            props={"Name": "threat_content_update"},
            scope="system",
        )

    # Interface management / monitor profiles (useful operational security controls)
    if dev is not None:
        for tag, label in (
            ("./network/profiles/interface-management-profile/entry", "Interface Management"),
            ("./network/profiles/monitor-profile/entry", "Link Monitor"),
        ):
            for entry in dev.findall(tag):
                pname = entry.get("name") or label
                _add_profile(
                    name=pname,
                    kind=label,
                    raw_snip=_xml_snippet(entry),
                    scope="network",
                )

    # IKE / IPSec crypto profiles
    if dev is not None:
        for tag, label in (
            (".//ike-crypto-profiles/entry", "IKE Crypto"),
            (".//ipsec-crypto-profiles/entry", "IPSec Crypto"),
            (".//global-protect-app-crypto-profiles/entry", "GlobalProtect Crypto"),
        ):
            for entry in dev.findall(tag):
                pname = entry.get("name") or label
                _add_profile(
                    name=pname,
                    kind=label,
                    raw_snip=_xml_snippet(entry),
                    scope="vpn",
                )

    if profile_objs:
        sections.append(
            ParsedSection(
                section_type=SectionType.APPLICATIONS.value,
                display_name="Security Profiles",
                object_count=len(profile_objs),
                parsed_ok=True,
                objects=profile_objs,
                raw_snippets=[o["raw"] for o in profile_objs if o.get("raw")],
            )
        )
    else:
        warnings.append(
            {
                "code": "PALO_NO_CUSTOM_PROFILES",
                "message": (
                    "No custom Antivirus / Anti-Spyware / Vulnerability / URL Filtering "
                    "profiles found in this XML. Pre-defined platform profiles are often "
                    "omitted from running-config unless customized or referenced on rules."
                ),
                "severity": "info",
                "section": "applications",
            }
        )

    # ---------- management users ----------
    user_objs: list[dict[str, Any]] = []
    for entry in root.findall("./mgt-config/users/entry"):
        uname = entry.get("name") or "user"
        role = None
        rb = entry.find("./permissions/role-based")
        if rb is not None:
            for child in list(rb):
                role = _local(child.tag)
                break
        raw_snip = _xml_snippet(entry)
        user = User(
            name=uname,
            user_type="admin",
            source_vendor=_VENDOR,
            source_ref=uname,
            source_raw=raw_snip,
            metadata={"role": role, "source": "palo_xml"},
        )
        model.users.append(user)
        user_objs.append(
            _obj(
                user.id,
                uname,
                raw_snip,
                {"Name": uname, "Type": "admin", "Role": role},
                preview=role or "admin",
            )
        )
    if user_objs:
        sections.append(
            ParsedSection(
                section_type=SectionType.USERS.value,
                display_name=SectionType.USERS.display_name,
                object_count=len(user_objs),
                parsed_ok=True,
                objects=user_objs,
                raw_snippets=[o["raw"] for o in user_objs if o.get("raw")],
            )
        )

    warnings.append(
        {
            "code": "PALO_XML_OK",
            "message": (
                f"Parsed Palo Alto XML ({device_name}"
                f"{', ' + hostname if hostname else ''}"
                f"{', PAN-OS ' + version if version else ''}): "
                f"{len(model.interfaces)} interfaces, {len(model.addresses)} addresses, "
                f"{len(model.policies)} security rules, {len(model.nat_rules)} NAT rules, "
                f"{len(model.static_routes)} static routes"
            ),
            "severity": "info",
        }
    )
    return sections, warnings
