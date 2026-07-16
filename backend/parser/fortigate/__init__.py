"""Fortigate (FortiOS) configuration parser – thorough object extraction.

Uses depth-aware block extraction so nested `config ... end` (e.g. tagging)
does not truncate parent sections.
"""

from __future__ import annotations

import re
from typing import Any

from model.enums import AddressType, PolicyAction, SectionType, ServiceProtocol, Vendor
from model.objects import (
    Address,
    AddressGroup,
    Application,
    Certificate,
    CommonModel,
    DHCPServer,
    DNSConfig,
    FirewallPolicy,
    Interface,
    IPSecTunnel,
    NamedReference,
    ParsedSection,
    Schedule,
    Service,
    ServiceGroup,
    SSLVPN,
    StaticRoute,
    SystemConfig,
    User,
    UserGroup,
    VIP,
)
from parser.base import SectionParser, VendorParser, register_parser
from parser.common import (
    extract_blocks,
    iter_edits,
    set_quoted_list,
    set_tokens,
    set_val,
    wrap_edit_raw,
)



def _return_section(
    section_type: str,
    display_name: str,
    objects: list,
    full_blocks: list[str] | None = None,
) -> ParsedSection:
    """Attach complete config...end blocks for section-level raw view."""
    snippets = list(full_blocks or [])
    if not snippets:
        snippets = [o["raw"] for o in objects if o.get("raw")]
    return ParsedSection(
        section_type=section_type,
        display_name=display_name,
        object_count=len(objects),
        parsed_ok=True,
        objects=objects,
        raw_snippets=snippets,
    )

def _obj(
    oid: str,
    name: str,
    raw: str,
    props: dict[str, Any],
    preview: str | None = None,
) -> dict[str, Any]:
    clean = {k: v for k, v in props.items() if v is not None and v != [] and v != ""}
    return {
        "id": oid,
        "name": name,
        "raw": raw,
        "properties": clean,
        "preview": preview or name,
    }


class FortiInterfaceParser(SectionParser):
    section_type = SectionType.INTERFACES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+interface\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                ip = set_val(body, "ip")
                ip_addr, mask = (None, None)
                if ip:
                    parts = ip.split()
                    if len(parts) >= 2:
                        ip_addr, mask = parts[0], parts[1]
                    else:
                        ip_addr = parts[0]
                alias = set_val(body, "alias")
                role = set_val(body, "role")
                itype = set_val(body, "type") or "physical"
                allow = set_tokens(body, "allowaccess")
                vlan = set_val(body, "vlanid")
                status = set_val(body, "status")
                enabled = status != "down"
                iface = Interface(
                    name=name,
                    ip_addresses=[ip_addr] if ip_addr else [],
                    netmask=mask,
                    interface_type=itype,
                    zone=role,
                    vlan_id=int(vlan) if vlan and vlan.isdigit() else None,
                    enabled=enabled,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                    metadata={"alias": alias, "allowaccess": allow, "role": role},
                )
                model.interfaces.append(iface)
                objects.append(
                    _obj(
                        iface.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Alias": alias,
                            "Role": role,
                            "Type": itype,
                            "IP Address": ip_addr,
                            "Subnet Mask": mask,
                            "Management Access": allow,
                            "VLAN": vlan,
                            "Status": "Up" if enabled else "Down",
                        },
                        preview=f"{ip_addr}/{mask}" if ip_addr and mask else name,
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiAddressParser(SectionParser):
    section_type = SectionType.ADDRESSES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []

        def _add_addr(
            *,
            name: str,
            block: str,
            snip: str,
            addr_type: AddressType,
            value: str,
            start_ip: str | None = None,
            end_ip: str | None = None,
            interface: str | None = None,
            description: str | None = None,
            extra_props: dict[str, Any] | None = None,
        ) -> None:
            meta = {"source": "fortigate"}
            if extra_props:
                meta.update({k: v for k, v in extra_props.items() if v not in (None, "", [])})
            addr = Address(
                name=name,
                address_type=addr_type,
                value=value,
                start_ip=start_ip,
                end_ip=end_ip,
                interface=interface,
                description=description,
                source_vendor=Vendor.FORTIGATE.value,
                source_ref=name,
                source_raw=wrap_edit_raw(block, snip),
                metadata=meta,
            )
            model.addresses.append(addr)
            props = {
                "Name": name,
                "Type": addr_type.value,
                "Value": value,
                "Interface": interface,
                "Description": description,
            }
            if extra_props:
                props.update(extra_props)
            objects.append(
                _obj(
                    addr.id,
                    name,
                    wrap_edit_raw(block, snip),
                    props,
                    preview=value,
                )
            )

        # IPv4 firewall addresses
        for block in extract_blocks(raw, r"^config\s+firewall\s+address\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                value = "0.0.0.0/0"
                addr_type = AddressType.IP_NETWORK
                start_ip = end_ip = None
                subnet = set_val(body, "subnet")
                fqdn = set_val(body, "fqdn")
                start = set_val(body, "start-ip")
                end = set_val(body, "end-ip")
                atype = set_val(body, "type")
                if fqdn or atype == "fqdn":
                    value = (fqdn or "").strip('"')
                    addr_type = AddressType.FQDN
                elif start and end:
                    value = f"{start}-{end}"
                    start_ip, end_ip = start, end
                    addr_type = AddressType.IP_RANGE
                elif subnet:
                    parts = subnet.split()
                    if len(parts) >= 2:
                        value = f"{parts[0]}/{parts[1]}"
                    else:
                        value = parts[0]
                    addr_type = AddressType.IP_NETWORK
                elif atype == "ipmask":
                    addr_type = AddressType.IP_NETWORK
                iface = set_val(body, "associated-interface")
                comment = set_val(body, "comment")
                _add_addr(
                    name=name,
                    block=block,
                    snip=snip,
                    addr_type=addr_type,
                    value=value,
                    start_ip=start_ip,
                    end_ip=end_ip,
                    interface=iface.strip('"') if iface else None,
                    description=comment,
                )

        # IPv6 addresses — critical dual-stack coverage
        for block in extract_blocks(raw, r"^config\s+firewall\s+address6\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                ip6 = set_val(body, "ip6") or set_val(body, "subnet") or "::/0"
                value = ip6.strip('"') if isinstance(ip6, str) else str(ip6)
                _add_addr(
                    name=name,
                    block=block,
                    snip=snip,
                    addr_type=AddressType.IP_NETWORK,
                    value=value,
                    extra_props={"Family": "IPv6"},
                )

        # Wildcard FQDN objects (used heavily in app/web policies)
        for block in extract_blocks(raw, r"^config\s+firewall\s+wildcard-fqdn\s+custom\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                wfqdn = (
                    set_val(body, "wildcard-fqdn")
                    or set_val(body, "fqdn")
                    or name
                )
                value = (wfqdn or name).strip('"')
                _add_addr(
                    name=name,
                    block=block,
                    snip=snip,
                    addr_type=AddressType.WILDCARD,
                    value=value,
                    extra_props={"Kind": "wildcard-fqdn"},
                )

        # Proxy addresses (explicit proxy / ZTNA style objects)
        for block in extract_blocks(raw, r"^config\s+firewall\s+proxy-address\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                atype = set_val(body, "type") or "proxy"
                host = set_val(body, "host") or set_val(body, "host-regex")
                path = set_val(body, "path")
                value = (host or path or atype or name).strip('"') if isinstance(host or path or atype, str) else name
                _add_addr(
                    name=name,
                    block=block,
                    snip=snip,
                    addr_type=AddressType.OTHER,
                    value=str(value),
                    extra_props={
                        "Kind": "proxy-address",
                        "Proxy Type": atype,
                        "Host": host,
                        "Path": path,
                    },
                )

        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiAddressGroupParser(SectionParser):
    section_type = SectionType.ADDRESS_GROUPS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+addrgrp\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                members = set_quoted_list(body, "member")
                grp = AddressGroup(
                    name=name,
                    members=[NamedReference(name=m, kind="address") for m in members],
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.address_groups.append(grp)
                objects.append(
                    _obj(
                        grp.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Members": members, "Member Count": len(members)},
                        preview=f"{len(members)} members",
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiServiceParser(SectionParser):
    section_type = SectionType.SERVICES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+service\s+custom\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                proto = ServiceProtocol.TCP
                ports: list[str] = []
                p = (set_val(body, "protocol") or "").upper()
                tcp = set_val(body, "tcp-portrange")
                udp = set_val(body, "udp-portrange")
                if "UDP" in p or udp:
                    proto = ServiceProtocol.UDP
                    ports = [udp] if udp else []
                elif "ICMP" in p:
                    proto = ServiceProtocol.ICMP
                elif tcp:
                    proto = ServiceProtocol.TCP
                    ports = [tcp]
                elif p:
                    proto = ServiceProtocol.OTHER
                svc = Service(
                    name=name,
                    protocol=proto,
                    destination_ports=ports,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.services.append(svc)
                objects.append(
                    _obj(
                        svc.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Protocol": proto.value,
                            "Destination Ports": ports,
                        },
                        preview=f"{proto.value} {','.join(ports)}".strip(),
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiServiceGroupParser(SectionParser):
    section_type = SectionType.SERVICE_GROUPS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+service\s+group\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                members = set_quoted_list(body, "member")
                grp = ServiceGroup(
                    name=name,
                    members=[NamedReference(name=m, kind="service") for m in members],
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.service_groups.append(grp)
                objects.append(
                    _obj(
                        grp.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Members": members},
                        preview=f"{len(members)} members",
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


# UTM / security-profile keys commonly set on firewall policies
_POLICY_PROFILE_KEYS: list[tuple[str, str]] = [
    ("av-profile", "AV Profile"),
    ("ips-sensor", "IPS Sensor"),
    ("webfilter-profile", "Web Filter"),
    ("dnsfilter-profile", "DNS Filter"),
    ("application-list", "Application Control"),
    ("ssl-ssh-profile", "SSL/SSH Profile"),
    ("profile-protocol-options", "Protocol Options"),
    ("dlp-sensor", "DLP Sensor"),
    ("file-filter-profile", "File Filter"),
    ("icap-profile", "ICAP Profile"),
    ("voip-profile", "VoIP Profile"),
    ("waf-profile", "WAF Profile"),
    ("emailfilter-profile", "Email Filter"),
    ("casb-profile", "CASB Profile"),
]


class FortiPolicyParser(SectionParser):
    section_type = SectionType.FIREWALL_POLICIES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+policy\b"):
            full_blocks.append(block)
            for pid, body, snip in iter_edits(block):
                name = set_val(body, "name") or f"policy_{pid}"
                action = PolicyAction.DENY if (set_val(body, "action") or "").lower() == "deny" else PolicyAction.ALLOW
                src_addrs = set_quoted_list(body, "srcaddr")
                dst_addrs = set_quoted_list(body, "dstaddr")
                services = set_quoted_list(body, "service")
                srcintf = set_quoted_list(body, "srcintf")
                dstintf = set_quoted_list(body, "dstintf")
                nat_on = (set_val(body, "nat") or "").lower() == "enable"
                status = set_val(body, "status")
                log = set_val(body, "logtraffic")
                utm_status = set_val(body, "utm-status")
                schedule = set_val(body, "schedule")

                profiles: dict[str, str] = {}
                for cli_key, label in _POLICY_PROFILE_KEYS:
                    val = set_val(body, cli_key)
                    if val:
                        profiles[label] = val.strip().strip('"')

                pol = FirewallPolicy(
                    name=name,
                    policy_id=pid,
                    action=action,
                    source_addresses=[NamedReference(name=a, kind="address") for a in src_addrs],
                    destination_addresses=[NamedReference(name=a, kind="address") for a in dst_addrs],
                    services=[NamedReference(name=s, kind="service") for s in services],
                    source_interfaces=srcintf,
                    destination_interfaces=dstintf,
                    enabled=status != "disable",
                    nat_enabled=nat_on,
                    log=bool(log and log.lower() != "disable"),
                    schedule=NamedReference(name=schedule, kind="schedule") if schedule else None,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=pid,
                    source_raw=wrap_edit_raw(block, snip),
                    position=int(pid) if pid.isdigit() else None,
                    metadata={
                        "utm_status": utm_status,
                        "profiles": profiles,
                        **{k: v for k, v in profiles.items()},
                    },
                )
                model.policies.append(pol)
                props: dict[str, Any] = {
                    "Name": name,
                    "Policy ID": pid,
                    "Action": action.value,
                    "Source Interfaces": srcintf,
                    "Destination Interfaces": dstintf,
                    "Source Addresses": src_addrs,
                    "Destination Addresses": dst_addrs,
                    "Services": services,
                    "NAT": "Enabled" if nat_on else "Disabled",
                    "Logging": log or "—",
                    "Enabled": pol.enabled,
                    "UTM": utm_status or "—",
                    "Schedule": schedule,
                }
                props.update(profiles)
                objects.append(
                    _obj(
                        pol.id,
                        name,
                        wrap_edit_raw(block, snip),
                        props,
                        preview=f"#{pid} {action.value}",
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiRouteParser(SectionParser):
    section_type = SectionType.STATIC_ROUTES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+router\s+static\b"):
            full_blocks.append(block)
            for rid, body, snip in iter_edits(block):
                dst = set_val(body, "dst")
                gw = set_val(body, "gateway")
                device = set_val(body, "device")
                if dst:
                    parts = dst.split()
                    dest = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else parts[0]
                else:
                    dest = "0.0.0.0/0"
                route = StaticRoute(
                    name=f"route_{rid}",
                    destination=dest,
                    gateway=gw,
                    interface=device.strip('"') if device else None,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=rid,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.static_routes.append(route)
                objects.append(
                    _obj(
                        route.id,
                        route.name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": route.name,
                            "Destination": dest,
                            "Gateway": gw,
                            "Interface": route.interface,
                        },
                        preview=dest,
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiUserParser(SectionParser):
    section_type = SectionType.USERS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+user\s+local\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                status = set_val(body, "status")
                utype = set_val(body, "type") or "password"
                email = set_val(body, "email-to")
                ldap = set_val(body, "ldap-server")
                enabled = status != "disable"
                user = User(
                    name=name,
                    user_type=utype,
                    email=email,
                    enabled=enabled,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                    metadata={"ldap_server": ldap} if ldap else {},
                )
                model.users.append(user)
                objects.append(
                    _obj(
                        user.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Type": utype,
                            "Status": "Enabled" if enabled else "Disabled",
                            "Email": email,
                            "LDAP Server": ldap,
                        },
                        preview=utype,
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiUserGroupParser(SectionParser):
    section_type = SectionType.GROUPS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+user\s+group\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                members = set_quoted_list(body, "member")
                gtype = set_val(body, "group-type") or "firewall"
                grp = UserGroup(
                    name=name,
                    members=[NamedReference(name=m, kind="user") for m in members],
                    group_type=gtype,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.groups.append(grp)
                objects.append(
                    _obj(
                        grp.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Type": gtype, "Members": members},
                        preview=f"{len(members)} members",
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiAdminParser(SectionParser):
    """System administrators → system management taxonomy via existing section."""

    section_type = SectionType.SYSTEM_SETTINGS  # will also push unmapped admin list
    # We use APPLICATIONS? No - store as unmapped with type admin OR use system
    # Better: emit as objects under SYSTEM via custom parse result only
    # Override to users? taxonomy system_management is empty count.
    # Put admins into unmapped with kind system_admin and also return as ParsedSection
    # with section_type system_settings is wrong.
    # Use SectionType.OTHER for admins? Better add to users list with user_type=admin

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        # Implemented as separate registration using SectionType that maps to system_management
        # We'll use a hack: SectionType.SYSTEM_SETTINGS only for global; admins go to unmapped
        # Actually change: use SectionType.USERS path no...
        # Map SYSTEM_SETTINGS leaves: general gets system; management gets from existing_map
        # Store admins only in ParsedSection with section_type we'll set after -
        # Looking at taxonomy LEGACY: we need system_management.
        # Add to model.unmapped and return section with type that resolve_leaf maps.
        # Quick fix: use SectionType.OTHER for admin and update LEGACY_TO_LEAF for custom.
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+admin\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                acc = set_val(body, "accprofile")
                trusthost = set_val(body, "trusthost1")
                objects.append(
                    _obj(
                        f"admin-{name}",
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Type": "admin",
                            "Access Profile": acc,
                            "Trusthost": trusthost,
                        },
                        preview=acc or "admin",
                    )
                )
                model.unmapped.append(
                    {"name": name, "type": "system_admin", "accprofile": acc, "raw": snip}
                )
                # Also as User for visibility under users if desired - keep unmapped only
        # Return with a pseudo - we'll register this under SYSTEM_SETTINGS incorrectly.
        # Instead return empty SYSTEM and handle in FortiManagementParser with custom section_type
        return ParsedSection(
            section_type="system_admin",  # custom key
            display_name="Administrators",
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiVIPParser(SectionParser):
    section_type = SectionType.VIP

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+vip\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                ext = set_val(body, "extip") or ""
                mapped = set_val(body, "mappedip") or set_val(body, "mapped-addr") or ""
                extport = set_val(body, "extport")
                mappedport = set_val(body, "mappedport")
                iface = set_val(body, "extintf")
                vip = VIP(
                    name=name,
                    external_ip=ext.strip('"'),
                    mapped_ip=mapped.strip('"'),
                    external_port=extport,
                    mapped_port=mappedport,
                    interface=iface.strip('"') if iface else None,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.vips.append(vip)
                objects.append(
                    _obj(
                        vip.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "External IP": vip.external_ip,
                            "Mapped IP": vip.mapped_ip,
                            "External Port": extport,
                            "Mapped Port": mappedport,
                            "Interface": vip.interface,
                        },
                        preview=f"{vip.external_ip} → {vip.mapped_ip}",
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiDHCPParser(SectionParser):
    section_type = SectionType.DHCP

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+dhcp\s+server\b"):
            full_blocks.append(block)
            for sid, body, snip in iter_edits(block):
                iface = set_val(body, "interface")
                net = set_val(body, "netmask")
                gw = set_val(body, "default-gateway")
                dns = set_tokens(body, "dns-server1") + set_tokens(body, "dns-server2")
                # ranges nested
                r_start = r_end = None
                rm = re.search(
                    r"config\s+ip-range.*?set\s+start-ip\s+(\S+).*?set\s+end-ip\s+(\S+)",
                    body,
                    re.S | re.I,
                )
                if rm:
                    r_start, r_end = rm.group(1), rm.group(2)
                status = set_val(body, "status")
                dhcp = DHCPServer(
                    name=f"dhcp_{sid}",
                    interface=iface.strip('"') if iface else None,
                    network=net,
                    gateway=gw,
                    dns_servers=dns,
                    range_start=r_start,
                    range_end=r_end,
                    enabled=status != "disable",
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=sid,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.dhcp_servers.append(dhcp)
                objects.append(
                    _obj(
                        dhcp.id,
                        dhcp.name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": dhcp.name,
                            "Interface": dhcp.interface,
                            "Gateway": gw,
                            "Range Start": r_start,
                            "Range End": r_end,
                            "Enabled": dhcp.enabled,
                        },
                        preview=dhcp.interface or dhcp.name,
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiDNSParser(SectionParser):
    section_type = SectionType.DNS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+dns\b"):
            full_blocks.append(block)
            # system dns often has no edit - just sets
            primary = set_val(block, "primary")
            secondary = set_val(block, "secondary")
            domain = set_val(block, "domain")
            dns = DNSConfig(
                name="system_dns",
                primary=primary,
                secondary=secondary,
                servers=[s for s in [primary, secondary] if s],
                domain=domain,
                source_vendor=Vendor.FORTIGATE.value,
                source_raw=block,
            )
            model.dns_configs.append(dns)
            objects.append(
                _obj(
                    dns.id,
                    "system_dns",
                    block,
                    {
                        "Name": "system_dns",
                        "Primary": primary,
                        "Secondary": secondary,
                        "Domain": domain,
                    },
                    preview=primary or "dns",
                )
            )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiIPSecParser(SectionParser):
    section_type = SectionType.IPSEC

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+vpn\s+ipsec\s+phase1-interface\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                remote = set_val(body, "remote-gw")
                iface = set_val(body, "interface")
                prop = set_val(body, "proposal")
                ike = set_val(body, "ike-version") or "1"
                psk = bool(re.search(r"set\s+psksecret\s+", body, re.I))
                tun = IPSecTunnel(
                    name=name,
                    remote_gateway=remote,
                    interface=iface.strip('"') if iface else None,
                    ike_version=f"v{ike}",
                    psk_set=psk,
                    phase1_proposal={"proposal": prop} if prop else {},
                    source_vendor=Vendor.FORTIGATE.value,
                    source_ref=name,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.ipsec_tunnels.append(tun)
                objects.append(
                    _obj(
                        tun.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Remote Gateway": remote,
                            "Interface": tun.interface,
                            "IKE": tun.ike_version,
                            "PSK Set": psk,
                            "Proposal": prop,
                        },
                        preview=remote or name,
                    )
                )
        # phase2 as unmapped extras attached as objects
        for block in extract_blocks(raw, r"^config\s+vpn\s+ipsec\s+phase2-interface\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                phase1 = set_val(body, "phase1name")
                objects.append(
                    _obj(
                        f"ipsec-p2-{name}",
                        f"p2:{name}",
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Type": "phase2",
                            "Phase1": phase1,
                        },
                        preview=phase1 or name,
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiSSLVPNParser(SectionParser):
    section_type = SectionType.SSL_VPN

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+vpn\s+ssl\s+settings\b"):
            full_blocks.append(block)
            port = set_val(block, "port")
            status = set_val(block, "status")
            src = set_quoted_list(block, "source-interface")
            pool = set_quoted_list(block, "tunnel-ip-pools")
            ssl = SSLVPN(
                name="ssl_settings",
                listen_port=int(port) if port and port.isdigit() else None,
                listen_interface=src[0] if src else None,
                address_pool=NamedReference(name=pool[0], kind="address") if pool else None,
                enabled=status != "disable",
                source_vendor=Vendor.FORTIGATE.value,
                source_raw=block,
            )
            model.ssl_vpns.append(ssl)
            objects.append(
                _obj(
                    ssl.id,
                    "ssl_settings",
                    block,
                    {
                        "Name": "ssl_settings",
                        "Port": port,
                        "Interfaces": src,
                        "Pools": pool,
                        "Enabled": ssl.enabled,
                    },
                    preview=f"port {port}" if port else "ssl",
                )
            )
        for block in extract_blocks(raw, r"^config\s+vpn\s+ssl\s+web\s+portal\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                tunnel = set_val(body, "tunnel-mode")
                objects.append(
                    _obj(
                        f"ssl-portal-{name}",
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Type": "ssl_portal", "Tunnel Mode": tunnel},
                        preview="portal",
                    )
                )
                model.ssl_vpns.append(
                    SSLVPN(
                        name=name,
                        portal_name=name,
                        source_vendor=Vendor.FORTIGATE.value,
                        source_raw=wrap_edit_raw(block, snip),
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiCertificateParser(SectionParser):
    section_type = SectionType.CERTIFICATES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for kind, pat in [
            ("local", r"^config\s+vpn\s+certificate\s+local\b"),
            ("ca", r"^config\s+vpn\s+certificate\s+ca\b"),
        ]:
            for block in extract_blocks(raw, pat):
                full_blocks.append(block)
                for name, body, snip in iter_edits(block):
                    cert = Certificate(
                        name=name,
                        cert_type=kind,
                        source_vendor=Vendor.FORTIGATE.value,
                        source_ref=name,
                        source_raw=wrap_edit_raw(block, snip),
                    )
                    model.certificates.append(cert)
                    objects.append(
                        _obj(
                            cert.id,
                            name,
                            wrap_edit_raw(block, snip),
                            {"Name": name, "Type": kind},
                            preview=kind,
                        )
                    )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiScheduleParser(SectionParser):
    section_type = SectionType.SCHEDULES

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+schedule\s+recurring\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                start = set_val(body, "start")
                end = set_val(body, "end")
                days = set_tokens(body, "day")
                sch = Schedule(
                    name=name,
                    schedule_type="recurring",
                    start=start,
                    end=end,
                    days=days,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.schedules.append(sch)
                objects.append(
                    _obj(
                        sch.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Type": "recurring", "Start": start, "End": end, "Days": days},
                    )
                )
        for block in extract_blocks(raw, r"^config\s+firewall\s+schedule\s+onetime\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                start = set_val(body, "start")
                end = set_val(body, "end")
                sch = Schedule(
                    name=name,
                    schedule_type="one-time",
                    start=start,
                    end=end,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_raw=wrap_edit_raw(block, snip),
                )
                model.schedules.append(sch)
                objects.append(
                    _obj(
                        sch.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Type": "one-time", "Start": start, "End": end},
                    )
                )
        for block in extract_blocks(raw, r"^config\s+firewall\s+schedule\s+group\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                members = set_quoted_list(body, "member")
                sch = Schedule(
                    name=name,
                    schedule_type="group",
                    days=members,
                    source_vendor=Vendor.FORTIGATE.value,
                    source_raw=wrap_edit_raw(block, snip),
                    metadata={"members": members},
                )
                model.schedules.append(sch)
                objects.append(
                    _obj(
                        sch.id,
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Type": "group", "Members": members},
                    )
                )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiSystemParser(SectionParser):
    section_type = SectionType.SYSTEM_SETTINGS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+global\b"):
            full_blocks.append(block)
            hostname = set_val(block, "hostname")
            tz = set_val(block, "timezone")
            alias = set_val(block, "alias")
            sport = set_val(block, "admin-sport")
            model.hostname = hostname or model.hostname
            model.system = SystemConfig(
                name="system_global",
                hostname=hostname,
                timezone=tz,
                admin_ports=[int(sport)] if sport and sport.isdigit() else [],
                settings={"alias": alias} if alias else {},
                source_vendor=Vendor.FORTIGATE.value,
                source_raw=block,
            )
            objects.append(
                _obj(
                    "system-global",
                    "system_global",
                    block,
                    {
                        "Name": "system_global",
                        "Hostname": hostname,
                        "Timezone": tz,
                        "Alias": alias,
                        "Admin Port": sport,
                    },
                    preview=hostname or "global",
                )
            )
        # HA
        for block in extract_blocks(raw, r"^config\s+system\s+ha\b"):
            full_blocks.append(block)
            mode = set_val(block, "mode")
            group = set_val(block, "group-name")
            objects.append(
                _obj(
                    "system-ha",
                    "system_ha",
                    block,
                    {"Name": "system_ha", "Mode": mode, "Group": group},
                    preview=mode or "ha",
                )
            )
            model.unmapped.append({"name": "system_ha", "type": "ha", "mode": mode})
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiManagementParser(SectionParser):
    """Admins + accprofiles → system management."""

    section_type = SectionType.OTHER  # remapped via custom section_type value

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+admin\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                acc = set_val(body, "accprofile")
                th = set_val(body, "trusthost1")
                objects.append(
                    _obj(
                        f"admin-{name}",
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Type": "administrator",
                            "Access Profile": acc,
                            "Trusthost": th,
                        },
                        preview=acc or "admin",
                    )
                )
        for block in extract_blocks(raw, r"^config\s+system\s+accprofile\b"):
            full_blocks.append(block)
            for name, body, snip in iter_edits(block):
                objects.append(
                    _obj(
                        f"accprofile-{name}",
                        name,
                        wrap_edit_raw(block, snip),
                        {"Name": name, "Type": "accprofile"},
                        preview="profile",
                    )
                )
        return ParsedSection(
            section_type="system_management",
            display_name="Management",
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiSecurityProfilesParser(SectionParser):
    section_type = SectionType.APPLICATIONS

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        profile_configs = [
            ("application list", "application"),
            ("ips sensor", "ips"),
            ("antivirus profile", "antivirus"),
            ("webfilter profile", "webfilter"),
            ("dnsfilter profile", "dnsfilter"),
            ("dlp profile", "dlp"),
            ("file-filter profile", "file_filter"),
            ("waf profile", "waf"),
            ("emailfilter profile", "emailfilter"),
            ("voip profile", "voip"),
            ("icap profile", "icap"),
            ("firewall ssl-ssh-profile", "ssl_ssh"),
            ("firewall profile-protocol-options", "protocol_options"),
        ]
        for cfg, kind in profile_configs:
            pat = rf"^config\s+{cfg.replace(' ', r'\s+')}\b"
            for block in extract_blocks(raw, pat):
                full_blocks.append(block)
                for name, body, snip in iter_edits(block):
                    app = Application(
                        name=name,
                        category=kind,
                        source_vendor=Vendor.FORTIGATE.value,
                        source_raw=wrap_edit_raw(block, snip),
                    )
                    model.applications.append(app)
                    objects.append(
                        _obj(
                            app.id,
                            name,
                            wrap_edit_raw(block, snip),
                            {"Name": name, "Profile Type": kind},
                            preview=kind,
                        )
                    )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiShapingPolicyParser(SectionParser):
    section_type = SectionType.OTHER

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+firewall\s+shaping-policy\b"):
            full_blocks.append(block)
            for pid, body, snip in iter_edits(block):
                name = set_val(body, "name") or f"shaping_{pid}"
                objects.append(
                    _obj(
                        f"shape-{pid}",
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Policy ID": pid,
                            "Type": "shaping_policy",
                            "Source": set_quoted_list(body, "srcaddr"),
                            "Destination": set_quoted_list(body, "dstaddr"),
                            "Service": set_quoted_list(body, "service"),
                            "Class ID": set_val(body, "class-id"),
                        },
                    )
                )
        for block in extract_blocks(raw, r"^config\s+firewall\s+local-in-policy\b"):
            full_blocks.append(block)
            for pid, body, snip in iter_edits(block):
                name = set_val(body, "name") or f"local_in_{pid}"
                objects.append(
                    _obj(
                        f"localin-{pid}",
                        name,
                        wrap_edit_raw(block, snip),
                        {
                            "Name": name,
                            "Policy ID": pid,
                            "Type": "local_in_policy",
                            "Interface": set_val(body, "intf") or set_quoted_list(body, "intf"),
                            "Source": set_quoted_list(body, "srcaddr"),
                            "Destination": set_quoted_list(body, "dstaddr"),
                            "Service": set_quoted_list(body, "service"),
                            "Action": set_val(body, "action"),
                            "Status": set_val(body, "status"),
                        },
                    )
                )
        return ParsedSection(
            section_type="policies_other",
            display_name="Other",
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiSDWANParser(SectionParser):
    """System SD-WAN zones, members, health-checks → Network / Other."""

    section_type = SectionType.OTHER

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects: list[dict[str, Any]] = []
        full_blocks: list[str] = []
        for block in extract_blocks(raw, r"^config\s+system\s+sdwan\b"):
            full_blocks.append(block)
            status = set_val(block, "status")
            # Nested: config zone / members / health-check / service
            for sub_pat, kind, label_key in (
                (r"^\s*config\s+zone\b", "sdwan_zone", "zone"),
                (r"^\s*config\s+members\b", "sdwan_member", "member"),
                (r"^\s*config\s+health-check\b", "sdwan_health_check", "health-check"),
                (r"^\s*config\s+service\b", "sdwan_service", "service"),
            ):
                for sub in extract_blocks(block, sub_pat):
                    for name, body, snip in iter_edits(sub):
                        props: dict[str, Any] = {
                            "Name": name,
                            "Type": kind,
                            "SD-WAN Status": status,
                        }
                        if kind == "sdwan_member":
                            props["Interface"] = set_val(body, "interface")
                            props["Zone"] = set_val(body, "zone")
                            props["Gateway"] = set_val(body, "gateway")
                        elif kind == "sdwan_health_check":
                            props["Server"] = set_val(body, "server") or set_tokens(
                                body, "server"
                            )
                            props["Members"] = set_val(body, "members")
                        elif kind == "sdwan_service":
                            props["Mode"] = set_val(body, "mode")
                            props["Priority Members"] = set_val(
                                body, "priority-members"
                            )
                        objects.append(
                            _obj(
                                f"sdwan-{kind}-{name}",
                                name,
                                wrap_edit_raw(sub, snip),
                                props,
                                preview=kind,
                            )
                        )
            # Always keep full sdwan block as a top-level raw object if nested empty
            if not objects:
                objects.append(
                    _obj(
                        "sdwan-config",
                        "system_sdwan",
                        block,
                        {"Name": "system_sdwan", "Type": "sdwan", "Status": status},
                        preview=status or "sdwan",
                    )
                )
        return ParsedSection(
            section_type="network_other",
            display_name="SD-WAN Network",
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiLoggingParser(SectionParser):
    section_type = SectionType.OTHER

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for label, pat in [
            ("log_disk", r"^config\s+log\s+disk\s+setting\b"),
            ("log_memory", r"^config\s+log\s+memory\s+setting\b"),
            ("log_setting", r"^config\s+log\s+setting\b"),
            ("log_fortiguard", r"^config\s+log\s+fortiguard\s+setting\b"),
        ]:
            for block in extract_blocks(raw, pat):
                full_blocks.append(block)
                status = set_val(block, "status")
                objects.append(
                    _obj(
                        label,
                        label,
                        block,
                        {"Name": label, "Status": status or "configured"},
                        preview=status or "log",
                    )
                )
        return ParsedSection(
            section_type="diagnostics_logging",
            display_name="Logging",
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


class FortiDynamicRoutingParser(SectionParser):
    section_type = SectionType.BGP

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        objects = []
        full_blocks: list[str] = []
        for label, pat in [
            ("bgp", r"^config\s+router\s+bgp\b"),
            ("ospf", r"^config\s+router\s+ospf\b"),
            ("ospf6", r"^config\s+router\s+ospf6\b"),
            ("rip", r"^config\s+router\s+rip\b"),
            ("isis", r"^config\s+router\s+isis\b"),
        ]:
            for block in extract_blocks(raw, pat):
                full_blocks.append(block)
                # neighbor edits inside bgp
                neighbors = list(iter_edits(block))
                if neighbors:
                    for name, body, snip in neighbors:
                        objects.append(
                            _obj(
                                f"{label}-{name}",
                                f"{label}:{name}",
                                wrap_edit_raw(block, snip),
                                {"Name": name, "Protocol": label},
                                preview=label,
                            )
                        )
                else:
                    as_num = set_val(block, "as") or set_val(block, "router-id")
                    objects.append(
                        _obj(
                            label,
                            label,
                            block,
                            {"Name": label, "Detail": as_num or "configured"},
                            preview=label,
                        )
                    )
        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(objects),
            parsed_ok=True,
            objects=objects,
            raw_snippets=full_blocks or [o["raw"] for o in objects if o.get("raw")],
        )


@register_parser(Vendor.FORTIGATE)
class FortigateParser(VendorParser):
    vendor = Vendor.FORTIGATE
    fingerprints = [
        r"config\s+system\s+global",
        r"config\s+firewall\s+policy",
        r"config\s+firewall\s+address",
        r"config\s+system\s+interface",
        r"set\s+vdom\s+",
        r"#config-version=FG",
        r"config\s+router\s+static",
        r"config\s+vpn\s+ipsec",
        r"config\s+user\s+local",
    ]

    def build_section_parsers(self) -> list[SectionParser]:
        return [
            FortiSystemParser(),
            FortiManagementParser(),
            FortiInterfaceParser(),
            FortiDHCPParser(),
            FortiDNSParser(),
            FortiAddressParser(),
            FortiAddressGroupParser(),
            FortiServiceParser(),
            FortiServiceGroupParser(),
            FortiScheduleParser(),
            FortiPolicyParser(),
            FortiVIPParser(),
            FortiRouteParser(),
            FortiDynamicRoutingParser(),
            FortiIPSecParser(),
            FortiSSLVPNParser(),
            FortiUserParser(),
            FortiUserGroupParser(),
            FortiCertificateParser(),
            FortiSecurityProfilesParser(),
            FortiShapingPolicyParser(),
            FortiSDWANParser(),
            FortiLoggingParser(),
        ]
