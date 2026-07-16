"""Parse Check Point GAiA `show configuration` CLI output.

Device-plane facts: hostname, interfaces, routes, DNS, users, management interface.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from model.enums import SectionType, Vendor
from model.objects import (
    CommonModel,
    DNSConfig,
    Interface,
    OSPFProcess,
    ParsedSection,
    StaticRoute,
    SystemConfig,
    User,
)

_VENDOR = Vendor.CHECKPOINT.value


def is_gaia_show_config(text: str) -> bool:
    t = text or ""
    if re.search(r"GAiA\s+version|show configuration|Language version:", t, re.I):
        return True
    if re.search(r"^set\s+interface\s+\S+\s+ipv4-address\s+", t, re.I | re.M):
        return True
    if re.search(r"^set\s+hostname\s+\S+", t, re.I | re.M) and re.search(
        r"^set\s+static-route\s+", t, re.I | re.M
    ):
        return True
    return False


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


def parse_gaia_into_model(raw: str, model: CommonModel) -> list[ParsedSection]:
    """Mutate model with GAiA OS/network objects; return parsed sections."""
    # Drop CLI prompt / pager junk
    lines: list[str] = []
    for line in (raw or "").replace("\r\n", "\n").split("\n"):
        s = line.strip()
        if not s or s in {"x", "More", "--More--"}:
            continue
        if re.match(r"^\S+>\s*show\s+configuration", s, re.I):
            continue
        if s.endswith(">") and " " not in s:
            continue
        lines.append(line.rstrip())

    text = "\n".join(lines)
    sections: list[ParsedSection] = []

    # ---- system ----
    hostname = None
    m = re.search(r"^set\s+hostname\s+(\S+)\s*$", text, re.I | re.M)
    if m:
        hostname = m.group(1).strip()
        model.hostname = hostname
    domain = None
    m = re.search(r"^set\s+domainname\s+(\S+)\s*$", text, re.I | re.M)
    if m:
        domain = m.group(1).strip()
    timezone = None
    m = re.search(r"^set\s+timezone\s+(.+?)\s*$", text, re.I | re.M)
    if m:
        timezone = re.sub(r"\s+", " ", m.group(1).strip())
    gaia_ver = None
    m = re.search(r"GAiA\s+version:\s*(\S+)", text, re.I)
    if m:
        gaia_ver = m.group(1)

    ntp: list[str] = []
    for m in re.finditer(
        r"^add\s+ntp\s+server\s+address\s+(\S+)", text, re.I | re.M
    ):
        ntp.append(m.group(1))

    sys_obj = SystemConfig(
        name=hostname or "system",
        hostname=hostname,
        timezone=timezone,
        ntp_servers=ntp,
        source_vendor=_VENDOR,
        source_raw=text[:2000],
        metadata={
            "domainname": domain,
            "gaia_version": gaia_ver,
            "source": "gaia_show_configuration",
        },
    )
    model.system = sys_obj
    sys_props = {
        "Hostname": hostname,
        "Domain": domain,
        "Timezone": timezone,
        "GAiA Version": gaia_ver,
        "NTP": ntp,
    }
    sections.append(
        ParsedSection(
            section_type=SectionType.SYSTEM_SETTINGS.value,
            display_name=SectionType.SYSTEM_SETTINGS.display_name,
            object_count=1,
            parsed_ok=True,
            objects=[
                _obj(
                    sys_obj.id,
                    hostname or "system",
                    "\n".join(
                        ln
                        for ln in lines
                        if re.match(
                            r"^\s*set\s+(hostname|domainname|timezone|ntp)\b",
                            ln,
                            re.I,
                        )
                    )
                    or f"hostname {hostname}",
                    sys_props,
                    preview=hostname or "system",
                )
            ],
            raw_snippets=[text[:4000]],
        )
    )

    # ---- DNS ----
    dns_primary = re.search(r"^set\s+dns\s+primary\s+(\S+)", text, re.I | re.M)
    dns_secondary = re.search(r"^set\s+dns\s+secondary\s+(\S+)", text, re.I | re.M)
    dns_suffix = re.search(r"^set\s+dns\s+suffix\s+(\S+)", text, re.I | re.M)
    if dns_primary or dns_secondary or dns_suffix:
        servers = []
        if dns_primary:
            servers.append(dns_primary.group(1))
        if dns_secondary:
            servers.append(dns_secondary.group(1))
        dns = DNSConfig(
            name="dns",
            primary=dns_primary.group(1) if dns_primary else None,
            secondary=dns_secondary.group(1) if dns_secondary else None,
            servers=servers,
            domain=dns_suffix.group(1) if dns_suffix else None,
            source_vendor=_VENDOR,
            source_raw="\n".join(
                ln for ln in lines if re.match(r"^\s*set\s+dns\b", ln, re.I)
            ),
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
                        {
                            "Primary": dns_primary.group(1) if dns_primary else None,
                            "Secondary": dns_secondary.group(1) if dns_secondary else None,
                            "Suffix": dns_suffix.group(1) if dns_suffix else None,
                        },
                        preview=", ".join(servers) or "dns",
                    )
                ],
            )
        )

    # ---- interfaces (dedupe by name; last write wins) ----
    iface_state: dict[str, dict[str, Any]] = {}
    for m in re.finditer(
        r"^set\s+interface\s+(\S+)\s+(.+?)\s*$", text, re.I | re.M
    ):
        name = m.group(1)
        rest = m.group(2).strip()
        st = iface_state.setdefault(name, {"name": name, "raw_lines": []})
        st["raw_lines"].append(m.group(0))
        if rest.startswith("state "):
            st["enabled"] = rest.split(None, 1)[1].lower() == "on"
        elif rest.startswith("ipv4-address "):
            parts = rest.split()
            # ipv4-address X mask-length N
            try:
                ip_i = parts.index("ipv4-address")
                st["ip"] = parts[ip_i + 1]
            except (ValueError, IndexError):
                pass
            if "mask-length" in parts:
                try:
                    ml = int(parts[parts.index("mask-length") + 1])
                    st["mask_length"] = ml
                except (ValueError, IndexError):
                    pass
        elif rest.startswith("mtu "):
            try:
                st["mtu"] = int(rest.split()[1])
            except (ValueError, IndexError):
                pass
        elif rest.startswith("link-speed "):
            st["link_speed"] = rest.split(None, 1)[1]
        elif rest.startswith("auto-negotiation "):
            st["auto_neg"] = rest.split()[1]

    mgmt_if = None
    m = re.search(r"^set\s+management\s+interface\s+(\S+)", text, re.I | re.M)
    if m:
        mgmt_if = m.group(1)

    iface_objs: list[dict[str, Any]] = []
    for name, st in iface_state.items():
        ip = st.get("ip")
        ml = st.get("mask_length")
        cidr = f"{ip}/{ml}" if ip is not None and ml is not None else ip
        raw_block = "\n".join(st.get("raw_lines") or [])
        enabled = st.get("enabled", True)
        # Keep loopback — never drop gateway interfaces from the analysis view
        if_type = "loopback" if name in ("lo", "loopback", "loopback0") else "physical"
        iface = Interface(
            name=name,
            interface_type=if_type,
            ip_addresses=[ip] if ip else [],
            netmask=str(ml) if ml is not None else None,
            enabled=bool(enabled),
            mtu=st.get("mtu"),
            source_vendor=_VENDOR,
            source_raw=raw_block,
            metadata={
                "mask_length": ml,
                "management": name == mgmt_if,
                "link_speed": st.get("link_speed"),
                "source": "gaia_show_configuration",
            },
        )
        model.interfaces.append(iface)
        props = {
            "Name": name,
            "Type": if_type,
            "IPv4": cidr,
            "Enabled": enabled,
            "MTU": st.get("mtu"),
            "Management": name == mgmt_if,
            "Link Speed": st.get("link_speed"),
        }
        iface_objs.append(
            _obj(iface.id, name, raw_block, props, preview=cidr or name)
        )

    sections.append(
        ParsedSection(
            section_type=SectionType.INTERFACES.value,
            display_name=SectionType.INTERFACES.display_name,
            object_count=len(iface_objs),
            parsed_ok=True,
            objects=iface_objs,
            raw_snippets=[
                "\n".join(ln for ln in lines if re.match(r"^\s*set\s+interface\b", ln, re.I))
            ],
        )
    )

    # ---- local users (set user <name> …) ----
    user_attrs: dict[str, dict[str, Any]] = {}
    user_raw: dict[str, list[str]] = {}
    for m in re.finditer(r"^set\s+user\s+(\S+)\s+(.+?)\s*$", text, re.I | re.M):
        uname = m.group(1)
        rest = m.group(2).strip()
        st = user_attrs.setdefault(uname, {"name": uname})
        user_raw.setdefault(uname, []).append(m.group(0))
        if rest.startswith("shell "):
            st["shell"] = rest.split(None, 1)[1]
        elif rest.startswith("password-hash "):
            ph = rest.split(None, 1)[1]
            st["has_password"] = bool(ph and ph not in {"*", "!"})
            st["password_locked"] = ph in {"*", "!"}
        elif rest.startswith("uid "):
            st["uid"] = rest.split(None, 1)[1]
        elif rest.startswith("homedir "):
            st["homedir"] = rest.split(None, 1)[1]
        elif rest.startswith("realname "):
            st["realname"] = rest.split(None, 1)[1].strip('"')
        else:
            # generic key value
            parts = rest.split(None, 1)
            if len(parts) == 2:
                st[parts[0]] = parts[1]

    # AAA / external auth summary (attach as user metadata + optional note user)
    aaa_lines = [ln for ln in lines if re.match(r"^\s*set\s+aaa\b", ln, re.I)]
    aaa_order: list[str] = []
    for m in re.finditer(
        r"^set\s+aaa\s+order\s+(\S+)\s+priority\s+(\d+)", text, re.I | re.M
    ):
        aaa_order.append(f"{m.group(1)}(p{m.group(2)})")
    radius_on = bool(
        re.search(r"^set\s+aaa\s+order\s+radius\s+state\s+on", text, re.I | re.M)
    )
    tacacs_on = bool(
        re.search(r"^set\s+aaa\s+order\s+tacacs\s+state\s+on", text, re.I | re.M)
    )

    user_objs: list[dict[str, Any]] = []
    for uname, st in sorted(user_attrs.items()):
        raw_block = "\n".join(user_raw.get(uname) or [])
        locked = bool(st.get("password_locked"))
        has_pw = bool(st.get("has_password"))
        user = User(
            name=uname,
            user_type="local",
            enabled=not locked,
            source_vendor=_VENDOR,
            source_raw=raw_block,
            metadata={
                "shell": st.get("shell"),
                "has_password": has_pw,
                "password_locked": locked,
                "uid": st.get("uid"),
                "homedir": st.get("homedir"),
                "realname": st.get("realname"),
                "source": "gaia_show_configuration",
            },
        )
        model.users.append(user)
        user_objs.append(
            _obj(
                user.id,
                uname,
                raw_block,
                {
                    "Name": uname,
                    "Type": "local",
                    "Shell": st.get("shell"),
                    "Password set": has_pw,
                    "Locked": locked,
                    "UID": st.get("uid"),
                    "Real name": st.get("realname"),
                },
                preview=(
                    f"{'locked' if locked else 'local'}"
                    + (f" · {st.get('shell')}" if st.get("shell") else "")
                ),
            )
        )

    # Auth method summary as a synthetic explorer object when AAA present
    if aaa_lines or aaa_order:
        auth_raw = "\n".join(aaa_lines)
        auth_name = "aaa-auth-order"
        user = User(
            name=auth_name,
            user_type="radius" if radius_on else ("tacacs" if tacacs_on else "local"),
            enabled=True,
            source_vendor=_VENDOR,
            source_raw=auth_raw,
            metadata={
                "aaa_order": aaa_order,
                "radius": radius_on,
                "tacacs": tacacs_on,
                "source": "gaia_show_configuration",
            },
        )
        model.users.append(user)
        user_objs.append(
            _obj(
                user.id,
                auth_name,
                auth_raw,
                {
                    "Name": "AAA authentication order",
                    "Order": ", ".join(aaa_order) or "—",
                    "RADIUS": radius_on,
                    "TACACS": tacacs_on,
                },
                preview=", ".join(aaa_order) or "aaa",
            )
        )

    sections.append(
        ParsedSection(
            section_type=SectionType.USERS.value,
            display_name=SectionType.USERS.display_name,
            object_count=len(user_objs),
            parsed_ok=True,
            objects=user_objs,
            raw_snippets=[
                "\n".join(
                    ln
                    for ln in lines
                    if re.match(r"^\s*set\s+(user|aaa)\b", ln, re.I)
                )
            ],
        )
    )

    # ---- static routes ----
    route_objs: list[dict[str, Any]] = []
    for m in re.finditer(
        r"^set\s+static-route\s+(\S+)\s+nexthop\s+gateway\s+address\s+(\S+)\s+on\s*$",
        text,
        re.I | re.M,
    ):
        dest = m.group(1)
        if dest.lower() == "default":
            dest = "0.0.0.0/0"
        gw = m.group(2)
        route = StaticRoute(
            name=f"route_{dest}",
            destination=dest,
            gateway=gw,
            source_vendor=_VENDOR,
            source_raw=m.group(0),
            metadata={"source": "gaia_show_configuration"},
        )
        model.static_routes.append(route)
        route_objs.append(
            _obj(
                route.id,
                dest,
                m.group(0),
                {"Destination": dest, "Gateway": gw},
                preview=f"{dest} → {gw}",
            )
        )
    sections.append(
        ParsedSection(
            section_type=SectionType.STATIC_ROUTES.value,
            display_name=SectionType.STATIC_ROUTES.display_name,
            object_count=len(route_objs),
            parsed_ok=True,
            objects=route_objs,
        )
    )

    # ---- OSPF presence ----
    if re.search(r"^set\s+ospf\b", text, re.I | re.M):
        ospf = OSPFProcess(
            name="default",
            process_id="default",
            source_vendor=_VENDOR,
            source_raw="\n".join(
                ln for ln in lines if re.search(r"\bospf\b", ln, re.I)
            )[:2000],
            metadata={"source": "gaia_show_configuration"},
        )
        model.ospf_processes.append(ospf)
        sections.append(
            ParsedSection(
                section_type=SectionType.OSPF.value,
                display_name=SectionType.OSPF.display_name,
                object_count=1,
                parsed_ok=True,
                objects=[
                    _obj(
                        ospf.id,
                        "ospf-default",
                        ospf.source_raw or "",
                        {"Instance": "default", "Area": "backbone"},
                        preview="OSPF backbone",
                    )
                ],
            )
        )

    return sections
