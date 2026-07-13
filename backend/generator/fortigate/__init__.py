"""Fortigate target configuration generator."""

from __future__ import annotations

from typing import Any

from model.enums import SectionType, Vendor
from model.objects import CommonModel, GeneratedSection
from generator.base import SectionGenerator, VendorGenerator, register_generator
from generator.common import StubSectionGenerator, default_stub_generators


class FortiAddressGen(SectionGenerator):
    section_type = SectionType.ADDRESSES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines = ["config firewall address"]
        for addr in model.addresses:
            lines.append(f'    edit "{addr.name}"')
            if addr.address_type.value == "fqdn":
                lines.append(f"        set type fqdn")
                lines.append(f'        set fqdn "{addr.value}"')
            elif "-" in addr.value and "/" not in addr.value:
                parts = addr.value.split("-", 1)
                lines.append("        set type iprange")
                lines.append(f"        set start-ip {parts[0]}")
                lines.append(f"        set end-ip {parts[1]}")
            else:
                # subnet form – best-effort split
                if "/" in addr.value:
                    ip, mask = addr.value.split("/", 1)
                    # leave mask as provided (may be CIDR or dotted)
                    lines.append(f"        set subnet {ip} {mask}")
                else:
                    lines.append(f"        set subnet {addr.value} 255.255.255.255")
            lines.append("    next")
        lines.append("end")
        content = "\n".join(lines) if model.addresses else "# (no addresses)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.addresses),
            success=True,
        )


class FortiServiceGen(SectionGenerator):
    section_type = SectionType.SERVICES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines = ["config firewall service custom"]
        for svc in model.services:
            lines.append(f'    edit "{svc.name}"')
            proto = svc.protocol.value.upper()
            if proto in ("TCP", "UDP"):
                lines.append(f"        set protocol {proto}")
                ports = " ".join(svc.destination_ports) or "0"
                key = "tcp-portrange" if proto == "TCP" else "udp-portrange"
                lines.append(f"        set {key} {ports}")
            elif proto == "ICMP":
                lines.append("        set protocol ICMP")
            lines.append("    next")
        lines.append("end")
        content = "\n".join(lines) if model.services else "# (no services)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.services),
            success=True,
        )


class FortiPolicyGen(SectionGenerator):
    section_type = SectionType.FIREWALL_POLICIES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines = ["config firewall policy"]
        for i, pol in enumerate(model.policies, start=1):
            pid = pol.policy_id or str(i)
            lines.append(f"    edit {pid}")
            lines.append(f'        set name "{pol.name}"')
            srcintf = " ".join(f'"{x}"' for x in (pol.source_interfaces or ["any"]))
            dstintf = " ".join(f'"{x}"' for x in (pol.destination_interfaces or ["any"]))
            lines.append(f"        set srcintf {srcintf}")
            lines.append(f"        set dstintf {dstintf}")
            src = " ".join(f'"{r.name}"' for r in pol.source_addresses) or '"all"'
            dst = " ".join(f'"{r.name}"' for r in pol.destination_addresses) or '"all"'
            svc = " ".join(f'"{r.name}"' for r in pol.services) or '"ALL"'
            lines.append(f"        set srcaddr {src}")
            lines.append(f"        set dstaddr {dst}")
            lines.append(f"        set service {svc}")
            action = "accept" if pol.action.value == "allow" else "deny"
            lines.append(f"        set action {action}")
            lines.append(f"        set schedule \"always\"")
            if not pol.enabled:
                lines.append("        set status disable")
            lines.append("    next")
        lines.append("end")
        content = "\n".join(lines) if model.policies else "# (no policies)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.policies),
            success=True,
        )


class FortiInterfaceGen(SectionGenerator):
    section_type = SectionType.INTERFACES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines = ["config system interface"]
        for iface in model.interfaces:
            lines.append(f'    edit "{iface.name}"')
            if iface.ip_addresses:
                lines.append(f"        set ip {iface.ip_addresses[0]} {iface.netmask or '255.255.255.0'}")
            if iface.vlan_id is not None:
                lines.append(f"        set vlanid {iface.vlan_id}")
            lines.append("    next")
        lines.append("end")
        content = "\n".join(lines) if model.interfaces else "# (no interfaces)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.interfaces),
            success=True,
        )


class FortiRouteGen(SectionGenerator):
    section_type = SectionType.STATIC_ROUTES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines = ["config router static"]
        for i, route in enumerate(model.static_routes, start=1):
            lines.append(f"    edit {i}")
            dest = route.destination
            if "/" in dest:
                ip, mask = dest.split("/", 1)
                lines.append(f"        set dst {ip} {mask}")
            else:
                lines.append(f"        set dst {dest}")
            if route.gateway:
                lines.append(f"        set gateway {route.gateway}")
            if route.interface:
                lines.append(f'        set device "{route.interface}"')
            lines.append("    next")
        lines.append("end")
        content = "\n".join(lines) if model.static_routes else "# (no static routes)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.static_routes),
            success=True,
        )


@register_generator(Vendor.FORTIGATE)
class FortigateGenerator(VendorGenerator):
    vendor = Vendor.FORTIGATE

    def build_section_generators(self) -> list[SectionGenerator]:
        # Prefer real generators; fill remaining with stubs
        specialized = {
            SectionType.INTERFACES: FortiInterfaceGen(),
            SectionType.ADDRESSES: FortiAddressGen(),
            SectionType.SERVICES: FortiServiceGen(),
            SectionType.FIREWALL_POLICIES: FortiPolicyGen(),
            SectionType.STATIC_ROUTES: FortiRouteGen(),
        }
        result: list[SectionGenerator] = []
        for gen in default_stub_generators(line_prefix="#"):
            if gen.section_type in specialized:
                result.append(specialized[gen.section_type])
            else:
                # Retarget stub to Forti-style comments
                gen.line_prefix = "#"
                result.append(gen)
        return result
