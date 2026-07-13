"""Palo Alto target configuration generator."""

from __future__ import annotations

from model.enums import SectionType, Vendor
from model.objects import CommonModel, GeneratedSection
from generator.base import SectionGenerator, VendorGenerator, register_generator
from generator.common import default_stub_generators


class PaloAddressGen(SectionGenerator):
    section_type = SectionType.ADDRESSES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for addr in model.addresses:
            if addr.address_type.value == "fqdn":
                lines.append(f'set address "{addr.name}" fqdn "{addr.value}"')
            elif "-" in addr.value and "/" not in addr.value:
                lines.append(f'set address "{addr.name}" ip-range {addr.value}')
            else:
                lines.append(f'set address "{addr.name}" ip-netmask {addr.value}')
        content = "\n".join(lines) if lines else "# (no addresses)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.addresses),
            success=True,
        )


class PaloServiceGen(SectionGenerator):
    section_type = SectionType.SERVICES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for svc in model.services:
            proto = svc.protocol.value
            ports = ",".join(svc.destination_ports) or "any"
            if proto in ("tcp", "udp"):
                lines.append(
                    f'set service "{svc.name}" protocol {proto} port {ports}'
                )
            else:
                lines.append(f'set service "{svc.name}" protocol {proto}')
        content = "\n".join(lines) if lines else "# (no services)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.services),
            success=True,
        )


class PaloPolicyGen(SectionGenerator):
    section_type = SectionType.FIREWALL_POLICIES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for pol in model.policies:
            action = "allow" if pol.action.value == "allow" else "deny"
            src_z = " ".join(pol.source_zones or pol.source_interfaces or ["any"])
            dst_z = " ".join(pol.destination_zones or pol.destination_interfaces or ["any"])
            src = " ".join(r.name for r in pol.source_addresses) or "any"
            dst = " ".join(r.name for r in pol.destination_addresses) or "any"
            svc = " ".join(r.name for r in pol.services) or "any"
            base = f'set rulebase security rules "{pol.name}"'
            lines.append(f"{base} from {src_z}")
            lines.append(f"{base} to {dst_z}")
            lines.append(f"{base} source {src}")
            lines.append(f"{base} destination {dst}")
            lines.append(f"{base} service {svc}")
            lines.append(f"{base} application any")
            lines.append(f"{base} action {action}")
            if not pol.enabled:
                lines.append(f"{base} disabled yes")
        content = "\n".join(lines) if lines else "# (no policies)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.policies),
            success=True,
        )


class PaloInterfaceGen(SectionGenerator):
    section_type = SectionType.INTERFACES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for iface in model.interfaces:
            lines.append(f'set network interface ethernet "{iface.name}" layer3')
            for ip in iface.ip_addresses:
                lines.append(
                    f'set network interface ethernet "{iface.name}" layer3 ip {ip}'
                )
            if iface.zone:
                lines.append(
                    f'set zone "{iface.zone}" network layer3 "{iface.name}"'
                )
        content = "\n".join(lines) if lines else "# (no interfaces)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.interfaces),
            success=True,
        )


class PaloRouteGen(SectionGenerator):
    section_type = SectionType.STATIC_ROUTES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for route in model.static_routes:
            gw = route.gateway or "0.0.0.0"
            iface = route.interface or "ethernet1/1"
            lines.append(
                f'set network virtual-router "default" routing-table ip static-route '
                f'"{route.name}" destination {route.destination} nexthop ip-address {gw} interface {iface}'
            )
        content = "\n".join(lines) if lines else "# (no static routes)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.static_routes),
            success=True,
        )


@register_generator(Vendor.PALO_ALTO)
class PaloAltoGenerator(VendorGenerator):
    vendor = Vendor.PALO_ALTO

    def build_section_generators(self) -> list[SectionGenerator]:
        specialized = {
            SectionType.INTERFACES: PaloInterfaceGen(),
            SectionType.ADDRESSES: PaloAddressGen(),
            SectionType.SERVICES: PaloServiceGen(),
            SectionType.FIREWALL_POLICIES: PaloPolicyGen(),
            SectionType.STATIC_ROUTES: PaloRouteGen(),
        }
        result: list[SectionGenerator] = []
        for gen in default_stub_generators(line_prefix="#"):
            if gen.section_type in specialized:
                result.append(specialized[gen.section_type])
            else:
                result.append(gen)
        return result
