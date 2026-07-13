"""Check Point target configuration generator."""

from __future__ import annotations

from model.enums import SectionType, Vendor
from model.objects import CommonModel, GeneratedSection
from generator.base import SectionGenerator, VendorGenerator, register_generator
from generator.common import default_stub_generators


class CPAddressGen(SectionGenerator):
    section_type = SectionType.ADDRESSES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for addr in model.addresses:
            if addr.address_type.value == "fqdn":
                lines.append(f'add dns-domain name "{addr.name}" is-sub-domain false')
            elif "-" in addr.value and "/" not in addr.value:
                start, end = addr.value.split("-", 1)
                lines.append(
                    f'add address-range name "{addr.name}" ip-address-first {start} ip-address-last {end}'
                )
            elif "/" in addr.value:
                ip, mask = addr.value.split("/", 1)
                lines.append(
                    f'add network name "{addr.name}" subnet {ip} subnet-mask {mask}'
                )
            else:
                lines.append(f'add host name "{addr.name}" ip-address {addr.value}')
        content = "\n".join(lines) if lines else "# (no addresses)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.addresses),
            success=True,
        )


class CPServiceGen(SectionGenerator):
    section_type = SectionType.SERVICES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for svc in model.services:
            ports = ",".join(svc.destination_ports) or "0"
            if svc.protocol.value == "tcp":
                lines.append(f'add service-tcp name "{svc.name}" port {ports}')
            elif svc.protocol.value == "udp":
                lines.append(f'add service-udp name "{svc.name}" port {ports}')
            else:
                lines.append(f'add service-other name "{svc.name}"')
        content = "\n".join(lines) if lines else "# (no services)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.services),
            success=True,
        )


class CPPolicyGen(SectionGenerator):
    section_type = SectionType.FIREWALL_POLICIES

    def generate(self, model: CommonModel) -> GeneratedSection:
        lines: list[str] = []
        for i, pol in enumerate(model.policies, start=1):
            action = "Accept" if pol.action.value == "allow" else "Drop"
            src = ",".join(r.name for r in pol.source_addresses) or "Any"
            dst = ",".join(r.name for r in pol.destination_addresses) or "Any"
            svc = ",".join(r.name for r in pol.services) or "Any"
            lines.append(
                f'add access-rule layer "Network" position {i} name "{pol.name}" '
                f'source "{src}" destination "{dst}" service "{svc}" action "{action}"'
            )
        content = "\n".join(lines) if lines else "# (no policies)"
        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=len(model.policies),
            success=True,
        )


@register_generator(Vendor.CHECKPOINT)
class CheckPointGenerator(VendorGenerator):
    vendor = Vendor.CHECKPOINT

    def build_section_generators(self) -> list[SectionGenerator]:
        specialized = {
            SectionType.ADDRESSES: CPAddressGen(),
            SectionType.SERVICES: CPServiceGen(),
            SectionType.FIREWALL_POLICIES: CPPolicyGen(),
        }
        result: list[SectionGenerator] = []
        for gen in default_stub_generators(line_prefix="#"):
            if gen.section_type in specialized:
                result.append(specialized[gen.section_type])
            else:
                result.append(gen)
        return result
