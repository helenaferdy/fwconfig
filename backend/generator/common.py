"""Shared stub section generators used until full vendor syntax is implemented.

Each generator emits human-readable placeholder syntax that demonstrates the
pipeline and preserves object structure for the middle-pane explorer.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from model.enums import SectionType
from model.objects import CommonModel, GeneratedSection
from generator.base import SectionGenerator


def _lines_for_objects(
    objects: Iterable[Any],
    formatter: Callable[[Any], str],
) -> tuple[str, int]:
    lines: list[str] = []
    count = 0
    for obj in objects:
        lines.append(formatter(obj))
        count += 1
    return "\n".join(lines), count


class StubSectionGenerator(SectionGenerator):
    """Maps a CommonModel field to a GeneratedSection with simple text output."""

    section_type: SectionType
    model_attr: str
    line_prefix: str = "#"

    def format_object(self, obj: Any) -> str:
        name = getattr(obj, "name", None) or getattr(obj, "id", "unnamed")
        extra = ""
        if hasattr(obj, "value"):
            extra = f" value={obj.value}"
        elif hasattr(obj, "destination"):
            extra = f" dest={obj.destination}"
        elif hasattr(obj, "action"):
            extra = f" action={obj.action}"
        return f"{self.line_prefix} {self.section_type.display_name}: {name}{extra}"

    def generate(self, model: CommonModel) -> GeneratedSection:
        items = getattr(model, self.model_attr, None) or []
        if self.model_attr == "system":
            items = [model.system] if model.system else []

        content, count = _lines_for_objects(items, self.format_object)
        if not content and count == 0:
            content = f"{self.line_prefix} (no {self.section_type.display_name.lower()} objects)"

        return GeneratedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            content=content,
            object_count=count,
            success=True,
        )


def default_stub_generators(
    line_prefix: str = "#",
) -> list[SectionGenerator]:
    """Build a full set of stub generators covering all section types."""

    mapping: list[tuple[SectionType, str]] = [
        (SectionType.INTERFACES, "interfaces"),
        (SectionType.ZONES, "zones"),
        (SectionType.ADDRESSES, "addresses"),
        (SectionType.ADDRESS_GROUPS, "address_groups"),
        (SectionType.SERVICES, "services"),
        (SectionType.SERVICE_GROUPS, "service_groups"),
        (SectionType.APPLICATIONS, "applications"),
        (SectionType.FIREWALL_POLICIES, "policies"),
        (SectionType.NAT, "nat_rules"),
        (SectionType.VIP, "vips"),
        (SectionType.STATIC_ROUTES, "static_routes"),
        (SectionType.BGP, "bgp_neighbors"),
        (SectionType.OSPF, "ospf_processes"),
        (SectionType.DHCP, "dhcp_servers"),
        (SectionType.DNS, "dns_configs"),
        (SectionType.SSL_VPN, "ssl_vpns"),
        (SectionType.IPSEC, "ipsec_tunnels"),
        (SectionType.USERS, "users"),
        (SectionType.GROUPS, "groups"),
        (SectionType.SCHEDULES, "schedules"),
        (SectionType.CERTIFICATES, "certificates"),
        (SectionType.SYSTEM_SETTINGS, "system"),
    ]

    gens: list[SectionGenerator] = []
    for section_type, attr in mapping:

        class _Gen(StubSectionGenerator):
            pass

        _Gen.section_type = section_type
        _Gen.model_attr = attr
        _Gen.line_prefix = line_prefix
        gens.append(_Gen())
    return gens
