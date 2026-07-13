"""Build a DependencyGraph from a CommonModel."""

from __future__ import annotations

from model.graph import DependencyGraph, GraphNode
from model.objects import CommonModel, NamedReference


def _add_refs(
    graph: DependencyGraph,
    source_id: str,
    refs: list[NamedReference],
    relation: str = "uses",
) -> None:
    for ref in refs:
        target_id = ref.id
        if not target_id:
            # Resolve by name
            matches = graph.find_by_name(ref.name, kind=ref.kind)
            if matches:
                target_id = matches[0].id
            else:
                # Placeholder node for unresolved refs
                target_id = f"unresolved:{ref.kind or 'object'}:{ref.name}"
                if target_id not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=target_id,
                            name=ref.name,
                            kind=ref.kind or "unknown",
                            metadata={"unresolved": True},
                        )
                    )
        graph.add_edge(source_id, target_id, relation)


def build_dependency_graph(model: CommonModel) -> DependencyGraph:
    graph = DependencyGraph()

    def add_objs(items, kind: str, section: str) -> None:
        for obj in items:
            graph.add_node(
                GraphNode(
                    id=obj.id,
                    name=obj.name,
                    kind=kind,
                    section=section,
                    metadata={"source_ref": obj.source_ref},
                )
            )

    add_objs(model.interfaces, "interface", "interfaces")
    add_objs(model.zones, "zone", "zones")
    add_objs(model.addresses, "address", "addresses")
    add_objs(model.address_groups, "address_group", "address_groups")
    add_objs(model.services, "service", "services")
    add_objs(model.service_groups, "service_group", "service_groups")
    add_objs(model.applications, "application", "applications")
    add_objs(model.policies, "policy", "firewall_policies")
    add_objs(model.nat_rules, "nat", "nat")
    add_objs(model.vips, "vip", "vip")
    add_objs(model.static_routes, "static_route", "static_routes")
    add_objs(model.bgp_neighbors, "bgp", "bgp")
    add_objs(model.ospf_processes, "ospf", "ospf")
    add_objs(model.ipsec_tunnels, "ipsec", "ipsec")
    add_objs(model.ssl_vpns, "ssl_vpn", "ssl_vpn")
    add_objs(model.users, "user", "users")
    add_objs(model.groups, "group", "groups")
    add_objs(model.schedules, "schedule", "schedules")
    add_objs(model.certificates, "certificate", "certificates")

    # Edges: groups → members
    for grp in model.address_groups:
        _add_refs(graph, grp.id, grp.members, relation="member")
    for grp in model.service_groups:
        _add_refs(graph, grp.id, grp.members, relation="member")

    # Policies → addresses / services / apps
    for pol in model.policies:
        _add_refs(graph, pol.id, pol.source_addresses, relation="source")
        _add_refs(graph, pol.id, pol.destination_addresses, relation="destination")
        _add_refs(graph, pol.id, pol.services, relation="service")
        _add_refs(graph, pol.id, pol.applications, relation="application")
        _add_refs(graph, pol.id, pol.users, relation="user")
        if pol.schedule:
            _add_refs(graph, pol.id, [pol.schedule], relation="schedule")
        for iface_name in pol.source_interfaces + pol.destination_interfaces:
            matches = graph.find_by_name(iface_name, kind="interface")
            if matches:
                graph.add_edge(pol.id, matches[0].id, "interface")

    # NAT
    for nat in model.nat_rules:
        _add_refs(graph, nat.id, nat.source_addresses, relation="source")
        _add_refs(graph, nat.id, nat.destination_addresses, relation="destination")
        _add_refs(graph, nat.id, nat.services, relation="service")
        if nat.translated_source:
            _add_refs(graph, nat.id, [nat.translated_source], relation="translated_source")
        if nat.translated_destination:
            _add_refs(graph, nat.id, [nat.translated_destination], relation="translated_destination")

    # VIP
    for vip in model.vips:
        _add_refs(graph, vip.id, vip.source_filter, relation="source_filter")

    # Routes → interfaces
    for route in model.static_routes:
        if route.interface:
            matches = graph.find_by_name(route.interface, kind="interface")
            if matches:
                graph.add_edge(route.id, matches[0].id, "routes_via")

    # Zones → interfaces
    for zone in model.zones:
        for iface_name in zone.interfaces:
            matches = graph.find_by_name(iface_name, kind="interface")
            if matches:
                graph.add_edge(zone.id, matches[0].id, "contains")

    return graph
