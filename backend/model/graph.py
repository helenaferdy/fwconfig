"""Dependency graph for configuration objects.

Powers reference lookup, impact analysis, optimization, and AI reasoning.
"""

from __future__ import annotations

from typing import Any, Iterable

from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    name: str
    kind: str  # address, service, policy, interface, ...
    section: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str  # uses, member_of, translates, routes_via, ...
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyGraph(BaseModel):
    """Directed object dependency graph."""

    nodes: dict[str, GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.edges.append(
            GraphEdge(
                source_id=source_id,
                target_id=target_id,
                relation=relation,
                metadata=metadata or {},
            )
        )

    def get_dependencies(self, node_id: str) -> list[GraphNode]:
        """Objects that `node_id` depends on (outgoing)."""
        targets = [e.target_id for e in self.edges if e.source_id == node_id]
        return [self.nodes[t] for t in targets if t in self.nodes]

    def get_dependents(self, node_id: str) -> list[GraphNode]:
        """Objects that depend on `node_id` (incoming)."""
        sources = [e.source_id for e in self.edges if e.target_id == node_id]
        return [self.nodes[s] for s in sources if s in self.nodes]

    def find_by_name(self, name: str, kind: str | None = None) -> list[GraphNode]:
        result = []
        for node in self.nodes.values():
            if node.name == name and (kind is None or node.kind == kind):
                result.append(node)
        return result

    def unused_nodes(self, kinds: Iterable[str] | None = None) -> list[GraphNode]:
        """Nodes that nothing depends on (excluding policies/nat as roots)."""
        referenced = {e.target_id for e in self.edges}
        roots = {"policy", "nat", "vip", "static_route", "ipsec", "ssl_vpn", "system"}
        unused = []
        for node in self.nodes.values():
            if node.kind in roots:
                continue
            if kinds is not None and node.kind not in kinds:
                continue
            if node.id not in referenced:
                unused.append(node)
        return unused

    def missing_references(self) -> list[dict[str, str]]:
        """Edges pointing to unknown target nodes."""
        missing = []
        for edge in self.edges:
            if edge.target_id not in self.nodes:
                missing.append(
                    {
                        "source_id": edge.source_id,
                        "target_id": edge.target_id,
                        "relation": edge.relation,
                    }
                )
        return missing

    def stats(self) -> dict[str, int]:
        by_kind: dict[str, int] = {}
        for node in self.nodes.values():
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            **{f"kind_{k}": v for k, v in by_kind.items()},
        }

    def summary_for_ai(self, max_nodes: int = 200) -> dict[str, Any]:
        """Compact graph representation safe to send to the AI assistant."""
        nodes = list(self.nodes.values())[:max_nodes]
        return {
            "stats": self.stats(),
            "nodes": [n.model_dump() for n in nodes],
            "edges_sample": [e.model_dump() for e in self.edges[:max_nodes]],
            "missing_references": self.missing_references()[:50],
            "unused_sample": [n.model_dump() for n in self.unused_nodes()[:50]],
            "truncated": len(self.nodes) > max_nodes,
        }
