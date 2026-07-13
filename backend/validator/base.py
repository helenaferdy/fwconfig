"""Validation framework.

Runs after generation (and optionally after parse) to produce structured
warnings: missing refs, duplicates, unused objects, unsupported features, etc.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any

from model.enums import WarningSeverity
from model.graph import DependencyGraph
from model.objects import CommonModel
from session.store import MigrationWarning

logger = logging.getLogger(__name__)


class ValidationIssue:
    def __init__(
        self,
        code: str,
        message: str,
        severity: WarningSeverity = WarningSeverity.WARNING,
        section: str | None = None,
        object_name: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.severity = severity
        self.section = section
        self.object_name = object_name
        self.details = details or {}

    def to_warning(self) -> MigrationWarning:
        return MigrationWarning(
            severity=self.severity,
            code=self.code,
            message=self.message,
            section=self.section,
            object_name=self.object_name,
            details=self.details,
        )


class Validator(ABC):
    name: str = "base"

    @abstractmethod
    def validate(
        self,
        model: CommonModel,
        graph: DependencyGraph | None = None,
        target_vendor: str | None = None,
    ) -> list[ValidationIssue]:
        ...


class MissingReferenceValidator(Validator):
    name = "missing_references"

    def validate(
        self,
        model: CommonModel,
        graph: DependencyGraph | None = None,
        target_vendor: str | None = None,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        known_addrs = {a.name for a in model.addresses} | {g.name for g in model.address_groups}
        known_svcs = {s.name for s in model.services} | {g.name for g in model.service_groups}
        # Built-in names commonly present on all vendors
        known_addrs |= {"all", "any", "ALL", "Any", "any-ipv4", "any-ipv6"}
        known_svcs |= {"ALL", "all", "Any", "any", "HTTP", "HTTPS", "DNS", "SSH", "PING"}

        for pol in model.policies:
            for ref in pol.source_addresses + pol.destination_addresses:
                if ref.name not in known_addrs:
                    issues.append(
                        ValidationIssue(
                            code="MISSING_ADDRESS_REF",
                            message=f"Policy '{pol.name}' references missing address '{ref.name}'",
                            severity=WarningSeverity.ERROR,
                            section="firewall_policies",
                            object_name=pol.name,
                            details={"ref": ref.name, "kind": "address"},
                        )
                    )
            for ref in pol.services:
                if ref.name not in known_svcs:
                    issues.append(
                        ValidationIssue(
                            code="MISSING_SERVICE_REF",
                            message=f"Policy '{pol.name}' references missing service '{ref.name}'",
                            severity=WarningSeverity.ERROR,
                            section="firewall_policies",
                            object_name=pol.name,
                            details={"ref": ref.name, "kind": "service"},
                        )
                    )

        for grp in model.address_groups:
            for ref in grp.members:
                if ref.name not in known_addrs:
                    issues.append(
                        ValidationIssue(
                            code="MISSING_GROUP_MEMBER",
                            message=f"Address group '{grp.name}' references missing member '{ref.name}'",
                            severity=WarningSeverity.ERROR,
                            section="address_groups",
                            object_name=grp.name,
                            details={"ref": ref.name},
                        )
                    )

        if graph:
            for miss in graph.missing_references():
                issues.append(
                    ValidationIssue(
                        code="GRAPH_MISSING_REF",
                        message=f"Dependency graph missing target {miss['target_id']} from {miss['source_id']}",
                        severity=WarningSeverity.WARNING,
                        details=miss,
                    )
                )
        return issues


class DuplicateObjectValidator(Validator):
    name = "duplicates"

    def validate(
        self,
        model: CommonModel,
        graph: DependencyGraph | None = None,
        target_vendor: str | None = None,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        collections = [
            ("addresses", [a.name for a in model.addresses]),
            ("services", [s.name for s in model.services]),
            ("interfaces", [i.name for i in model.interfaces]),
            ("firewall_policies", [p.name for p in model.policies]),
        ]
        for section, names in collections:
            counts = Counter(names)
            for name, n in counts.items():
                if n > 1:
                    issues.append(
                        ValidationIssue(
                            code="DUPLICATE_OBJECT",
                            message=f"Duplicate {section} name '{name}' appears {n} times",
                            severity=WarningSeverity.WARNING,
                            section=section,
                            object_name=name,
                            details={"count": n},
                        )
                    )
        return issues


class UnusedObjectValidator(Validator):
    name = "unused_objects"

    def validate(
        self,
        model: CommonModel,
        graph: DependencyGraph | None = None,
        target_vendor: str | None = None,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        if not graph:
            return issues
        for node in graph.unused_nodes(kinds={"address", "service", "address_group", "service_group"}):
            issues.append(
                ValidationIssue(
                    code="UNUSED_OBJECT",
                    message=f"Unused {node.kind} object '{node.name}'",
                    severity=WarningSeverity.INFO,
                    section=node.section,
                    object_name=node.name,
                    details={"kind": node.kind, "id": node.id},
                )
            )
        return issues


class UnsupportedFeatureValidator(Validator):
    name = "unsupported_features"

    def validate(
        self,
        model: CommonModel,
        graph: DependencyGraph | None = None,
        target_vendor: str | None = None,
    ) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        # Flag objects marked unsupported during parse
        for collection_name in (
            "interfaces",
            "addresses",
            "services",
            "policies",
            "nat_rules",
            "ssl_vpns",
            "ipsec_tunnels",
        ):
            items = getattr(model, collection_name, []) or []
            for obj in items:
                if getattr(obj, "unsupported", False):
                    issues.append(
                        ValidationIssue(
                            code="UNSUPPORTED_FEATURE",
                            message=getattr(obj, "unsupported_reason", None)
                            or f"Unsupported feature on '{obj.name}'",
                            severity=WarningSeverity.WARNING,
                            section=collection_name,
                            object_name=obj.name,
                        )
                    )
        for item in model.unmapped:
            issues.append(
                ValidationIssue(
                    code="UNMAPPED_OBJECT",
                    message=f"Unmapped configuration element: {item.get('name', item.get('type', 'unknown'))}",
                    severity=WarningSeverity.WARNING,
                    section="other",
                    object_name=str(item.get("name", "")),
                    details=item if isinstance(item, dict) else {},
                )
            )
        # Heuristic: SSL VPN often partial
        if model.ssl_vpns:
            issues.append(
                ValidationIssue(
                    code="PARTIAL_SSL_VPN",
                    message="SSL VPN conversion may be incomplete – review portal, auth, and split-tunnel settings",
                    severity=WarningSeverity.WARNING,
                    section="ssl_vpn",
                )
            )
        return issues


class NameCollisionValidator(Validator):
    name = "name_collisions"

    def validate(
        self,
        model: CommonModel,
        graph: DependencyGraph | None = None,
        target_vendor: str | None = None,
    ) -> list[ValidationIssue]:
        """Detect same name used across different object kinds (problematic on some vendors)."""
        issues: list[ValidationIssue] = []
        name_kinds: dict[str, set[str]] = {}
        for kind, items in [
            ("address", model.addresses),
            ("service", model.services),
            ("interface", model.interfaces),
            ("zone", model.zones),
        ]:
            for obj in items:
                name_kinds.setdefault(obj.name, set()).add(kind)
        for name, kinds in name_kinds.items():
            if len(kinds) > 1:
                issues.append(
                    ValidationIssue(
                        code="NAME_COLLISION",
                        message=f"Name '{name}' used across object kinds: {', '.join(sorted(kinds))}",
                        severity=WarningSeverity.INFO,
                        object_name=name,
                        details={"kinds": sorted(kinds)},
                    )
                )
        return issues


DEFAULT_VALIDATORS: list[Validator] = [
    MissingReferenceValidator(),
    DuplicateObjectValidator(),
    UnusedObjectValidator(),
    UnsupportedFeatureValidator(),
    NameCollisionValidator(),
]


def run_validation(
    model: CommonModel,
    graph: DependencyGraph | None = None,
    target_vendor: str | None = None,
    validators: list[Validator] | None = None,
) -> list[MigrationWarning]:
    results: list[MigrationWarning] = []
    for v in validators or DEFAULT_VALIDATORS:
        try:
            for issue in v.validate(model, graph=graph, target_vendor=target_vendor):
                results.append(issue.to_warning())
        except Exception:  # noqa: BLE001
            logger.exception("Validator %s failed", v.name)
            results.append(
                MigrationWarning(
                    severity=WarningSeverity.ERROR,
                    code="VALIDATOR_FAILURE",
                    message=f"Validator '{v.name}' crashed – results incomplete",
                )
            )
    return results
