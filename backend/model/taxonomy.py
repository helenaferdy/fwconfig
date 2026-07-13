"""Hierarchical configuration categorization for explorer + summaries.

Tree is fixed for all vendors. Leaf ids are stable section_type keys used
for left/middle pane synchronization.
"""

from __future__ import annotations

from typing import Any


# (category_id, category_name, [(leaf_id, leaf_name), ...])
CATEGORY_TREE: list[tuple[str, str, list[tuple[str, str]]]] = [
    (
        "system",
        "System",
        [
            ("system_general", "General"),
            ("system_management", "Management"),
            ("system_services", "Services"),
            ("system_other", "Other"),
        ],
    ),
    (
        "network",
        "Network",
        [
            ("network_interfaces", "Interfaces"),
            ("network_zones", "Zones"),
            ("network_dhcp", "DHCP"),
            ("network_other", "Other"),
        ],
    ),
    (
        "objects",
        "Objects",
        [
            ("objects_addresses", "Addresses"),
            ("objects_address_groups", "Address Groups"),
            ("objects_services", "Services"),
            ("objects_service_groups", "Service Groups"),
            ("objects_other", "Other"),
        ],
    ),
    (
        "routing",
        "Routing",
        [
            ("routing_static", "Static"),
            ("routing_dynamic", "Dynamic"),
            ("routing_policy", "Policy Routing"),
            ("routing_other", "Other"),
        ],
    ),
    (
        "policies",
        "Policies",
        [
            ("policies_security", "Security Policies"),
            ("policies_nat", "NAT"),
            ("policies_auth", "Authentication"),
            ("policies_other", "Other"),
        ],
    ),
    (
        "vpn",
        "VPN",
        [
            ("vpn_ipsec", "IPsec"),
            ("vpn_ssl", "SSL VPN"),
            ("vpn_other", "Other"),
        ],
    ),
    (
        "security",
        "Security",
        [
            ("security_profiles", "Profiles"),
            ("security_inspection", "Inspection"),
            ("security_other", "Other"),
        ],
    ),
    (
        "users",
        "Users",
        [
            ("users_users", "Users"),
            ("users_groups", "Groups"),
            ("users_external_auth", "External Authentication"),
            ("users_other", "Other"),
        ],
    ),
    (
        "diagnostics",
        "Diagnostics",
        [
            ("diagnostics_logging", "Logging"),
            ("diagnostics_monitoring", "Monitoring"),
            ("diagnostics_ha", "High Availability"),
            ("diagnostics_other", "Other"),
        ],
    ),
    (
        "other",
        "Other",
        [
            ("other_unclassified", "Unclassified"),
            ("other_unsupported", "Unsupported"),
            ("other_unknown", "Unknown"),
        ],
    ),
]

# Flattened leaf order for pipeline / API
LEAF_ORDER: list[str] = [
    leaf_id for _, _, children in CATEGORY_TREE for leaf_id, _ in children
]

LEAF_DISPLAY: dict[str, str] = {
    leaf_id: leaf_name for _, _, children in CATEGORY_TREE for leaf_id, leaf_name in children
}

CATEGORY_OF_LEAF: dict[str, str] = {
    leaf_id: cat_id for cat_id, _, children in CATEGORY_TREE for leaf_id, _ in children
}

CATEGORY_DISPLAY: dict[str, str] = {cat_id: name for cat_id, name, _ in CATEGORY_TREE}

# Map legacy / parser section keys → taxonomy leaf
LEGACY_TO_LEAF: dict[str, str] = {
    "interfaces": "network_interfaces",
    "zones": "network_zones",
    "dhcp": "network_dhcp",
    "addresses": "objects_addresses",
    "address_groups": "objects_address_groups",
    "services": "objects_services",
    "service_groups": "objects_service_groups",
    "applications": "security_profiles",
    "firewall_policies": "policies_security",
    "nat": "policies_nat",
    "vip": "policies_nat",
    "static_routes": "routing_static",
    "bgp": "routing_dynamic",
    "ospf": "routing_dynamic",
    "ssl_vpn": "vpn_ssl",
    "ipsec": "vpn_ipsec",
    "users": "users_users",
    "groups": "users_groups",
    "schedules": "objects_other",
    "certificates": "system_other",
    "system_settings": "system_general",
    "system_admin": "system_management",
    "dns": "system_services",
    "other": "other_unclassified",
    # already leaf ids
    **{leaf: leaf for leaf in LEAF_ORDER},
}


def resolve_leaf(section_type: str) -> str:
    return LEGACY_TO_LEAF.get(section_type, "other_unclassified")


def taxonomy_tree_for_api() -> list[dict[str, Any]]:
    return [
        {
            "id": cat_id,
            "name": cat_name,
            "children": [
                {"id": leaf_id, "name": leaf_name} for leaf_id, leaf_name in children
            ],
        }
        for cat_id, cat_name, children in CATEGORY_TREE
    ]
