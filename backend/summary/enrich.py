"""Enrich parsed sections with properties and hierarchical taxonomy."""

from __future__ import annotations

from typing import Any

from model.objects import CommonModel, ParsedSection
from model.taxonomy import (
    CATEGORY_DISPLAY,
    CATEGORY_OF_LEAF,
    LEAF_DISPLAY,
    LEAF_ORDER,
    resolve_leaf,
)


# Internal parser bookkeeping — never show as table columns
_META_SKIP_KEYS = {
    "source",  # e.g. migrate_server / gaia_show_configuration
    "kind",
    "action_name",
    "profiles",
    "cp_class",
    "mask_length",
    "management",  # boolean flag; prefer explicit labels if needed
    "link_speed",
    "gateway",  # internal nested; routes already have Gateway field
    "has_password",
    "password_locked",
    "shell",
    "uid",
    "homedir",
    "realname",
    "aaa_order",
    "radius",
    "tacacs",
}

_FILE_SOURCE_VALUES = {
    "migrate_server",
    "gaia_show_configuration",
    "fortigate",
    "primary",
    "other",
}


def _stringify_prop(v: Any) -> Any:
    if v is None or v == "" or v == [] or v == {}:
        return None
    # Enums (including str Enums like PolicyAction)
    try:
        from enum import Enum

        if isinstance(v, Enum):
            return v.value
    except Exception:  # noqa: BLE001
        pass
    if isinstance(v, list) and v and isinstance(v[0], dict) and "name" in v[0]:
        return [x.get("name") for x in v]
    if isinstance(v, dict) and "name" in v:
        return v["name"]
    return v


def _props_from_obj(obj: Any) -> dict[str, Any]:
    skip = {
        "id",
        "source_raw",
        "metadata",
        "tags",
        "source_vendor",
        "source_ref",
        "unsupported",
        "unsupported_reason",
    }
    props: dict[str, Any] = {}
    data = obj.model_dump() if hasattr(obj, "model_dump") else {}
    for k, v in data.items():
        if k in skip or v is None or v == [] or v == {} or v == "":
            continue
        if k == "name":
            props["Name"] = v
            continue
        label = k.replace("_", " ").title()
        # Prefer human field names for addresses on policies
        if label == "Source Addresses":
            label = "Source"
        elif label == "Destination Addresses":
            label = "Destination"
        val = _stringify_prop(v)
        if val is None:
            continue
        props[label] = val

    meta = getattr(obj, "metadata", None) or {}
    # Flatten nested profile map first (keeps AV Profile / IPS Sensor labels)
    nested = meta.get("profiles")
    if isinstance(nested, dict):
        for pk, pv in nested.items():
            if pv not in (None, "", []):
                props[str(pk)] = pv
    for k, v in meta.items():
        kl = str(k).lower().replace(" ", "_")
        if kl in _META_SKIP_KEYS or k in _META_SKIP_KEYS:
            continue
        if v is None or v == "" or v == [] or v == {}:
            continue
        # Never surface upload/parser origin as a data column
        if isinstance(v, str) and v in _FILE_SOURCE_VALUES:
            continue
        # Preserve human labels that already contain spaces (e.g. "AV Profile")
        if " " in str(k) or (str(k)[:1].isupper() if k else False):
            label = str(k)
        else:
            label = str(k).replace("_", " ").title()
        # Don't let internal meta clobber real config fields
        if label in props and label in (
            "Source",
            "Destination",
            "Services",
            "Action",
            "Name",
            "Gateway",
        ):
            # Only override if existing is empty / Any and meta is richer
            existing = props[label]
            if existing not in (None, "", [], "Any", ["Any"]):
                continue
        if isinstance(v, dict):
            continue
        props[label] = _stringify_prop(v) if not isinstance(v, (str, int, float, bool, list)) else v
    return props


def _normalize_prop_keys(props: dict[str, Any]) -> dict[str, Any]:
    """Collapse duplicate/legacy labels so the UI never shows two Destination columns.

    Check Point historically surfaced both model fields (Source Addresses /
    Destination Addresses) and metadata keys (Source / Destination), which the
    mid-pane treated as separate columns. Always map to one canonical label.
    """
    aliases = {
        "source addresses": "Source",
        "destination addresses": "Destination",
        "original source": "Source",
        "original destination": "Destination",
        "ip addresses": "IPv4",
        "action / profile": "Action / Profile",
        "protected scope": "Protected Scope",
        "policy package": "Policy Package",
        "nat type": "Method",
        "translated source": "Translated Source",
        "translated destination": "Translated Destination",
    }
    out: dict[str, Any] = {}
    by_lower: dict[str, str] = {}  # lower(canon) -> key stored in out
    for k, v in props.items():
        if v is None or v == "" or v == []:
            continue
        # Drop file-origin markers if they slipped through as values
        if isinstance(v, str) and v in _FILE_SOURCE_VALUES:
            continue
        canon = aliases.get(str(k).lower(), k)
        lower = str(canon).lower()
        existing_key = by_lower.get(lower)
        if existing_key is not None:
            existing = out[existing_key]
            # Prefer non-empty / more specific value over "Any" or placeholders
            if existing not in (None, "", [], "Any", ["Any"]):
                continue
            out[existing_key] = v
        else:
            by_lower[lower] = canon
            out[canon] = v
    return out


def _obj_entry(obj: Any) -> dict[str, Any]:
    props = _normalize_prop_keys(_props_from_obj(obj))
    raw = getattr(obj, "source_raw", None) or ""
    preview = (
        props.get("Value")
        or props.get("Action / Profile")
        or props.get("Action")
        or props.get("Destination")
        or props.get("IPv4")
        or props.get("Gateway")
    )
    if isinstance(preview, list):
        preview = ", ".join(str(x) for x in preview)
    return {
        "id": getattr(obj, "id", None),
        "name": getattr(obj, "name", "object"),
        "raw": raw,
        "properties": props,
        "preview": str(preview) if preview else None,
    }


def _merge_objects(*lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lst in lists:
        for o in lst:
            key = str(o.get("id") or o.get("name") or id(o))
            if key in seen:
                continue
            seen.add(key)
            out.append(o)
    return out


def _with_package_dividers(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Insert package-name divider rows between groups of policy/NAT objects.

    Check Point only: objects must carry an explicit Policy Package property.
    FortiGate / Palo Alto do not use policy packages — never invent "Unassigned"
    dividers or "policy package" chrome for those vendors.
    """
    if not objects:
        return objects

    def _pkg(o: dict[str, Any]) -> str | None:
        props = o.get("properties") or {}
        if props.get("is_divider"):
            return None
        for key in ("Policy Package", "policy package"):
            if props.get(key):
                return str(props[key])
        return None

    # Only when at least one real package is set (CP multi-package layouts)
    packages = {_pkg(o) for o in objects}
    packages.discard(None)
    if not packages:
        return objects

    buckets: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for o in objects:
        if (o.get("properties") or {}).get("is_divider"):
            continue
        pkg = _pkg(o) or "Unassigned"
        if pkg not in buckets:
            buckets[pkg] = []
            order.append(pkg)
        buckets[pkg].append(o)

    order.sort(key=lambda p: (p == "Unassigned", p.lower()))
    out: list[dict[str, Any]] = []
    for pkg in order:
        out.append(
            {
                "id": f"__divider__{pkg}",
                "name": pkg,
                "raw": "",
                "preview": "Policy package",
                "properties": {
                    "is_divider": True,
                    "Type": "Policy package",
                    "Policy Package": pkg,
                },
            }
        )
        out.extend(buckets[pkg])
    return out


def enrich_parsed_sections(
    model: CommonModel, existing: list[ParsedSection] | None = None
) -> list[ParsedSection]:
    """Build taxonomy-keyed sections for the explorer (category + leaf)."""
    existing_map = {s.section_type: s for s in (existing or [])}

    # Split threat-prevention / TLS inspection rules from profile applications
    tp_rules = [
        o
        for o in model.applications
        if (o.metadata or {}).get("kind") == "threat_prevention_rule"
        or (o.category or "") == "Threat Prevention Rule"
    ]
    tls_rules = [
        o
        for o in model.applications
        if (o.metadata or {}).get("kind") == "ssl_inspection_rule"
        or (o.category or "") == "TLS Inspection Rule"
    ]
    special_app_ids = {id(o) for o in tp_rules} | {id(o) for o in tls_rules}
    profile_apps = [o for o in model.applications if id(o) not in special_app_ids]

    access_policies = [
        o
        for o in model.policies
        if (o.metadata or {}).get("kind") != "threat_prevention"
        and not str(o.name or "").startswith("[TP]")
    ]

    # Objects from common model by legacy bucket
    model_buckets: dict[str, list[dict[str, Any]]] = {
        "interfaces": [_obj_entry(o) for o in model.interfaces],
        "zones": [_obj_entry(o) for o in model.zones],
        "addresses": [_obj_entry(o) for o in model.addresses],
        "address_groups": [_obj_entry(o) for o in model.address_groups],
        "services": [_obj_entry(o) for o in model.services],
        "service_groups": [_obj_entry(o) for o in model.service_groups],
        "applications": [_obj_entry(o) for o in profile_apps],
        "firewall_policies": _with_package_dividers(
            [_obj_entry(o) for o in access_policies]
        ),
        "threat_policies": _with_package_dividers([_obj_entry(o) for o in tp_rules]),
        "security_inspection": _with_package_dividers(
            [_obj_entry(o) for o in tls_rules]
        ),
        "nat": _with_package_dividers([_obj_entry(o) for o in model.nat_rules]),
        "vip": [_obj_entry(o) for o in model.vips],
        "static_routes": [_obj_entry(o) for o in model.static_routes],
        "bgp": [_obj_entry(o) for o in model.bgp_neighbors],
        "ospf": [_obj_entry(o) for o in model.ospf_processes],
        "dhcp": [_obj_entry(o) for o in model.dhcp_servers],
        "dns": [_obj_entry(o) for o in model.dns_configs],
        "ssl_vpn": [_obj_entry(o) for o in model.ssl_vpns],
        "ipsec": [_obj_entry(o) for o in model.ipsec_tunnels],
        "users": [_obj_entry(o) for o in model.users],
        "groups": [_obj_entry(o) for o in model.groups],
        "schedules": [_obj_entry(o) for o in model.schedules],
        "certificates": [_obj_entry(o) for o in model.certificates],
        "system_settings": [],
        "other": [],
    }

    if model.system:
        model_buckets["system_settings"].append(_obj_entry(model.system))
    elif model.hostname:
        model_buckets["system_settings"].append(
            {
                "id": "hostname",
                "name": "hostname",
                "raw": "",
                "properties": {"Hostname": model.hostname},
                "preview": model.hostname,
            }
        )

    # Fold parser-only sections (and custom leaf keys) into buckets
    for legacy, prev in existing_map.items():
        if not prev.objects:
            continue
        leaf_objs = []
        for o in prev.objects:
            raw_props = o.get("properties") or {
                k: v
                for k, v in o.items()
                if k not in ("id", "name", "raw", "preview", "properties")
            }
            leaf_objs.append(
                {
                    "id": o.get("id"),
                    "name": o.get("name", "object"),
                    "raw": o.get("raw") or o.get("preview") or "",
                    # Normalize so CP "Original Destination" / "Destination Addresses"
                    # never become a second Destination column beside model objects.
                    "properties": _normalize_prop_keys(dict(raw_props or {})),
                    "preview": o.get("preview"),
                }
            )
        key = legacy
        if not model_buckets.get(key):
            model_buckets[key] = leaf_objs
        else:
            names = {x.get("name") for x in model_buckets[key]}
            for o in leaf_objs:
                if o.get("name") not in names:
                    model_buckets[key].append(o)

    # Aggregate into taxonomy leaves
    leaf_objects: dict[str, list[dict[str, Any]]] = {leaf: [] for leaf in LEAF_ORDER}
    leaf_errors: dict[str, list[str]] = {leaf: [] for leaf in LEAF_ORDER}
    leaf_ok: dict[str, bool] = {leaf: True for leaf in LEAF_ORDER}
    # Preserve complete parser config…end blocks (never truncate to 40 objects)
    leaf_raw_snippets: dict[str, list[str]] = {leaf: [] for leaf in LEAF_ORDER}

    for legacy, objs in model_buckets.items():
        leaf = resolve_leaf(legacy)
        leaf_objects[leaf] = _merge_objects(leaf_objects.get(leaf, []), objs)
        prev = existing_map.get(legacy)
        if prev:
            leaf_errors[leaf].extend(prev.errors or [])
            if not prev.parsed_ok:
                leaf_ok[leaf] = False
            for snip in prev.raw_snippets or []:
                text = str(snip).strip() if snip else ""
                if text and text not in leaf_raw_snippets[leaf]:
                    leaf_raw_snippets[leaf].append(text)

    def _snippet_edit_count(text: str) -> int:
        import re

        return len(re.findall(r"^\s*edit\s+", text or "", flags=re.I | re.M))

    def _raw_snippets_for_leaf(leaf: str, objects: list[dict[str, Any]]) -> list[str]:
        """Prefer full multi-edit config blocks; else every object raw (no cap)."""
        collected = list(leaf_raw_snippets.get(leaf) or [])
        multi = [s for s in collected if _snippet_edit_count(s) > 1]
        if multi:
            return multi
        # Fall back to all per-object raws so left pane never drops table rows
        obj_raws = [
            str(o.get("raw")).strip()
            for o in objects
            if o.get("raw")
            and not (o.get("properties") or {}).get("is_divider")
        ]
        # Keep multi-edit snippets first, then any single-edit leftovers not already covered
        if collected and not multi:
            # Parser stored only single-edit wraps — use object raws instead (complete set)
            return obj_raws or collected
        return obj_raws or collected

    result: list[ParsedSection] = []
    for leaf in LEAF_ORDER:
        objects = leaf_objects.get(leaf, [])
        # Prefer non-empty raw from either side when merging left table completeness
        result.append(
            ParsedSection(
                section_type=leaf,
                display_name=LEAF_DISPLAY[leaf],
                object_count=len(
                    [
                        o
                        for o in objects
                        if not (o.get("properties") or {}).get("is_divider")
                    ]
                ),
                parsed_ok=leaf_ok.get(leaf, True),
                objects=objects,
                raw_snippets=_raw_snippets_for_leaf(leaf, objects),
                errors=leaf_errors.get(leaf, []),
            )
        )

    # Attach category using dynamic attributes via model_dump extra — update ParsedSection
    # We'll set via model_copy after ensuring fields exist
    enriched: list[ParsedSection] = []
    for s in result:
        leaf = s.section_type
        data = s.model_dump()
        data["category"] = CATEGORY_OF_LEAF.get(leaf, "other")
        data["category_display"] = CATEGORY_DISPLAY.get(
            CATEGORY_OF_LEAF.get(leaf, "other"), "Other"
        )
        enriched.append(ParsedSection.model_validate(data))

    return enriched


def taxonomy_outline() -> list[dict[str, Any]]:
    return [
        {
            "id": cat_id,
            "name": cat_name,
            "children": [{"id": lid, "name": lname} for lid, lname in children],
        }
        for cat_id, cat_name, children in CATEGORY_TREE
    ]
