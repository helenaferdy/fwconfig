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
        if isinstance(v, list) and v and isinstance(v[0], dict) and "name" in v[0]:
            props[label] = [x.get("name") for x in v]
        elif isinstance(v, dict) and "name" in v:
            props[label] = v["name"]
        else:
            props[label] = v
    meta = getattr(obj, "metadata", None) or {}
    # Flatten nested profile map first (keeps AV Profile / IPS Sensor labels)
    nested = meta.get("profiles")
    if isinstance(nested, dict):
        for pk, pv in nested.items():
            if pv not in (None, "", []):
                props[str(pk)] = pv
    for k, v in meta.items():
        if k == "profiles":
            continue
        if v is None or v == "" or v == [] or v == {}:
            continue
        # Preserve human labels that already contain spaces (e.g. "AV Profile")
        if " " in k or k[:1].isupper():
            label = k
        else:
            label = k.replace("_", " ").title()
        if isinstance(v, dict):
            # Avoid dumping nested dict blobs into properties
            continue
        props[label] = v
    return props


def _obj_entry(obj: Any) -> dict[str, Any]:
    props = _props_from_obj(obj)
    raw = getattr(obj, "source_raw", None) or ""
    preview = (
        props.get("Value")
        or props.get("Action")
        or props.get("Destination")
        or props.get("Ip Addresses")
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


def enrich_parsed_sections(
    model: CommonModel, existing: list[ParsedSection] | None = None
) -> list[ParsedSection]:
    """Build taxonomy-keyed sections for the explorer (category + leaf)."""
    existing_map = {s.section_type: s for s in (existing or [])}

    # Objects from common model by legacy bucket
    model_buckets: dict[str, list[dict[str, Any]]] = {
        "interfaces": [_obj_entry(o) for o in model.interfaces],
        "zones": [_obj_entry(o) for o in model.zones],
        "addresses": [_obj_entry(o) for o in model.addresses],
        "address_groups": [_obj_entry(o) for o in model.address_groups],
        "services": [_obj_entry(o) for o in model.services],
        "service_groups": [_obj_entry(o) for o in model.service_groups],
        "applications": [_obj_entry(o) for o in model.applications],
        "firewall_policies": [_obj_entry(o) for o in model.policies],
        "nat": [_obj_entry(o) for o in model.nat_rules],
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
            leaf_objs.append(
                {
                    "id": o.get("id"),
                    "name": o.get("name", "object"),
                    "raw": o.get("raw") or o.get("preview") or "",
                    "properties": o.get("properties")
                    or {
                        k: v
                        for k, v in o.items()
                        if k not in ("id", "name", "raw", "preview", "properties")
                    },
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

    for legacy, objs in model_buckets.items():
        leaf = resolve_leaf(legacy)
        leaf_objects[leaf] = _merge_objects(leaf_objects.get(leaf, []), objs)
        prev = existing_map.get(legacy)
        if prev:
            leaf_errors[leaf].extend(prev.errors or [])
            if not prev.parsed_ok:
                leaf_ok[leaf] = False

    result: list[ParsedSection] = []
    for leaf in LEAF_ORDER:
        cat = CATEGORY_OF_LEAF[leaf]
        objects = leaf_objects.get(leaf, [])
        result.append(
            ParsedSection(
                section_type=leaf,
                display_name=LEAF_DISPLAY[leaf],
                object_count=len(objects),
                parsed_ok=leaf_ok.get(leaf, True),
                objects=objects,
                raw_snippets=[o["raw"] for o in objects if o.get("raw")][:40],
                errors=leaf_errors.get(leaf, []),
                # extra fields via model - ParsedSection may need category fields
            )
        )
        # attach category as soft fields on objects list is not ideal;
        # store on section via metadata pattern: put in errors? Better extend model.

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
