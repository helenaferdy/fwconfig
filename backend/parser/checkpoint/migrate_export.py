"""Parse Check Point `migrate_server export` .tgz (R8x DLE NDJSON).

Management-plane: hosts, networks, gateway, policy packages, access + NAT rules,
threat prevention (profiles, rules, IPS/AV/TE blade settings).
"""

from __future__ import annotations

import io
import json
import logging
import re
import tarfile
from pathlib import Path
from typing import Any

from model.enums import AddressType, PolicyAction, SectionType, ServiceProtocol, Vendor
from model.objects import (
    Address,
    AddressGroup,
    Application,
    CommonModel,
    FirewallPolicy,
    Interface,
    NamedReference,
    NATRule,
    ParsedSection,
    Service,
    ServiceGroup,
)

logger = logging.getLogger(__name__)

_VENDOR = Vendor.CHECKPOINT.value

# Well-known global object UIDs in Check Point databases
_WELL_KNOWN: dict[str, str] = {
    "97aeb369-9aea-11d5-bd16-0090272ccb30": "Any",
    "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c": "Original",
    "97aeb369-9aea-11d5-bd16-0090272ccb31": "None",
    "6c488338-8eec-4103-ad21-cd461ac2c472": "Accept",
    "6c488338-8eec-4103-ad21-cd461ac2c473": "Drop",
    "6c488338-8eec-4103-ad21-cd461ac2c474": "Reject",
    "6c488338-8eec-4103-ad21-cd461ac2c476": "Policy Targets",
    "6c488338-8eec-4103-ad21-cd461ac2c477": "Log",
    # Common threat-prevention action / profile references seen in exports
    "fa1aa324-a8cc-4dbd-bc04-f31fdb8abf61": "Optimized",
    "eb39a60d-c454-49f5-a28c-a89aa5bd2e09": "Strict",
    "5d5500c7-bdcb-42eb-bb49-ad4ee802f62c": "Inactive",
}

# Baseline class files we parse (filename suffix)
_OBJECT_CLASS_FILES = {
    "com.checkpoint.objects.classes.dummy.CpmiHostPlain.data": "host",
    "com.checkpoint.objects.classes.dummy.CpmiHostCkp.data": "host_ckp",
    "com.checkpoint.objects.classes.dummy.CpmiNetwork.data": "network",
    "com.checkpoint.objects.classes.dummy.CpmiNetworkObjectGroup.data": "addr_group",
    "com.checkpoint.objects.classes.dummy.CpmiGatewayCkp.data": "gateway",
    "com.checkpoint.objects.classes.dummy.CpmiTcpService.data": "svc_tcp",
    "com.checkpoint.objects.classes.dummy.CpmiUdpService.data": "svc_udp",
    "com.checkpoint.objects.classes.dummy.CpmiIcmpService.data": "svc_icmp",
    "com.checkpoint.objects.classes.dummy.CpmiOtherService.data": "svc_other",
    "com.checkpoint.objects.classes.dummy.CpmiServiceGroup.data": "svc_group",
    "com.checkpoint.management.policy_package.objects.policy_package.PolicyPackage.data": "package",
    "com.checkpoint.management.access.objects.access_rulebase.AccessPolicyContainer.data": "access_container",
    "com.checkpoint.management.access.objects.access_rulebase.AccessPolicy.data": "access_policy",
    "com.checkpoint.management.access.objects.nat_rulebase.NatPolicy.data": "nat_policy",
    "com.checkpoint.objects.appfw.dummy.CpmiAppfwAppCategory.data": "app_category",
    "com.checkpoint.objects.appfw.dummy.CpmiAppfwApplication.data": "app_application",
    # Threat Prevention / IPS / AV / TE
    "com.checkpoint.objects.threat_prevention.ThreatPreventionProfile.data": "tp_profile",
    "com.checkpoint.objects.threat_prevention.SimplifiedThreatPolicy.data": "tp_simple_policy",
    "com.checkpoint.objects.threat_rulebase.ThreatPolicy.data": "tp_policy",
    "com.checkpoint.objects.classes.dummy.CpmiAsmIpsSettings.data": "ips_settings",
    "com.checkpoint.objects.ips_classes.dummy.CpmiIpsGlobalEnvironmentSettings.data": "ips_global",
    "com.checkpoint.objects.anti_malware.dummy.CpmiAntimalwareGeneralSettings.data": "amw_general",
    "com.checkpoint.objects.anti_malware.dummy.CpmiAntimalwareBladeGatewaySettings.data": "amw_gw",
    "com.checkpoint.objects.content_security_classes.dummy.CpmiAvSettings.data": "av_settings",
    "com.checkpoint.objects.threat_emulation.dummy.CpmiTeGeneralSettings.data": "te_general",
    "com.checkpoint.objects.threat_emulation.dummy.CpmiThreatEmulationBladeGatewaySettings.data": "te_gw",
    "com.checkpoint.objects.threat_emulation.dummy.CpmiTeFileTypeSupport.data": "te_filetypes",
    "com.checkpoint.objects.scrubbing.dummy.CpmiSbGeneralSettings.data": "tex_scrub",
}

_THREAT_RULE_TYPES = {
    "ThreatRule",
    "ThreatExceptionRule",
}


def is_migrate_server_tgz(data: bytes) -> bool:
    if not data or len(data) < 100:
        return False
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            names = tf.getnames()[:80]
    except Exception:  # noqa: BLE001
        return False
    blob = "\n".join(names)
    return (
        "com.checkpoint.management" in blob
        or "DomainBase.data" in blob
        or "/baseline/" in blob
        or "extra_data/MachineTypeData.data" in blob
    )


def _java_unwrap(obj: Any) -> Any:
    """Unwrap [\"java.Type\", payload] wrappers recursively (shallow helpers use this)."""
    if isinstance(obj, list) and len(obj) == 2 and isinstance(obj[0], str):
        # Collection types
        if obj[0].startswith("java.util."):
            inner = obj[1]
            if isinstance(inner, list):
                return [_java_unwrap(x) for x in inner]
            if isinstance(inner, dict):
                return {k: _java_unwrap(v) for k, v in inner.items()}
            return _java_unwrap(inner)
        # Typed object [className, dict]
        if isinstance(obj[1], dict):
            return obj  # keep type+body for callers that need class
        return _java_unwrap(obj[1])
    if isinstance(obj, dict):
        return {k: _java_unwrap(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_java_unwrap(x) for x in obj]
    return obj


def _typed_body(obj: Any) -> tuple[str | None, dict[str, Any]]:
    if isinstance(obj, list) and len(obj) == 2 and isinstance(obj[0], str) and isinstance(obj[1], dict):
        return obj[0], obj[1]
    if isinstance(obj, dict):
        return None, obj
    return None, {}


def _collect_uuids(node: Any, out: list[str] | None = None) -> list[str]:
    out = out if out is not None else []
    if isinstance(node, str) and re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        node,
    ):
        out.append(node)
    elif isinstance(node, list):
        if len(node) == 2 and isinstance(node[0], str) and node[0].startswith("java.util."):
            _collect_uuids(node[1], out)
        else:
            for x in node:
                _collect_uuids(x, out)
    elif isinstance(node, dict):
        for v in node.values():
            _collect_uuids(v, out)
    return out


def _field_uuids(field: Any) -> list[str]:
    """Extract member UUIDs from AccessRule src/dst/svc/app field wrappers."""
    if field is None:
        return []
    cls, body = _typed_body(field)
    if body:
        for key in (
            "srcs",
            "dsts",
            "svcs",
            "applications",
            "members",
            "objects",
            "scope",
        ):
            if key in body:
                return _collect_uuids(body[key])
    return _collect_uuids(field)


def _resolve_names(uids: list[str], index: dict[str, dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for u in uids:
        if u in _WELL_KNOWN:
            names.append(_WELL_KNOWN[u])
        elif u in index:
            names.append(str(index[u].get("name") or u))
        else:
            names.append(u[:8] + "…")
    return names or ["Any"]


def _obj_entry(
    oid: str,
    name: str,
    raw: str,
    props: dict[str, Any],
    preview: str | None = None,
) -> dict[str, Any]:
    clean = {k: v for k, v in props.items() if v not in (None, "", [])}
    return {
        "id": oid,
        "name": name,
        "raw": raw,
        "properties": clean,
        "preview": preview or name,
    }


def _iter_ndjson_member(tf: tarfile.TarFile, member: tarfile.TarInfo) -> list[Any]:
    f = tf.extractfile(member)
    if not f:
        return []
    raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    rows: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "[{":
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _pick_local_domain(tf: tarfile.TarFile) -> str | None:
    """Return domain UUID folder with the largest baseline (LocalDomain)."""
    counts: dict[str, int] = {}
    for name in tf.getnames():
        m = re.match(
            r"^\.?/?([0-9a-fA-F-]{36})/baseline/",
            name,
        )
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    if not counts:
        return None
    # Prefer LocalDomain from DomainBase if present
    for name in tf.getnames():
        if name.endswith("DomainBase.data"):
            for row in _iter_ndjson_member(tf, tf.getmember(name)):
                cls, body = _typed_body(row)
                if cls and "LocalDomain" in cls and body.get("objId"):
                    oid = str(body["objId"])
                    if oid in counts:
                        return oid
    return max(counts.items(), key=lambda kv: kv[1])[0]


def parse_migrate_tgz(data: bytes, model: CommonModel) -> tuple[list[ParsedSection], list[dict]]:
    """Parse migrate_server export bytes into model + sections."""
    warnings: list[dict] = []
    sections: list[ParsedSection] = []
    index: dict[str, dict[str, Any]] = {
        uid: {"name": name, "kind": "global"} for uid, name in _WELL_KNOWN.items()
    }

    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception as exc:  # noqa: BLE001
        warnings.append(
            {
                "code": "CP_TGZ_OPEN",
                "message": f"Failed to open migrate_server export: {exc}",
                "severity": "error",
            }
        )
        return sections, warnings

    with tf:
        domain_id = _pick_local_domain(tf)
        if not domain_id:
            warnings.append(
                {
                    "code": "CP_NO_DOMAIN",
                    "message": "No LocalDomain baseline found in migrate_server export",
                    "severity": "error",
                }
            )
            return sections, warnings

        baseline_prefix = f"{domain_id}/baseline/"
        # Also handle ./uuid/baseline/
        members = [
            m
            for m in tf.getmembers()
            if m.isfile()
            and (
                f"/{domain_id}/baseline/" in f"/{m.name}"
                or m.name.startswith(baseline_prefix)
                or m.name.startswith(f"./{baseline_prefix}")
            )
        ]
        # Application categories / apps live in the APPI data domain (shared catalog)
        app_suffixes = (
            "CpmiAppfwAppCategory.data",
            "CpmiAppfwApplication.data",
            "DbIndexAppfwObject.data",
        )
        for m in tf.getmembers():
            if not m.isfile():
                continue
            base = Path(m.name).name
            if any(base.endswith(s) for s in app_suffixes):
                if m not in members:
                    members.append(m)

        # ---- pass 1: index objects ----
        host_rows: list[dict[str, Any]] = []
        net_rows: list[dict[str, Any]] = []
        gw_rows: list[dict[str, Any]] = []
        group_rows: list[dict[str, Any]] = []
        svc_rows: list[dict[str, Any]] = []
        svc_group_rows: list[dict[str, Any]] = []
        package_rows: list[dict[str, Any]] = []
        tp_profile_rows: list[dict[str, Any]] = []
        tp_policy_rows: list[dict[str, Any]] = []
        tp_blade_rows: list[dict[str, Any]] = []
        package_link_rows: list[dict[str, Any]] = []  # package / access / nat / threat policy links
        access_rules: list[dict[str, Any]] = []
        nat_rules: list[dict[str, Any]] = []
        threat_rules: list[dict[str, Any]] = []
        rulebase_meta: list[dict[str, Any]] = []

        for member in members:
            base = Path(member.name).name
            kind = _OBJECT_CLASS_FILES.get(base)
            if kind:
                for row in _iter_ndjson_member(tf, member):
                    cls, body = _typed_body(row)
                    if not body:
                        continue
                    oid = str(body.get("objId") or "")
                    name = str(body.get("name") or body.get("displayName") or oid or "object")
                    if oid:
                        index[oid] = {
                            "name": name,
                            "kind": kind,
                            "class": cls,
                            "ipaddr": body.get("ipaddr"),
                            "netmask": body.get("netmask"),
                            "body": body,
                        }
                    rec = {"objId": oid, "name": name, "class": cls, "body": body, "kind": kind}
                    if kind in ("host", "host_ckp"):
                        host_rows.append(rec)
                    elif kind == "network":
                        net_rows.append(rec)
                    elif kind == "gateway":
                        gw_rows.append(rec)
                    elif kind == "addr_group":
                        group_rows.append(rec)
                    elif kind.startswith("svc_") and kind != "svc_group":
                        svc_rows.append(rec)
                    elif kind == "svc_group":
                        svc_group_rows.append(rec)
                    elif kind in (
                        "package",
                        "access_container",
                        "access_policy",
                        "nat_policy",
                        "tp_policy",
                        "tp_simple_policy",
                    ):
                        package_link_rows.append(rec)
                        if kind == "package":
                            package_rows.append(rec)
                        if kind in ("tp_simple_policy", "tp_policy"):
                            tp_policy_rows.append(rec)
                    elif kind in ("app_category", "app_application"):
                        pass  # already in index
                    elif kind == "tp_profile":
                        tp_profile_rows.append(rec)
                    elif kind.startswith(("ips_", "amw_", "av_", "te_", "tex_")):
                        tp_blade_rows.append(rec)
                continue

            if "/rulebases/" in member.name and member.name.endswith(".data"):
                for row in _iter_ndjson_member(tf, member):
                    cls, body = _typed_body(row)
                    if not body:
                        continue
                    rbo = body.get("rulebaseObject")
                    rcls, rbody = _typed_body(rbo)
                    if not rbody:
                        continue
                    short = (rcls or "").split(".")[-1]
                    if short == "AccessCtrlRule":
                        access_rules.append(rbody)
                    elif short == "NatRule":
                        nat_rules.append(rbody)
                    elif short in _THREAT_RULE_TYPES:
                        threat_rules.append(rbody)
                    elif short in (
                        "AccessCtrlRulebase",
                        "NatRulebase",
                        "ThreatRulebase",
                        "ThreatExceptionRulebase",
                    ):
                        rulebase_meta.append(
                            {
                                "type": short,
                                "name": rbody.get("name"),
                                "objId": rbody.get("objId"),
                                "owner": rbody.get("owner"),
                                "parent": rbody.get("parent"),
                            }
                        )

        def _dedupe_by_objid(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            seen: set[str] = set()
            out: list[dict[str, Any]] = []
            for body in rows:
                oid = str(body.get("objId") or "")
                key = oid or f"{body.get('name')}:{body.get('position')}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(body)
            return out

        access_rules = _dedupe_by_objid(access_rules)
        nat_rules = _dedupe_by_objid(nat_rules)
        threat_rules = _dedupe_by_objid(threat_rules)

        # ---- Map rulebase / layer UID → policy package name ----
        # package → accessPolicyContainer → accessPolicy.layers / natPolicy.rulebase
        # package → threatPolicy.layers
        access_policy_by_id: dict[str, dict[str, Any]] = {}
        nat_policy_by_id: dict[str, dict[str, Any]] = {}
        access_container_by_id: dict[str, dict[str, Any]] = {}
        threat_policy_by_id: dict[str, dict[str, Any]] = {}
        packages: list[dict[str, Any]] = []
        for rec in package_link_rows:
            kind = rec.get("kind")
            body = rec["body"]
            oid = rec["objId"]
            if kind == "package":
                packages.append(rec)
            elif kind == "access_container":
                access_container_by_id[oid] = body
            elif kind == "access_policy":
                access_policy_by_id[oid] = body
            elif kind == "nat_policy":
                nat_policy_by_id[oid] = body
            elif kind == "tp_policy":
                threat_policy_by_id[oid] = body

        rulebase_to_package: dict[str, str] = {}
        rulebase_to_layer_name: dict[str, str] = {
            str(r["objId"]): str(r.get("name") or r["objId"])
            for r in rulebase_meta
            if r.get("objId")
        }

        for rec in packages:
            body = rec["body"]
            pkg_name = rec["name"] or "Unassigned"
            # Access layers via container → access policy → layers
            cont_id = str(body.get("accessPolicyContainer") or "")
            cont = access_container_by_id.get(cont_id) or {}
            ap_id = str(cont.get("accessPolicy") or "")
            ap = access_policy_by_id.get(ap_id) or {}
            for lid in _collect_uuids(ap.get("layers")):
                rulebase_to_package[lid] = pkg_name
            # NAT
            nat_id = str(cont.get("natPolicy") or "")
            np = nat_policy_by_id.get(nat_id) or {}
            rb = np.get("rulebase")
            if rb:
                rulebase_to_package[str(rb)] = pkg_name
            # Threat policy layers
            tp_id = str(body.get("threatPolicy") or "")
            tp = threat_policy_by_id.get(tp_id) or {}
            for lid in _collect_uuids(tp.get("layers")):
                rulebase_to_package[lid] = pkg_name

        # Exception sub-rulebases inherit package from their owning threat layer
        for r in rulebase_meta:
            oid = str(r.get("objId") or "")
            owner = str(r.get("owner") or "")
            if oid and owner and oid not in rulebase_to_package and owner in rulebase_to_package:
                rulebase_to_package[oid] = rulebase_to_package[owner]
            if oid and r.get("name"):
                rulebase_to_layer_name.setdefault(oid, str(r["name"]))

        def _pkg_for_rule(body: dict[str, Any]) -> tuple[str, str]:
            owner = str(body.get("owner") or "")
            parent = str(body.get("parent") or "")
            pkg = (
                rulebase_to_package.get(owner)
                or rulebase_to_package.get(parent)
                or "Unassigned"
            )
            layer = (
                rulebase_to_layer_name.get(owner)
                or rulebase_to_layer_name.get(parent)
                or (owner[:8] if owner else "—")
            )
            return pkg, layer

        # ---- materialize addresses ----
        addr_objects: list[dict[str, Any]] = []
        for rec in host_rows + [
            r for r in gw_rows
        ]:  # gw also as address-like host
            body = rec["body"]
            name = rec["name"]
            ip = body.get("ipaddr")
            if not ip and rec in gw_rows:
                continue
            # skip pure gateway from host list if also in host_rows
            kind = "host"
            at = AddressType.IP_HOST
            raw = json.dumps(
                {"name": name, "ipaddr": ip, "objId": rec["objId"]},
                default=str,
            )
            addr = Address(
                name=name,
                address_type=at,
                value=str(ip) if ip else name,
                source_vendor=_VENDOR,
                source_ref=rec["objId"],
                source_raw=raw,
                metadata={"cp_class": rec.get("class"), "source": "migrate_server"},
            )
            model.addresses.append(addr)
            addr_objects.append(
                _obj_entry(
                    addr.id,
                    name,
                    raw,
                    {"Name": name, "IP": ip, "Type": "host", "UID": rec["objId"]},
                    preview=str(ip) if ip else name,
                )
            )

        for rec in net_rows:
            body = rec["body"]
            name = rec["name"]
            ip = body.get("ipaddr")
            mask = body.get("netmask")
            value = f"{ip}/{mask}" if ip and mask else (str(ip) if ip else name)
            raw = json.dumps(
                {"name": name, "ipaddr": ip, "netmask": mask, "objId": rec["objId"]},
                default=str,
            )
            addr = Address(
                name=name,
                address_type=AddressType.IP_NETWORK,
                value=value,
                source_vendor=_VENDOR,
                source_ref=rec["objId"],
                source_raw=raw,
                metadata={"source": "migrate_server"},
            )
            model.addresses.append(addr)
            addr_objects.append(
                _obj_entry(
                    addr.id,
                    name,
                    raw,
                    {"Name": name, "Network": ip, "Mask": mask, "UID": rec["objId"]},
                    preview=value,
                )
            )

        sections.append(
            ParsedSection(
                section_type=SectionType.ADDRESSES.value,
                display_name=SectionType.ADDRESSES.display_name,
                object_count=len(addr_objects),
                parsed_ok=True,
                objects=addr_objects,
            )
        )

        # ---- address groups ----
        grp_objects: list[dict[str, Any]] = []
        for rec in group_rows:
            body = rec["body"]
            name = rec["name"]
            members = _resolve_names(_collect_uuids(body.get("members") or body.get("member")), index)
            raw = json.dumps({"name": name, "members": members, "objId": rec["objId"]}, default=str)
            grp = AddressGroup(
                name=name,
                members=[NamedReference(name=m, kind="address") for m in members],
                source_vendor=_VENDOR,
                source_ref=rec["objId"],
                source_raw=raw,
            )
            model.address_groups.append(grp)
            grp_objects.append(
                _obj_entry(
                    grp.id,
                    name,
                    raw,
                    {"Name": name, "Members": members, "UID": rec["objId"]},
                    preview=f"{len(members)} members",
                )
            )
        sections.append(
            ParsedSection(
                section_type=SectionType.ADDRESS_GROUPS.value,
                display_name=SectionType.ADDRESS_GROUPS.display_name,
                object_count=len(grp_objects),
                parsed_ok=True,
                objects=grp_objects,
            )
        )

        # ---- services ----
        svc_objects: list[dict[str, Any]] = []
        for rec in svc_rows:
            body = rec["body"]
            name = rec["name"]
            port = body.get("port") or body.get("port1") or body.get("port2")
            proto = ServiceProtocol.TCP
            cls = (rec.get("class") or "").lower()
            if "udp" in cls:
                proto = ServiceProtocol.UDP
            elif "icmp" in cls:
                proto = ServiceProtocol.ICMP
            ports = [str(port)] if port not in (None, "") else []
            raw = json.dumps(
                {"name": name, "port": port, "objId": rec["objId"]}, default=str
            )
            svc = Service(
                name=name,
                protocol=proto,
                destination_ports=ports,
                source_vendor=_VENDOR,
                source_ref=rec["objId"],
                source_raw=raw,
            )
            model.services.append(svc)
            svc_objects.append(
                _obj_entry(
                    svc.id,
                    name,
                    raw,
                    {"Name": name, "Protocol": proto.value, "Port": port, "UID": rec["objId"]},
                    preview=f"{proto.value} {port}" if port else name,
                )
            )
        sections.append(
            ParsedSection(
                section_type=SectionType.SERVICES.value,
                display_name=SectionType.SERVICES.display_name,
                object_count=len(svc_objects),
                parsed_ok=True,
                objects=svc_objects,
            )
        )

        # ---- service groups ----
        sg_objects: list[dict[str, Any]] = []
        for rec in svc_group_rows:
            body = rec["body"]
            name = rec["name"]
            members = _resolve_names(_collect_uuids(body.get("members")), index)
            raw = json.dumps({"name": name, "members": members}, default=str)
            sg = ServiceGroup(
                name=name,
                members=[NamedReference(name=m, kind="service") for m in members],
                source_vendor=_VENDOR,
                source_ref=rec["objId"],
                source_raw=raw,
            )
            model.service_groups.append(sg)
            sg_objects.append(
                _obj_entry(
                    sg.id,
                    name,
                    raw,
                    {"Name": name, "Members": members},
                    preview=f"{len(members)} members",
                )
            )
        sections.append(
            ParsedSection(
                section_type=SectionType.SERVICE_GROUPS.value,
                display_name=SectionType.SERVICE_GROUPS.display_name,
                object_count=len(sg_objects),
                parsed_ok=True,
                objects=sg_objects,
            )
        )

        # ---- gateway → interfaces (if GAiA did not already fill) ----
        existing_ifaces = {i.name for i in model.interfaces}
        gw_iface_objects: list[dict[str, Any]] = []
        for rec in gw_rows:
            body = rec["body"]
            gw_name = rec["name"]
            if not model.hostname:
                model.hostname = gw_name
            ifaces = body.get("interfaces")
            items: list[Any] = []
            if isinstance(ifaces, list) and len(ifaces) == 2 and isinstance(ifaces[1], list):
                items = ifaces[1]
            for it in items:
                _c, ib = _typed_body(it)
                if not ib:
                    continue
                iname = str(ib.get("officialname") or ib.get("name") or "if")
                ip = ib.get("ipaddr")
                mask = ib.get("netmask")
                raw = json.dumps(
                    {"gateway": gw_name, "interface": iname, "ip": ip, "mask": mask},
                    default=str,
                )
                if iname not in existing_ifaces:
                    iface = Interface(
                        name=iname,
                        interface_type="physical",
                        ip_addresses=[str(ip)] if ip else [],
                        netmask=str(mask) if mask else None,
                        enabled=True,
                        source_vendor=_VENDOR,
                        source_raw=raw,
                        metadata={
                            "gateway": gw_name,
                            "source": "migrate_server",
                        },
                    )
                    model.interfaces.append(iface)
                    existing_ifaces.add(iname)
                    gw_iface_objects.append(
                        _obj_entry(
                            iface.id,
                            iname,
                            raw,
                            {
                                "Name": iname,
                                "IPv4": f"{ip}/{mask}" if ip and mask else ip,
                                "Gateway": gw_name,
                            },
                            preview=str(ip) if ip else iname,
                        )
                    )

        if gw_iface_objects and not any(
            s.section_type == SectionType.INTERFACES.value for s in sections
        ):
            sections.append(
                ParsedSection(
                    section_type=SectionType.INTERFACES.value,
                    display_name=SectionType.INTERFACES.display_name,
                    object_count=len(gw_iface_objects),
                    parsed_ok=True,
                    objects=gw_iface_objects,
                )
            )
        elif gw_iface_objects:
            # merge into existing interfaces section if present
            for s in sections:
                if s.section_type == SectionType.INTERFACES.value:
                    s.objects.extend(gw_iface_objects)
                    s.object_count = len(s.objects)
                    break

        # ---- access policies (security only — threat prevention is separate) ----
        pol_objects: list[dict[str, Any]] = []
        for i, body in enumerate(access_rules):
            name = str(body.get("name") or f"rule_{i}")
            src_uids = _field_uuids(body.get("srcs"))
            dst_uids = _field_uuids(body.get("dsts"))
            svc_uids = _field_uuids(body.get("svcs"))
            app_uids = _field_uuids(body.get("applications"))
            srcs = _resolve_names(src_uids, index)
            dsts = _resolve_names(dst_uids, index)
            svcs = _resolve_names(svc_uids, index)
            apps = _resolve_names(app_uids, index)
            # App categories (e.g. Gambling) often sit in applications, not svcs
            svc_display = svcs
            if apps and apps != ["Any"] and (not svcs or svcs == ["Any"]):
                svc_display = apps
            elif apps and apps != ["Any"]:
                svc_display = list(dict.fromkeys([*svcs, *apps]))
            action_uid = None
            asettings = body.get("actionSettings")
            _ac, ab = _typed_body(asettings)
            if ab:
                action_uid = ab.get("action")
            action_name = _WELL_KNOWN.get(str(action_uid or ""), "")
            if not action_name and action_uid:
                action_name = index.get(str(action_uid), {}).get("name") or str(action_uid)[:8]
            if not action_name:
                action_name = "Drop" if "cleanup" in name.lower() else "Accept"
            action = (
                PolicyAction.DENY
                if action_name.lower() in ("drop", "reject", "deny")
                else PolicyAction.ALLOW
            )
            enabled = bool(body.get("enabled", True))
            pkg, layer = _pkg_for_rule(body)
            raw = json.dumps(
                {
                    "name": name,
                    "policy_package": pkg,
                    "layer": layer,
                    "source": srcs,
                    "destination": dsts,
                    "service": svcs,
                    "applications": apps,
                    "action": action_name,
                    "enabled": enabled,
                    "objId": body.get("objId"),
                    "position": body.get("position"),
                },
                default=str,
                indent=2,
            )
            pol = FirewallPolicy(
                name=name,
                policy_id=str(body.get("objId") or i),
                action=action,
                source_addresses=[NamedReference(name=s, kind="address") for s in srcs],
                destination_addresses=[NamedReference(name=d, kind="address") for d in dsts],
                services=[NamedReference(name=s, kind="service") for s in svc_display],
                applications=[
                    NamedReference(name=a, kind="application")
                    for a in apps
                    if a != "Any"
                ],
                enabled=enabled,
                source_vendor=_VENDOR,
                source_ref=str(body.get("objId") or ""),
                source_raw=raw,
                position=i,
                comments=body.get("comments") or None,
                metadata={
                    "action_name": action_name,
                    "source": "migrate_server",
                    "kind": "access",
                    "Policy Package": pkg,
                    "Layer": layer,
                    "Applications": [a for a in apps if a != "Any"],
                    # Prefer app categories over bare Any when apps present
                    "Services": svc_display,
                },
            )
            model.policies.append(pol)
            pol_objects.append(
                _obj_entry(
                    pol.id,
                    name,
                    raw,
                    {
                        "Name": name,
                        "Policy Package": pkg,
                        "Layer": layer,
                        "Action": action_name,
                        "Source": srcs,
                        "Destination": dsts,
                        "Services": svc_display,
                        "Applications": [a for a in apps if a != "Any"],
                        "Enabled": enabled,
                        "Position": body.get("position"),
                    },
                    preview=f"[{pkg}] {action_name} · {','.join(svc_display[:3])}",
                )
            )

        sections.append(
            ParsedSection(
                section_type=SectionType.FIREWALL_POLICIES.value,
                display_name=SectionType.FIREWALL_POLICIES.display_name,
                object_count=len(pol_objects),
                parsed_ok=True,
                objects=pol_objects,
            )
        )

        # ---- NAT ----
        nat_objects: list[dict[str, Any]] = []
        for i, body in enumerate(nat_rules):
            name = str(body.get("name") or f"nat_{i}")
            o_src = _resolve_names(_collect_uuids(body.get("originalSrc")), index)
            o_dst = _resolve_names(_collect_uuids(body.get("originalDst")), index)
            o_svc = _resolve_names(_collect_uuids(body.get("originalSvc")), index)
            t_src = _resolve_names(_collect_uuids(body.get("translatedSrc")), index)
            t_dst = _resolve_names(_collect_uuids(body.get("translatedDst")), index)
            t_svc = _resolve_names(_collect_uuids(body.get("translatedSvc")), index)
            method = body.get("natMethod") or "HIDE"
            pkg, layer = _pkg_for_rule(body)
            raw = json.dumps(
                {
                    "name": name,
                    "policy_package": pkg,
                    "method": method,
                    "original": {"src": o_src, "dst": o_dst, "svc": o_svc},
                    "translated": {"src": t_src, "dst": t_dst, "svc": t_svc},
                },
                default=str,
                indent=2,
            )
            nat = NATRule(
                name=name,
                rule_id=str(body.get("objId") or i),
                nat_type=str(method).lower(),
                enabled=bool(body.get("enabled", True)),
                source_addresses=[NamedReference(name=s, kind="address") for s in o_src],
                destination_addresses=[NamedReference(name=d, kind="address") for d in o_dst],
                services=[NamedReference(name=s, kind="service") for s in o_svc],
                translated_source=NamedReference(name=t_src[0], kind="address") if t_src else None,
                translated_destination=NamedReference(name=t_dst[0], kind="address")
                if t_dst
                else None,
                source_vendor=_VENDOR,
                source_ref=str(body.get("objId") or ""),
                source_raw=raw,
                metadata={
                    "source": "migrate_server",
                    "Policy Package": pkg,
                    "Layer": layer,
                },
            )
            model.nat_rules.append(nat)
            nat_objects.append(
                _obj_entry(
                    nat.id,
                    name,
                    raw,
                    {
                        "Name": name,
                        "Policy Package": pkg,
                        "Method": method,
                        "Original Source": o_src,
                        "Original Destination": o_dst,
                        "Translated Source": t_src,
                        "Translated Destination": t_dst,
                    },
                    preview=f"[{pkg}] {method} {','.join(o_src[:2])}→{','.join(t_src[:2])}",
                )
            )
        sections.append(
            ParsedSection(
                section_type=SectionType.NAT.value,
                display_name=SectionType.NAT.display_name,
                object_count=len(nat_objects),
                parsed_ok=True,
                objects=nat_objects,
            )
        )

        # ---- Threat Prevention / IPS / AV / TE (→ security_profiles via applications) ----
        profile_objects: list[dict[str, Any]] = []

        def _add_profile_app(
            *,
            name: str,
            category: str,
            oid: str,
            body: dict[str, Any],
            props: dict[str, Any],
            preview: str | None = None,
        ) -> None:
            raw = json.dumps(
                {"name": name, "category": category, "objId": oid, **{
                    k: body.get(k)
                    for k in (
                        "comments",
                        "type",
                        "enableIpsAutomatically",
                        "enableAvAutomatically",
                        "enableAbAutomatically",
                        "enableTeAutomatically",
                        "enableTexAutomatically",
                        "threatPreventionMainProfile",
                        "layers",
                        "maxFileSize",
                        "fileEmulationTime",
                        "scanHttp",
                        "scanFtp",
                        "scanSmtp",
                        "mailAntiVirusMode",
                    )
                    if body.get(k) not in (None, "", [], {})
                }},
                default=str,
                indent=2,
            )
            app = Application(
                name=name,
                category=category,
                source_vendor=_VENDOR,
                source_ref=oid,
                source_raw=raw,
                metadata={"source": "migrate_server", "kind": category},
            )
            model.applications.append(app)
            profile_objects.append(
                _obj_entry(
                    app.id,
                    name,
                    raw,
                    {"Name": name, "Category": category, **props, "UID": oid},
                    preview=preview or category,
                )
            )

        for rec in tp_profile_rows:
            body = rec["body"]
            name = rec["name"] or "Threat Prevention Profile"
            _add_profile_app(
                name=name,
                category="Threat Prevention Profile",
                oid=rec["objId"],
                body=body,
                props={"Comments": body.get("comments") or "—"},
                preview="TP Profile",
            )

        for rec in tp_policy_rows:
            body = rec["body"]
            name = rec["name"] or "Threat Policy"
            main_prof = body.get("threatPreventionMainProfile")
            main_name = (
                _resolve_names([str(main_prof)], index)[0] if main_prof else None
            )
            kind_label = (
                "Threat Policy"
                if rec.get("kind") == "tp_policy"
                else "Simplified Threat Policy"
            )
            _add_profile_app(
                name=name,
                category=kind_label,
                oid=rec["objId"],
                body=body,
                props={
                    "Main profile": main_name or main_prof,
                    "Layers": body.get("layers"),
                },
                preview=main_name or kind_label,
            )

        te_filetypes: list[str] = []
        for rec in tp_blade_rows:
            body = rec["body"]
            name = rec["name"] or rec.get("kind") or "blade"
            kind = rec.get("kind") or ""
            if kind == "te_filetypes":
                te_filetypes.append(str(name))
                continue
            cat_map = {
                "ips_settings": "IPS Settings",
                "ips_global": "IPS Global",
                "amw_general": "Anti-Malware / Threat Extraction",
                "amw_gw": "Anti-Malware Gateway",
                "av_settings": "Antivirus Settings",
                "te_general": "Threat Emulation",
                "te_gw": "Threat Emulation Gateway",
                "tex_scrub": "Threat Extraction",
            }
            category = cat_map.get(kind, "Threat Prevention")
            blade_flags = {
                k: body.get(k)
                for k in (
                    "enableIpsAutomatically",
                    "enableAvAutomatically",
                    "enableAbAutomatically",
                    "enableTeAutomatically",
                    "enableTexAutomatically",
                    "enableZpAutomatically",
                    "tpHttpInspectAll",
                    "scanHttp",
                    "scanFtp",
                    "scanSmtp",
                    "mailAntiVirusMode",
                    "maxFileSize",
                    "fileEmulationTime",
                    "failOpenMode",
                    "avHoldMode",
                    "abHoldMode",
                )
                if body.get(k) not in (None, "", [], {})
            }
            _add_profile_app(
                name=name,
                category=category,
                oid=rec["objId"],
                body=body,
                props={**blade_flags},
                preview=category,
            )
        if te_filetypes:
            ft_name = "TE supported file types"
            _add_profile_app(
                name=ft_name,
                category="Threat Emulation File Types",
                oid="te-filetypes",
                body={"file_types": te_filetypes},
                props={"File types": ", ".join(sorted(set(te_filetypes)))},
                preview=f"{len(set(te_filetypes))} types",
            )

        # Threat prevention rules — separate from access policies; group by TP policy/package
        threat_rule_objects: list[dict[str, Any]] = []
        for i, body in enumerate(threat_rules):
            name = str(body.get("name") or f"threat_rule_{i}")
            srcs = _resolve_names(_field_uuids(body.get("srcs")), index)
            dsts = _resolve_names(_field_uuids(body.get("dsts")), index)
            svcs = _resolve_names(_field_uuids(body.get("svcs")), index)
            scope = _resolve_names(_field_uuids(body.get("scope")), index)
            action_uid = str(body.get("action") or "")
            action_name = _WELL_KNOWN.get(action_uid) or (
                index.get(action_uid, {}).get("name") if action_uid else None
            ) or (action_uid[:8] + "…" if action_uid else "—")
            profile_hint = (
                index.get(action_uid, {}).get("name") if action_uid in index else None
            )
            enabled = bool(body.get("enabled", True))
            pkg, layer = _pkg_for_rule(body)
            raw = json.dumps(
                {
                    "name": name,
                    "policy_package": pkg,
                    "layer": layer,
                    "action": action_name,
                    "profile": profile_hint,
                    "source": srcs,
                    "destination": dsts,
                    "service": svcs,
                    "scope": scope,
                    "enabled": enabled,
                    "packetCapture": body.get("packetCapture"),
                    "enableForensics": body.get("enableForensics"),
                    "objId": body.get("objId"),
                },
                default=str,
                indent=2,
            )
            # Stored as Application with kind so enrich can map to policies_threat
            app = Application(
                name=name,
                category="Threat Prevention Rule",
                source_vendor=_VENDOR,
                source_ref=str(body.get("objId") or ""),
                source_raw=raw,
                metadata={
                    "source": "migrate_server",
                    "kind": "threat_prevention_rule",
                    "action": action_name,
                    "profile": profile_hint,
                    "Policy Package": pkg,
                    "Layer": layer,
                    "Action": profile_hint or action_name,
                    "Source": srcs,
                    "Destination": dsts,
                    "Services": svcs,
                    "Protected Scope": scope,
                    "Enabled": enabled,
                    "Packet Capture": body.get("packetCapture"),
                    "Forensics": body.get("enableForensics"),
                },
            )
            model.applications.append(app)
            threat_rule_objects.append(
                _obj_entry(
                    app.id,
                    name,
                    raw,
                    {
                        "Name": name,
                        "Policy Package": pkg,
                        "Layer": layer,
                        "Action / Profile": profile_hint or action_name,
                        "Source": srcs,
                        "Destination": dsts,
                        "Services": svcs,
                        "Protected scope": scope,
                        "Enabled": enabled,
                    },
                    preview=f"[{pkg}] {profile_hint or action_name}",
                )
            )

        if profile_objects:
            sections.append(
                ParsedSection(
                    section_type=SectionType.APPLICATIONS.value,
                    display_name="Threat Prevention / Profiles",
                    object_count=len(profile_objects),
                    parsed_ok=True,
                    objects=profile_objects,
                )
            )
        if threat_rule_objects:
            sections.append(
                ParsedSection(
                    section_type="threat_policies",
                    display_name="Threat Prevention",
                    object_count=len(threat_rule_objects),
                    parsed_ok=True,
                    objects=threat_rule_objects,
                )
            )
            warnings.append(
                {
                    "code": "CP_THREAT_OK",
                    "message": (
                        f"Threat Prevention: {len(tp_profile_rows)} profile(s), "
                        f"{len(threat_rules)} rule(s), {len(tp_blade_rows)} blade setting object(s)"
                    ),
                    "severity": "info",
                    "section": "threat_policies",
                }
            )

        # packages as system/other notes
        if package_rows:
            pkg_objs = []
            for rec in package_rows:
                raw = json.dumps({"name": rec["name"], "objId": rec["objId"]}, default=str)
                pkg_objs.append(
                    _obj_entry(
                        rec["objId"] or rec["name"],
                        rec["name"],
                        raw,
                        {"Name": rec["name"], "UID": rec["objId"]},
                        preview=rec["name"],
                    )
                )
            # stash on model metadata via system if present
            if model.system:
                model.system.metadata["policy_packages"] = [r["name"] for r in package_rows]
            warnings.append(
                {
                    "code": "CP_PACKAGES",
                    "message": "Policy packages: "
                    + ", ".join(r["name"] for r in package_rows),
                    "severity": "info",
                    "section": SectionType.FIREWALL_POLICIES.value,
                }
            )

        warnings.append(
            {
                "code": "CP_MIGRATE_OK",
                "message": (
                    f"Parsed migrate_server domain {domain_id[:8]}…: "
                    f"{len(addr_objects)} addresses, {len(pol_objects)} access rules, "
                    f"{len(nat_objects)} NAT rules, "
                    f"{len(profile_objects)} threat-prevention objects"
                ),
                "severity": "info",
            }
        )

    return sections, warnings
