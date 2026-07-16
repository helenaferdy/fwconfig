/**
 * Client-side config compare: merge taxonomy sections + fundamental object diffs.
 * Vendors share leaf section_type ids (network_interfaces, policies_security, …).
 */

import type { ParsedObject, ParsedSection } from "./types";

export type DiffStatus = "only-a" | "only-b" | "changed" | "same";

export interface ObjectDiff {
  status: DiffStatus;
  key: string;
  nameA?: string;
  nameB?: string;
}

export interface SectionDiff {
  sectionType: string;
  objects: Map<string, ObjectDiff>;
  counts: { onlyA: number; onlyB: number; changed: number; same: number };
}

/** Mirror of backend model/taxonomy.py LEAF_ORDER for stable nav ordering. */
export const LEAF_ORDER: string[] = [
  "system_general",
  "system_management",
  "system_services",
  "system_other",
  "network_interfaces",
  "network_zones",
  "network_dhcp",
  "network_other",
  "objects_addresses",
  "objects_address_groups",
  "objects_services",
  "objects_service_groups",
  "objects_other",
  "routing_static",
  "routing_dynamic",
  "routing_policy",
  "routing_other",
  "policies_security",
  "policies_threat",
  "policies_nat",
  "policies_auth",
  "policies_other",
  "vpn_ipsec",
  "vpn_ssl",
  "vpn_other",
  "security_profiles",
  "security_inspection",
  "security_other",
  "users_users",
  "users_groups",
  "users_external_auth",
  "users_other",
  "diagnostics_logging",
  "diagnostics_monitoring",
  "diagnostics_ha",
  "diagnostics_other",
  "other_unclassified",
  "other_unsupported",
  "other_unknown",
];

const LEAF_INDEX = new Map(LEAF_ORDER.map((id, i) => [id, i]));

const PROP_ALIASES: Record<string, string> = {
  "source addresses": "Source",
  "destination addresses": "Destination",
  "original source": "Source",
  "original destination": "Destination",
  "ip addresses": "IPv4",
  "nat type": "Method",
  "protected scope": "Protected Scope",
  "destination ports": "Ports",
  "dest ports": "Ports",
};

const NOISE_KEYS = new Set(
  [
    "uid",
    "Uid",
    "UID",
    "Policy Id",
    "Rule Id",
    "VSYS",
    "Policy Package",
    "Position",
    "Layer",
    "Source Vendor",
    "is_divider",
    "Is Divider",
    "Kind",
    "Description",
    "Name",
    "Log",
    "Nat Enabled",
    "Action Name",
    "Profile",
  ].map((s) => s.toLowerCase())
);

const DEFAULT_NAME_RE =
  /^(any|all|none|always|default|sslvpn_.*|all_internet|cleanup rule|any-ipv4|any-ipv6|any ipv4|any ipv6)$/i;

/** Core keys by leaf family — fundamental non-default compare. */
function coreKeysForSection(sectionType: string): string[] | null {
  if (
    sectionType.startsWith("objects_address") ||
    sectionType === "objects_other"
  ) {
    return ["Value", "Address Type", "Members", "IPv4", "IP Address"];
  }
  if (sectionType.startsWith("objects_service")) {
    return ["Protocol", "Ports", "Members", "Destination Ports"];
  }
  if (sectionType === "network_interfaces") {
    // Match / equality primarily by host IPv4 (CIDR stripped)
    return ["IPv4", "IP Address"];
  }
  if (sectionType === "network_dhcp") {
    // Match / equality by Network host (CIDR/mask stripped)
    return ["Network"];
  }
  if (sectionType.startsWith("network_")) {
    return ["Members", "Enabled", "Value", "IPv4", "IP Address", "Network"];
  }
  if (sectionType === "routing_static") {
    // Match / equality by destination+gateway (destination host form)
    return ["Destination", "Gateway"];
  }
  if (sectionType.startsWith("routing_")) {
    return [
      "Destination",
      "Gateway",
      "Interface",
      "Enabled",
      "Blackhole",
      "Metric",
      "Distance",
    ];
  }
  if (sectionType === "policies_nat") {
    return [
      "Action",
      "Enabled",
      "Source",
      "Destination",
      "Services",
      "Applications",
      "Source Interfaces",
      "Destination Interfaces",
      "Method",
      "Translated Source",
      "Translated Destination",
    ];
  }
  if (sectionType.startsWith("policies_")) {
    return [
      "Action",
      "Action / Profile",
      "Enabled",
      "Source",
      "Destination",
      "Services",
      "Applications",
      "Source Interfaces",
      "Destination Interfaces",
      "Protected Scope",
    ];
  }
  if (sectionType.startsWith("users_")) {
    return ["Enabled", "Type", "Action", "Members"];
  }
  if (sectionType.startsWith("vpn_")) {
    return [
      "Enabled",
      "Type",
      "Interface",
      "Gateway",
      "Local",
      "Remote",
      "Members",
    ];
  }
  if (sectionType.startsWith("security_")) {
    return ["Action", "Enabled", "Type", "Members", "Profile", "Action / Profile"];
  }
  // null → use all non-noise keys
  return null;
}

export function normalizeObjectName(name: string): string {
  let s = String(name || "").trim();
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1).trim();
  }
  return s.toLowerCase();
}

/**
 * Policy name match: treat _ and - as spaces so WAN_BACKUP ≡ WAN BACKUP ≡ WAN-BACKUP.
 */
export function normalizePolicyName(name: string): string {
  return normalizeObjectName(name)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Host form of an address: ignore everything after "/".
 * 10.10.10.1/24, 10.10.10.1/255.255.255.0, and 10.10.10.1 all → 10.10.10.1
 * Also drops trailing dotted masks when space-separated (10.10.10.1 255.255.255.0).
 */
export function stripCidr(value: string): string {
  let s = String(value || "").trim().toLowerCase();
  if (!s) return "";
  // first token if space-separated (ip + mask)
  s = s.split(/\s+/)[0] || s;
  // drop anything past "/" (prefix length or dotted mask)
  const slash = s.indexOf("/");
  if (slash >= 0) s = s.slice(0, slash);
  return s.trim();
}

function isDivider(obj: ParsedObject): boolean {
  const p = obj.properties as Record<string, unknown> | undefined;
  return Boolean(p?.is_divider);
}

function isEmptyish(v: unknown): boolean {
  if (v === null || v === undefined || v === "") return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === "string") {
    const t = v.trim().toLowerCase();
    if (t === "any" || t === "all" || t === "none" || t === "—") return true;
  }
  if (
    Array.isArray(v) &&
    v.length === 1 &&
    typeof v[0] === "string" &&
    ["any", "all", "none"].includes(v[0].trim().toLowerCase())
  ) {
    return true;
  }
  return false;
}

const CIDR_FIELD_KEYS = new Set(
  [
    "IPv4",
    "IP Address",
    "Network",
    "Destination",
    "Value",
    "Gateway",
    "Translated Source",
    "Translated Destination",
    "Source",
    "Members",
  ].map((k) => k.toLowerCase())
);

function normalizePropValue(v: unknown, fieldKey?: string): string {
  if (isEmptyish(v)) return "";
  if (typeof v === "boolean") return v ? "yes" : "no";
  const strip = fieldKey ? CIDR_FIELD_KEYS.has(fieldKey.toLowerCase()) : true;
  if (Array.isArray(v)) {
    return v
      .map((x) => {
        let t = String(x).trim().toLowerCase();
        if (strip) t = stripCidr(t);
        return t;
      })
      .filter(Boolean)
      .sort()
      .join(",");
  }
  if (typeof v === "object" && v !== null) {
    try {
      return JSON.stringify(v);
    } catch {
      return String(v);
    }
  }
  let s = String(v).trim().toLowerCase();
  if (strip) s = stripCidr(s);
  return s;
}

function normalizeProps(
  props: Record<string, unknown> | undefined | null
): Record<string, string> {
  if (!props) return {};
  const out: Record<string, string> = {};
  for (const [rawKey, v] of Object.entries(props)) {
    if (rawKey === "Name" || rawKey === "is_divider") continue;
    const canon = PROP_ALIASES[rawKey.toLowerCase()] || rawKey;
    if (NOISE_KEYS.has(canon.toLowerCase())) continue;
    if (isEmptyish(v)) continue;
    const nv = normalizePropValue(v, canon);
    if (!nv) continue;
    // Prefer host form without CIDR when both exist (shorter after strip is equal length)
    const prev = out[canon];
    if (!prev || nv.length > prev.length) out[canon] = nv;
  }
  return out;
}

function propLookup(
  norm: Record<string, string>,
  ...keys: string[]
): string {
  for (const k of keys) {
    if (norm[k]) return norm[k];
    const hit = Object.keys(norm).find((x) => x.toLowerCase() === k.toLowerCase());
    if (hit && norm[hit]) return norm[hit];
  }
  return "";
}

/**
 * Cross-config match key. Special cases:
 * - interfaces → host IPv4 (anything after / ignored)
 * - dhcp → Network host (anything after / ignored)
 * - static routes → destination host + gateway pair
 * - security policies → name with _/- as space (WAN_BACKUP ≡ WAN BACKUP)
 * - else → object name
 */
export function objectMatchKey(
  obj: ParsedObject,
  sectionType: string
): string {
  const norm = normalizeProps(obj.properties as Record<string, unknown>);
  if (sectionType === "network_interfaces") {
    const ip = stripCidr(propLookup(norm, "IPv4", "IP Address"));
    if (ip) return `ip:${ip}`;
  }
  if (sectionType === "network_dhcp") {
    const net = stripCidr(propLookup(norm, "Network"));
    if (net) return `net:${net}`;
  }
  if (sectionType === "routing_static") {
    const dest = stripCidr(propLookup(norm, "Destination"));
    const gw = stripCidr(propLookup(norm, "Gateway"));
    if (dest || gw) return `route:${dest}|gw:${gw}`;
  }
  if (sectionType === "policies_security") {
    return `name:${normalizePolicyName(obj.name)}`;
  }
  return `name:${normalizeObjectName(obj.name)}`;
}

function fingerprint(
  props: Record<string, unknown> | undefined | null,
  sectionType: string
): string {
  const norm = normalizeProps(props);
  // For interface / dhcp / static route: equality is the match field only
  if (sectionType === "network_interfaces") {
    return `ip:${stripCidr(propLookup(norm, "IPv4", "IP Address"))}`;
  }
  if (sectionType === "network_dhcp") {
    return `net:${stripCidr(propLookup(norm, "Network"))}`;
  }
  if (sectionType === "routing_static") {
    const dest = stripCidr(propLookup(norm, "Destination"));
    const gw = stripCidr(propLookup(norm, "Gateway"));
    return `route:${dest}|gw:${gw}`;
  }

  const core = coreKeysForSection(sectionType);
  const entries: [string, string][] = [];

  if (core) {
    const coreLower = new Map(core.map((k) => [k.toLowerCase(), k]));
    for (const [k, v] of Object.entries(norm)) {
      if (coreLower.has(k.toLowerCase())) {
        entries.push([coreLower.get(k.toLowerCase())!, v]);
      }
    }
    if (entries.length === 0) {
      for (const [k, v] of Object.entries(norm)) {
        entries.push([k, v]);
      }
    }
  } else {
    for (const [k, v] of Object.entries(norm)) {
      entries.push([k, v]);
    }
  }

  entries.sort((a, b) => a[0].localeCompare(b[0]));
  return entries.map(([k, v]) => `${k}=${v}`).join("|");
}

function sectionObjectCount(s: ParsedSection): number {
  const fromField = s.object_count ?? 0;
  const dataObjs = (s.objects || []).filter((o) => !isDivider(o));
  return Math.max(fromField, dataObjs.length);
}

/**
 * Union A∪B by section_type for SectionNav.
 * Prefer metadata from A; object stubs for search (deduped by name).
 */
export function mergeSections(
  a: ParsedSection[] | undefined,
  b: ParsedSection[] | undefined
): ParsedSection[] {
  const map = new Map<string, ParsedSection>();
  const nameSets = new Map<string, Set<string>>();

  const ingest = (list: ParsedSection[] | undefined, preferMeta: boolean) => {
    if (!list) return;
    for (const s of list) {
      if (!s.section_type) continue;
      const count = sectionObjectCount(s);
      if (count <= 0 && !(s.objects || []).some((o) => !isDivider(o))) continue;

      const prev = map.get(s.section_type);
      if (!prev) {
        map.set(s.section_type, {
          section_type: s.section_type,
          display_name: s.display_name,
          category: s.category,
          category_display: s.category_display,
          object_count: count,
          parsed_ok: s.parsed_ok,
          objects: [],
        });
        nameSets.set(s.section_type, new Set());
      } else {
        prev.object_count = (prev.object_count || 0) + count;
        if (preferMeta) {
          if (s.display_name) prev.display_name = s.display_name;
          if (s.category) prev.category = s.category;
          if (s.category_display) prev.category_display = s.category_display;
        }
      }

      const names = nameSets.get(s.section_type)!;
      for (const o of s.objects || []) {
        if (isDivider(o) || !o.name) continue;
        const key = normalizeObjectName(o.name);
        if (names.has(key)) continue;
        names.add(key);
        map.get(s.section_type)!.objects.push({ name: o.name });
      }
    }
  };

  // A first (preferred meta), then B
  ingest(a, true);
  ingest(b, false);

  const items = Array.from(map.values());
  items.sort((x, y) => {
    const ix = LEAF_INDEX.get(x.section_type);
    const iy = LEAF_INDEX.get(y.section_type);
    if (ix != null && iy != null) return ix - iy;
    if (ix != null) return -1;
    if (iy != null) return 1;
    return x.section_type.localeCompare(y.section_type);
  });
  return items;
}

function indexSectionObjects(
  sections: ParsedSection[]
): Map<string, Map<string, ParsedObject>> {
  const byLeaf = new Map<string, Map<string, ParsedObject>>();
  for (const s of sections) {
    if (!s.section_type) continue;
    let m = byLeaf.get(s.section_type);
    if (!m) {
      m = new Map();
      byLeaf.set(s.section_type, m);
    }
    for (const o of s.objects || []) {
      if (isDivider(o) || !o.name) continue;
      const key = objectMatchKey(o, s.section_type);
      // Keep first if duplicate match keys
      if (!m.has(key)) m.set(key, o);
    }
  }
  return byLeaf;
}

/**
 * Build per-leaf object diffs for fundamental non-default differences.
 */
export function buildCompareDiff(
  sectionsA: ParsedSection[],
  sectionsB: ParsedSection[]
): Map<string, SectionDiff> {
  const idxA = indexSectionObjects(sectionsA);
  const idxB = indexSectionObjects(sectionsB);
  const leafIds = new Set<string>(
    Array.from(idxA.keys()).concat(Array.from(idxB.keys()))
  );
  const result = new Map<string, SectionDiff>();

  for (const leaf of Array.from(leafIds)) {
    const mapA = idxA.get(leaf) || new Map<string, ParsedObject>();
    const mapB = idxB.get(leaf) || new Map<string, ParsedObject>();
    const keys = new Set<string>(
      Array.from(mapA.keys()).concat(Array.from(mapB.keys()))
    );
    const objects = new Map<string, ObjectDiff>();
    const counts = { onlyA: 0, onlyB: 0, changed: 0, same: 0 };

    for (const key of Array.from(keys)) {
      const oa = mapA.get(key);
      const ob = mapB.get(key);

      if (oa && !ob) {
        objects.set(key, {
          status: "only-a",
          key,
          nameA: oa.name,
        });
        counts.onlyA++;
        continue;
      }
      if (ob && !oa) {
        objects.set(key, {
          status: "only-b",
          key,
          nameB: ob.name,
        });
        counts.onlyB++;
        continue;
      }
      if (oa && ob) {
        const fa = fingerprint(
          oa.properties as Record<string, unknown>,
          leaf
        );
        const fb = fingerprint(
          ob.properties as Record<string, unknown>,
          leaf
        );
        let status: DiffStatus = fa === fb ? "same" : "changed";

        // Default-ish names that match on both sides: never badge as fundamental
        if (
          status === "same" &&
          DEFAULT_NAME_RE.test(oa.name) &&
          DEFAULT_NAME_RE.test(ob.name)
        ) {
          status = "same";
        }

        objects.set(key, {
          status,
          key,
          nameA: oa.name,
          nameB: ob.name,
        });
        if (status === "changed") counts.changed++;
        else counts.same++;
      }
    }

    result.set(leaf, { sectionType: leaf, objects, counts });
  }

  return result;
}

/** Total fundamental diffs for a leaf (badge count). */
export function fundamentalDiffCount(sd: SectionDiff | undefined): number {
  if (!sd) return 0;
  return sd.counts.onlyA + sd.counts.onlyB + sd.counts.changed;
}

/**
 * Map normalized *display name* → true when the object exists on both A and B
 * (used for green mid-pane row highlighting by object name on each side).
 */
export function matchMapBoth(
  sd: SectionDiff | undefined
): Map<string, boolean> {
  const out = new Map<string, boolean>();
  if (!sd) return out;
  sd.objects.forEach((d) => {
    if (d.status === "same" || d.status === "changed") {
      if (d.nameA) out.set(normalizeObjectName(d.nameA), true);
      if (d.nameB) out.set(normalizeObjectName(d.nameB), true);
    }
  });
  return out;
}

/** Leaf ids present (non-empty) on both configs — green section boxes. */
export function sharedSectionTypes(
  sectionsA: ParsedSection[] | undefined,
  sectionsB: ParsedSection[] | undefined
): Record<string, boolean> {
  const present = (list: ParsedSection[] | undefined): Set<string> => {
    const s = new Set<string>();
    if (!list) return s;
    for (const sec of list) {
      if (!sec.section_type) continue;
      if (sectionObjectCount(sec) > 0) s.add(sec.section_type);
    }
    return s;
  };
  const a = present(sectionsA);
  const b = present(sectionsB);
  const out: Record<string, boolean> = {};
  a.forEach((id) => {
    if (b.has(id)) out[id] = true;
  });
  return out;
}

/** @deprecated kept for any callers — prefer matchMapBoth / sharedSectionTypes */
export function diffMapForSide(
  sd: SectionDiff | undefined,
  side: "a" | "b"
): Map<string, DiffStatus> {
  const out = new Map<string, DiffStatus>();
  if (!sd) return out;
  sd.objects.forEach((d, key) => {
    if (d.status === "same" || d.status === "changed") {
      // both sides: mark as "same" for green highlight consumers that still use status
      out.set(key, "same");
      return;
    }
    if (side === "a" && d.status === "only-a") out.set(key, d.status);
    if (side === "b" && d.status === "only-b") out.set(key, d.status);
  });
  return out;
}

/** section_type → fundamental diff count (legacy badges; unused in green UI). */
export function diffCountMap(
  diffBySection: Map<string, SectionDiff> | null
): Record<string, number> {
  if (!diffBySection) return {};
  const out: Record<string, number> = {};
  diffBySection.forEach((sd, leaf) => {
    const n = fundamentalDiffCount(sd);
    if (n > 0) out[leaf] = n;
  });
  return out;
}
