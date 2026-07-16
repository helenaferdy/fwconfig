"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import type { ParsedObject, ParsedSection, SummarySection } from "@/lib/types";
import { ChevronIcon, SpinnerIcon } from "./icons";

interface Props {
  analyzing: boolean;
  hasSession: boolean;
  hasSummary: boolean;
  parsedSections: ParsedSection[];
  summarySections: SummarySection[];
  selectedSection: string | null;
  selectedObjectId?: string | null;
  selectedObjectName?: string | null;
  aiHighlights?: string[];
  aiNotes?: Record<string, string>;
  vendorDisplay?: string | null;
  onAnalyze?: () => void;
  onSelectSection?: (sectionType: string) => void;
  onSelectObject?: (sectionType: string, object: ParsedObject) => void;
}

function fmt(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) {
    if (!v.length) return "—";
    return v.map(String).join(", ");
  }
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** Columns for dense row view (prefer these keys from properties). Unique names only. */
const COL_CANDIDATES = [
  "Role",
  "Category",
  "IPv4",
  "IP Address",
  "Value",
  "Action",
  "Action / Profile",
  "Source",
  "Destination",
  "Translated Source",
  "Translated Destination",
  "Services",
  "Applications",
  "Protected Scope",
  "Source Interfaces",
  "Destination Interfaces",
  "Gateway",
  "Protocol",
  "Members",
  "Method",
  "Nat Type",
  "Policy Package",
  "Layer",
  "Enabled",
  "Alias",
  "Netmask",
];

/** Columns that are internal / not useful in the dense table. */
const COL_SKIP = new Set(
  [
    "Name",
    "is_divider",
    "Is Divider",
    "Kind",
    "Source Vendor",
    "Policy Id",
    "Rule Id",
    "Position",
    "Log",
    "Nat Enabled",
    "Blackhole",
    "Action Name",
    "Uid",
    "UID",
    "Profile", // often duplicates Action / Profile
    // Legacy aliases — collapsed via COL_ALIASES / normalizeProps
    "Source Addresses",
    "Destination Addresses",
    "Original Source",
    "Original Destination",
  ].map((s) => s.toLowerCase())
);

/**
 * Collapse legacy / CP dual labels onto one canonical key.
 * Check Point used to emit both model "Source Addresses" and meta "Source",
 * which produced two Destination/Source columns in the mid-pane.
 */
const COL_ALIASES: Record<string, string> = {
  "source addresses": "Source",
  "destination addresses": "Destination",
  "original source": "Source",
  "original destination": "Destination",
  "ip addresses": "IPv4",
  "nat type": "Method",
  "protected scope": "Protected Scope",
};

const FILE_ORIGIN_VALUES = new Set([
  "migrate_server",
  "gaia_show_configuration",
  "fortigate",
  "primary",
  "other",
]);

function isFileOriginValue(v: unknown): boolean {
  if (typeof v !== "string") return false;
  if (FILE_ORIGIN_VALUES.has(v)) return true;
  return v.startsWith("gaia_");
}

function isEmptyProp(v: unknown): boolean {
  return (
    v === null ||
    v === undefined ||
    v === "" ||
    (Array.isArray(v) && v.length === 0)
  );
}

/** Prefer real config values over placeholders / file-origin markers. */
function preferPropValue(existing: unknown, incoming: unknown): unknown {
  if (isEmptyProp(incoming) || isFileOriginValue(incoming)) return existing;
  if (isEmptyProp(existing) || isFileOriginValue(existing)) return incoming;
  if (existing === "Any" || existing === "any" || (Array.isArray(existing) && existing.length === 1 && String(existing[0]).toLowerCase() === "any")) {
    if (!(incoming === "Any" || incoming === "any" || (Array.isArray(incoming) && incoming.length === 1 && String(incoming[0]).toLowerCase() === "any"))) {
      return incoming;
    }
  }
  // Prefer longer / richer values (e.g. address lists over a bare string)
  const score = (v: unknown) => {
    if (Array.isArray(v)) return 10 + v.length;
    if (typeof v === "string") return v.length;
    return 1;
  };
  return score(incoming) > score(existing) ? incoming : existing;
}

/**
 * Normalize object properties for table display:
 * - alias Source Addresses / Destination Addresses → Source / Destination
 * - drop file-origin values (migrate_server / gaia_…)
 * - case-collapse so we never emit two Destination columns
 */
function normalizeProps(
  props: Record<string, unknown> | undefined | null
): Record<string, unknown> {
  if (!props) return {};
  const out: Record<string, unknown> = {};
  const byLower = new Map<string, string>(); // lower → canonical key kept in out
  for (const [rawKey, v] of Object.entries(props)) {
    if (rawKey === "Name" || rawKey === "is_divider") {
      out[rawKey] = v;
      continue;
    }
    if (isEmptyProp(v) || isFileOriginValue(v)) continue;
    // Alias first so "Destination Addresses" becomes "Destination" before skip checks
    const canon = COL_ALIASES[rawKey.toLowerCase()] || rawKey;
    // Drop bookkeeping after aliasing (legacy address labels are gone by now)
    if (COL_SKIP.has(canon.toLowerCase())) continue;
    const lower = canon.toLowerCase();
    const existingKey = byLower.get(lower);
    if (existingKey) {
      out[existingKey] = preferPropValue(out[existingKey], v);
    } else {
      byLower.set(lower, canon);
      out[canon] = v;
    }
  }
  return out;
}

function pickColumns(objects: ParsedObject[], max = 5): string[] {
  const scores = new Map<string, number>();
  for (const obj of objects.slice(0, 40)) {
    const props = normalizeProps(obj.properties as Record<string, unknown>);
    for (const [k, v] of Object.entries(props)) {
      if (k === "Name" || k === "is_divider") continue;
      if (isEmptyProp(v)) continue;
      if (COL_SKIP.has(k.toLowerCase())) continue;
      scores.set(k, (scores.get(k) || 0) + 1);
    }
  }
  const keys = Array.from(scores.keys());
  const seen = new Set<string>();
  const preferred: string[] = [];
  for (const cand of COL_CANDIDATES) {
    const found = keys.find((s) => s.toLowerCase() === cand.toLowerCase());
    if (!found) continue;
    const norm = found.toLowerCase();
    if (seen.has(norm)) continue;
    seen.add(norm);
    preferred.push(found);
  }
  const rest = Array.from(scores.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([k]) => k)
    .filter((k) => !seen.has(k.toLowerCase()));
  return preferred.concat(rest).slice(0, max);
}

function cellValue(obj: ParsedObject, key: string): string {
  const props = normalizeProps(obj.properties as Record<string, unknown>);
  if (key in props) return fmt(props[key]);
  const hit = Object.keys(props).find((k) => k.toLowerCase() === key.toLowerCase());
  return hit ? fmt(props[hit]) : "—";
}

export function CenterPane({
  analyzing,
  hasSession,
  hasSummary,
  parsedSections,
  selectedSection,
  selectedObjectId,
  selectedObjectName,
  aiHighlights = [],
  aiNotes = {},
  vendorDisplay,
  onAnalyze,
  onSelectSection,
  onSelectObject,
}: Props) {
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const [catCollapsed, setCatCollapsed] = useState<Record<string, boolean>>({});

  // Only scroll mid-pane when AI highlights a section — not on user clicks
  useEffect(() => {
    if (!aiHighlights.length) return;
    const target = aiHighlights[aiHighlights.length - 1];
    const el = sectionRefs.current[target];
    if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [aiHighlights]);

  const nonEmpty = useMemo(
    () => parsedSections.filter((s) => s.object_count > 0),
    [parsedSections]
  );

  const grouped = useMemo(() => {
    const order: string[] = [];
    const map = new Map<string, { name: string; items: ParsedSection[] }>();
    for (const s of nonEmpty) {
      const cid = s.category || "other";
      const cname = s.category_display || "Other";
      if (!map.has(cid)) {
        map.set(cid, { name: cname, items: [] });
        order.push(cid);
      }
      map.get(cid)!.items.push(s);
    }
    return order.map((id) => ({ id, ...map.get(id)! }));
  }, [nonEmpty]);

  const overview = useMemo(
    () =>
      grouped.map((g) => ({
        id: g.id,
        name: g.name,
      })),
    [grouped]
  );

  const focusSection = selectedSection
    ? nonEmpty.find((s) => s.section_type === selectedSection)
    : null;

  const renderTable = (section: ParsedSection, limit?: number) => {
    const allObjs = section.objects || [];
    const dataObjs = allObjs.filter(
      (o) => !(o.properties as Record<string, unknown> | undefined)?.is_divider
    );
    const objs =
      limit != null ? allObjs.slice(0, limit) : allObjs;
    const cols = pickColumns(dataObjs.length ? dataObjs : allObjs);
    const colSpan = 1 + cols.length;
    return (
      <table className="data-table">
        <thead>
          <tr>
            <th style={{ width: "18%" }}>Name</th>
            {cols.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {objs.map((obj, i) => {
            const props = (obj.properties || {}) as Record<string, unknown>;
            const isDivider = Boolean(props.is_divider);
            const oid = String(obj.id || `${section.section_type}-${i}`);
            if (isDivider) {
              const dtype = String(props.Type || "group");
              return (
                <tr key={oid} className="policy-package-divider">
                  <td colSpan={colSpan}>
                    <span className="font-medium text-[var(--fg)]">
                      {obj.name}
                    </span>
                    <span className="meta">
                      {" "}
                      · {dtype === "Policy package" ? "policy package" : dtype}
                    </span>
                  </td>
                </tr>
              );
            }
            const active =
              selectedObjectId === oid || selectedObjectName === obj.name;
            return (
              <tr
                key={oid}
                className={active ? "active" : undefined}
                onClick={() => onSelectObject?.(section.section_type, obj)}
              >
                <td className="name-cell" title={obj.name}>
                  {obj.name}
                </td>
                {cols.map((c) => (
                  <td key={c} title={cellValue(obj, c)}>
                    {cellValue(obj, c)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="pane-header panel-header shrink-0">
        <div className="min-w-0 truncate">
          <span className="font-medium">Overview</span>
          <span className="meta">
            {" "}
            · {hasSummary ? vendorDisplay || "parsed" : "awaiting"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {focusSection && (
            <button
              type="button"
              className="btn-outline"
              onClick={() => onSelectSection?.("")}
            >
              All
            </button>
          )}
          {hasSession && onAnalyze && (
            <button
              type="button"
              className="btn-outline"
              disabled={analyzing}
              onClick={onAnalyze}
            >
              {analyzing ? "…" : "Refresh"}
            </button>
          )}
        </div>
      </div>

      {!hasSummary && (
        <div className="flex flex-1 items-center justify-center p-6 text-center">
          <div>
            <p className="meta mb-3">Readable configuration overview</p>
            {hasSession && onAnalyze && (
              <button
                type="button"
                className="btn-primary"
                disabled={analyzing}
                onClick={onAnalyze}
              >
                {analyzing ? (
                  <>
                    <SpinnerIcon className="h-3 w-3" /> Analyzing…
                  </>
                ) : (
                  "Analyze Configuration"
                )}
              </button>
            )}
            {!hasSession && <p className="meta">Upload a configuration first</p>}
          </div>
        </div>
      )}

      {hasSummary && (
        <div className="min-h-0 flex-1 overflow-y-auto">
          {focusSection ? (
            <div
              ref={(el) => {
                sectionRefs.current[focusSection.section_type] = el;
              }}
              className={
                aiHighlights.includes(focusSection.section_type)
                  ? "section-ai-highlight"
                  : ""
              }
              data-note={aiNotes[focusSection.section_type] || undefined}
            >
              <div className="section-head active" style={{ cursor: "default" }}>
                <span className="meta" style={{ color: "#aaa" }}>
                  {focusSection.category_display}
                </span>
                <span>{focusSection.display_name}</span>
              </div>
              {renderTable(focusSection)}
            </div>
          ) : (
            <>
              <div className="overview-strip">
                {overview.map((g) => (
                  <div key={g.id} className="overview-chip">
                    <span className="overview-chip-name">{g.name}</span>
                  </div>
                ))}
              </div>

              {grouped.map((g) => {
                const collapsed = catCollapsed[g.id] ?? false;
                return (
                  <div key={g.id}>
                    <button
                      type="button"
                      className="summary-cat-label"
                      onClick={() =>
                        setCatCollapsed((p) => ({ ...p, [g.id]: !collapsed }))
                      }
                    >
                      <ChevronIcon open={!collapsed} className="h-2.5 w-2.5" />
                      {g.name}
                    </button>

                    {!collapsed &&
                      g.items.map((section) => {
                        const aiHit = aiHighlights.includes(section.section_type);
                        const note = aiNotes[section.section_type];
                        const isActive = selectedSection === section.section_type;
                        return (
                          <div
                            key={section.section_type}
                            ref={(el) => {
                              sectionRefs.current[section.section_type] = el;
                            }}
                            className={`${aiHit ? "section-ai-highlight" : ""} ${
                              note ? "section-ai-annotate" : ""
                            }`}
                            data-note={note || undefined}
                          >
                            <button
                              type="button"
                              className={`section-head ${isActive ? "active" : ""}`}
                              onClick={() =>
                                onSelectSection?.(section.section_type)
                              }
                            >
                              <span className="flex-1 truncate">
                                {section.display_name}
                              </span>
                            </button>
                            {/* Preview first rows only in overview */}
                            {renderTable(section, 12)}
                            {section.object_count > 12 && (
                              <button
                                type="button"
                                className="btn-ghost w-full justify-start px-2 py-0.5 text-left"
                                style={{ minHeight: 22, fontSize: 10 }}
                                onClick={() =>
                                  onSelectSection?.(section.section_type)
                                }
                              >
                                +{section.object_count - 12} more — open section
                              </button>
                            )}
                          </div>
                        );
                      })}
                  </div>
                );
              })}

              {grouped.length === 0 && (
                <p className="p-4 meta">No parsed objects yet.</p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
