"use client";

import React, { useEffect, useMemo, useRef } from "react";
import { objectMatchKey } from "@/lib/compareDiff";
import type { ParsedObject, ParsedSection } from "@/lib/types";

interface Props {
  sections: ParsedSection[];
  originalConfig?: string | null;
  selectedSection: string | null;
  selectedObjectId?: string | null;
  /** Cross-config match key so raw pane can resolve counterpart on the other side */
  selectedMatchKey?: string | null;
  onSelectSection: (sectionType: string) => void;
  /** Compare side label shown in the raw header, e.g. "A" | "B" */
  sideLabel?: string | null;
  /** When selected leaf is missing on this config */
  emptySectionMessage?: string | null;
}

/** True when text looks like a FortiGate-style `config …` / `end` block. */
function isFortiConfigBlock(raw: string): boolean {
  return /^\s*config\s+\S+/im.test(raw);
}

function countEdits(raw: string): number {
  return (raw.match(/^\s*edit\s+/gim) || []).length;
}

/**
 * True multi-edit FortiGate section dump (complete config…end with 2+ edits).
 * Do NOT use line-count heuristics — single long edit blocks must not be treated
 * as the entire section (that caused only 3 of 13 static routes to show).
 */
function isFullMultiEditDump(raw: string): boolean {
  if (!isFortiConfigBlock(raw) || !/^\s*end\s*$/im.test(raw)) return false;
  return countEdits(raw) > 1;
}

/** Strip outer config/end so FortiGate edits can be re-joined into one block. */
function unwrapEditBody(raw: string): string {
  let lines = raw.replace(/\r\n/g, "\n").split("\n");
  while (lines.length && !lines[0].trim()) lines = lines.slice(1);
  while (lines.length && !lines[lines.length - 1].trim()) lines = lines.slice(0, -1);
  if (lines.length && /^\s*config\s+\S+/i.test(lines[0])) {
    lines = lines.slice(1);
  }
  if (lines.length && /^\s*end\s*$/i.test(lines[lines.length - 1])) {
    lines = lines.slice(0, -1);
  }
  return lines.join("\n");
}

function extractConfigHeader(raw: string): string | null {
  for (const line of raw.split("\n")) {
    if (/^\s*config\s+\S+/i.test(line)) return line.trimEnd();
  }
  return null;
}

/** Merge FortiGate per-object config/edit/end snippets under one header each. */
function mergeFortiObjectRaws(objRaws: string[]): string {
  const groups = new Map<string, string[]>();
  const order: string[] = [];
  const loose: string[] = [];

  for (const raw of objRaws) {
    const text = raw.trim();
    if (!text) continue;
    if (!isFortiConfigBlock(text)) {
      loose.push(text);
      continue;
    }
    const header = extractConfigHeader(text);
    if (!header) {
      loose.push(text);
      continue;
    }
    if (!groups.has(header)) {
      groups.set(header, []);
      order.push(header);
    }
    const body = unwrapEditBody(text);
    if (body.trim()) {
      groups.get(header)!.push(body);
    }
  }

  const parts: string[] = [];
  for (const header of order) {
    const bodies = groups.get(header) || [];
    if (!bodies.length) continue;
    parts.push(`${header}\n${bodies.join("\n")}\nend`);
  }
  if (loose.length) {
    parts.push(loose.join("\n\n"));
  }
  return parts.length ? parts.join("\n\n") + "\n" : "";
}

/**
 * Full section raw for the left pane.
 * Critical: never drop objects — mid-pane count and left-pane config must match.
 */
function sectionRaw(sec: ParsedSection | undefined): string {
  if (!sec) return "";

  const dataObjs = (sec.objects || []).filter(
    (o) => !(o.properties as Record<string, unknown> | undefined)?.is_divider
  );

  // 1) Prefer true multi-edit full blocks from the parser (complete config…end)
  const fullDumps = (sec.raw_snippets || [])
    .map((s) => String(s).trim())
    .filter(isFullMultiEditDump);

  if (fullDumps.length) {
    // If we have full dumps, still verify they cover enough edits vs objects.
    // Prefer the dump(s) with the most edits for each config header.
    const byHeader = new Map<string, string>();
    for (const dump of fullDumps) {
      const header = extractConfigHeader(dump) || dump.slice(0, 40);
      const prev = byHeader.get(header);
      if (!prev || countEdits(dump) >= countEdits(prev)) {
        byHeader.set(header, dump);
      }
    }
    const dumps = Array.from(byHeader.values());
    const dumpEdits = dumps.reduce((n, d) => n + countEdits(d), 0);
    const objRaws = dataObjs
      .map((o) => (o.raw ? String(o.raw).trim() : ""))
      .filter(Boolean);
    // If full dumps cover all (or more) object edits, use them as-is
    if (dumpEdits >= objRaws.length || dumpEdits >= dataObjs.length) {
      return dumps.join("\n\n") + "\n";
    }
    // Otherwise fall through and rebuild from every object raw
  }

  // 2) Merge every object that has raw (primary path after enrich)
  const objRaws = dataObjs
    .map((o) => (o.raw ? String(o.raw).trim() : ""))
    .filter(Boolean);

  if (objRaws.length) {
    return mergeFortiObjectRaws(objRaws);
  }

  // 3) Fallback: any remaining snippets (even single-edit) merged the same way
  const snips = (sec.raw_snippets || [])
    .map((s) => String(s).trim())
    .filter(Boolean);
  if (snips.length) {
    return mergeFortiObjectRaws(snips);
  }

  return "";
}

function objectDisplayRaw(raw: string | null | undefined): string {
  if (!raw) return "";
  const text = String(raw).trim();
  if (isFortiConfigBlock(text) && !/^\s*end\s*$/im.test(text)) {
    return text + "\nend";
  }
  return text;
}

function findObject(
  sec: ParsedSection | undefined,
  objectId: string | null | undefined,
  matchKey?: string | null
): ParsedObject | undefined {
  if (!sec) return undefined;
  const objs = sec.objects || [];
  if (objectId) {
    const byId = objs.find(
      (o, i) =>
        String(o.id || `${sec.section_type}-${i}`) === objectId ||
        o.name === objectId
    );
    if (byId) return byId;
  }
  if (matchKey) {
    return objs.find(
      (o) =>
        !(o.properties as Record<string, unknown> | undefined)?.is_divider &&
        objectMatchKey(o, sec.section_type) === matchKey
    );
  }
  return undefined;
}

/**
 * Left pane: raw configuration only (full height).
 * Section list lives in the right pane top slot.
 */
export function ConfigExplorer({
  sections,
  selectedSection,
  selectedObjectId,
  selectedMatchKey,
  onSelectSection,
  sideLabel,
  emptySectionMessage,
}: Props) {
  const rawScrollRef = useRef<HTMLDivElement>(null);
  const prevKeyRef = useRef<string>("");

  const activeSection = useMemo(
    () => sections.find((s) => s.section_type === selectedSection),
    [sections, selectedSection]
  );

  const activeObject = useMemo(
    () => findObject(activeSection, selectedObjectId, selectedMatchKey),
    [activeSection, selectedObjectId, selectedMatchKey]
  );

  const leafMissing =
    Boolean(selectedSection) && !activeSection && Boolean(emptySectionMessage);

  const raw = useMemo(() => {
    if (leafMissing) {
      return {
        title: sideLabel ? `Config · ${sideLabel}` : "Config",
        subtitle: "",
        body: `// ${emptySectionMessage}`,
      };
    }
    if (activeObject?.raw) {
      return {
        title: activeObject.name,
        subtitle: activeSection
          ? `${activeSection.category_display || "Other"} · ${activeSection.display_name}`
          : "",
        body: objectDisplayRaw(activeObject.raw),
      };
    }
    if (activeSection) {
      const body = sectionRaw(activeSection);
      return {
        title: activeSection.display_name,
        subtitle: activeSection.category_display || "",
        body:
          body ||
          `// no raw blocks extracted for ${activeSection.display_name}`,
      };
    }
    return {
      title: sideLabel ? `Config · ${sideLabel}` : "No section selected",
      subtitle: "",
      body: "// Select a section to view its raw configuration",
    };
  }, [activeSection, activeObject, leafMissing, emptySectionMessage, sideLabel]);

  const lines = useMemo(() => raw.body.split("\n"), [raw.body]);

  // Reset raw scroll only when the displayed content identity changes
  useEffect(() => {
    const key = `${selectedSection || ""}|${selectedObjectId || ""}|${raw.title}|${lines.length}`;
    if (key === prevKeyRef.current) return;
    prevKeyRef.current = key;
    if (rawScrollRef.current) rawScrollRef.current.scrollTop = 0;
  }, [selectedSection, selectedObjectId, raw.title, lines.length]);

  return (
    <div className="flex h-full min-h-0 flex-col left-nav">
      <div className="raw-pane raw-pane-full">
        <div className="pane-header raw-toolbar shrink-0">
          <div className="min-w-0 flex-1 truncate">
            {sideLabel && !activeSection && !activeObject && (
              <span className="raw-title">Config · {sideLabel}</span>
            )}
            {!(sideLabel && !activeSection && !activeObject) && (
              <span className="raw-title">
                {sideLabel ? `${sideLabel} · ${raw.title}` : raw.title}
              </span>
            )}
            {raw.subtitle && <span className="meta"> · {raw.subtitle}</span>}
            {activeObject && <span className="meta"> · object</span>}
            <span className="meta"> · {lines.length} lines</span>
          </div>
          {selectedObjectId && selectedSection && (
            <button
              type="button"
              className="btn-ghost"
              onClick={() => onSelectSection(selectedSection)}
              title="Show full section raw"
            >
              section
            </button>
          )}
        </div>

        <div className="min-h-0 flex-1 overflow-auto" ref={rawScrollRef}>
          {!selectedSection ? (
            <p className="p-3 meta">
              Select a section to view raw configuration.
            </p>
          ) : (
            <table className="raw-table">
              <tbody>
                {lines.map((text, i) => (
                  <tr key={i}>
                    <td className="raw-ln">{i + 1}</td>
                    <td className="raw-code">
                      <code>{text || " "}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
