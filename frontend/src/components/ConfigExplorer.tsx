"use client";

import React, { useEffect, useMemo, useRef } from "react";
import type { ParsedObject, ParsedSection } from "@/lib/types";

interface Props {
  sections: ParsedSection[];
  originalConfig?: string | null;
  selectedSection: string | null;
  selectedObjectId?: string | null;
  onSelectSection: (sectionType: string) => void;
}

/** True when text looks like a FortiGate-style `config …` / `end` block. */
function isFortiConfigBlock(raw: string): boolean {
  return /^\s*config\s+\S+/im.test(raw);
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

/**
 * Full section raw.
 * FortiGate: merge per-object `config/edit/end` under real headers.
 * Other vendors: show object/snippet raw as-is.
 */
function sectionRaw(sec: ParsedSection | undefined): string {
  if (!sec) return "";

  const originals = (sec.raw_snippets || [])
    .map((s) => String(s).trim())
    .filter((s) => {
      if (!isFortiConfigBlock(s) || !/^\s*end\s*$/im.test(s)) return false;
      return (s.match(/^\s*edit\s+/gim) || []).length > 1 || s.split("\n").length > 8;
    });
  if (originals.length) {
    return originals.join("\n\n") + "\n";
  }

  const objRaws = (sec.objects || [])
    .map((o) => (o.raw ? String(o.raw).trim() : ""))
    .filter(Boolean);

  if (!objRaws.length) {
    const snippets = (sec.raw_snippets || []).map((s) => String(s).trim()).filter(Boolean);
    return snippets.length ? snippets.join("\n\n") + "\n" : "";
  }

  const forti = objRaws.filter(isFortiConfigBlock);
  const other = objRaws.filter((r) => !isFortiConfigBlock(r));
  const parts: string[] = [];

  if (forti.length) {
    const groups = new Map<string, string[]>();
    const order: string[] = [];
    for (const raw of forti) {
      const header = extractConfigHeader(raw);
      if (!header) {
        parts.push(raw);
        continue;
      }
      if (!groups.has(header)) {
        groups.set(header, []);
        order.push(header);
      }
      groups.get(header)!.push(unwrapEditBody(raw));
    }
    for (const header of order) {
      const bodies = (groups.get(header) || []).filter(Boolean);
      if (!bodies.length) continue;
      parts.push(`${header}\n${bodies.join("\n")}\nend`);
    }
  }

  if (other.length) {
    parts.push(other.join("\n\n"));
  }

  if (!parts.length && (sec.raw_snippets || []).length) {
    return (
      (sec.raw_snippets || [])
        .map((s) => String(s).trim())
        .filter(Boolean)
        .join("\n\n") + "\n"
    );
  }

  return parts.length ? parts.join("\n\n") + "\n" : "";
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
  objectId: string | null | undefined
): ParsedObject | undefined {
  if (!sec || !objectId) return undefined;
  return sec.objects?.find(
    (o, i) =>
      String(o.id || `${sec.section_type}-${i}`) === objectId || o.name === objectId
  );
}

/**
 * Left pane: raw configuration only (full height).
 * Section list lives in the right pane top slot.
 */
export function ConfigExplorer({
  sections,
  selectedSection,
  selectedObjectId,
  onSelectSection,
}: Props) {
  const rawScrollRef = useRef<HTMLDivElement>(null);
  const prevKeyRef = useRef<string>("");

  const activeSection = useMemo(
    () => sections.find((s) => s.section_type === selectedSection),
    [sections, selectedSection]
  );

  const activeObject = useMemo(
    () => findObject(activeSection, selectedObjectId),
    [activeSection, selectedObjectId]
  );

  const raw = useMemo(() => {
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
      title: "No section selected",
      subtitle: "",
      body: "// Select a section to view its raw configuration",
    };
  }, [activeSection, activeObject]);

  const lines = useMemo(() => raw.body.split("\n"), [raw.body]);

  // Reset raw scroll only when the displayed content identity changes
  // (not on every mid-pane re-render / unrelated selection noise)
  useEffect(() => {
    const key = `${selectedSection || ""}|${selectedObjectId || ""}|${raw.title}`;
    if (key === prevKeyRef.current) return;
    prevKeyRef.current = key;
    if (rawScrollRef.current) rawScrollRef.current.scrollTop = 0;
  }, [selectedSection, selectedObjectId, raw.title]);

  return (
    <div className="flex h-full min-h-0 flex-col left-nav">
      <div className="raw-pane raw-pane-full">
        <div className="pane-header raw-toolbar shrink-0">
          <div className="min-w-0 flex-1 truncate">
            <span className="raw-title">{raw.title}</span>
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
