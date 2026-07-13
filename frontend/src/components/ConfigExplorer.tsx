"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import type { ParsedObject, ParsedSection } from "@/lib/types";

interface Props {
  sections: ParsedSection[];
  originalConfig?: string | null;
  selectedSection: string | null;
  selectedObjectId?: string | null;
  onSelectSection: (sectionType: string) => void;
  onSelectObject?: (sectionType: string, object: ParsedObject) => void;
}

/** Strip outer config/end so edits can be re-joined into one block. */
function unwrapEditBody(raw: string): string {
  let lines = raw.replace(/\r\n/g, "\n").split("\n");
  // drop leading blank
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
 * Full section raw: always `config …` header + all edits + `end`.
 * Prefer complete original blocks in raw_snippets; else merge object raws.
 */
function sectionRaw(sec: ParsedSection | undefined): string {
  if (!sec) return "";

  // Original full section dumps (one config, many edits) — preferred
  const originals = (sec.raw_snippets || [])
    .map((s) => String(s).trim())
    .filter((s) => {
      if (!/^\s*config\s+\S+/im.test(s) || !/^\s*end\s*$/im.test(s)) return false;
      return (s.match(/^\s*edit\s+/gim) || []).length > 1 || s.split("\n").length > 8;
    });
  if (originals.length) {
    return originals.join("\n\n") + "\n";
  }

  // Merge per-object raw (each is config/edit/end) under one header per config type
  const objRaws = (sec.objects || [])
    .map((o) => (o.raw ? String(o.raw).trim() : ""))
    .filter(Boolean);
  if (!objRaws.length) {
    return (sec.raw_snippets || []).map(String).join("\n\n");
  }

  const groups = new Map<string, string[]>();
  const order: string[] = [];
  for (const raw of objRaws) {
    const header = extractConfigHeader(raw) || "config unknown";
    if (!groups.has(header)) {
      groups.set(header, []);
      order.push(header);
    }
    groups.get(header)!.push(unwrapEditBody(raw));
  }

  return (
    order
      .map((header) => {
        const bodies = groups.get(header) || [];
        return `${header}\n${bodies.join("\n")}\nend`;
      })
      .join("\n\n") + "\n"
  );
}

/** Single-object raw always includes config header + end. */
function objectDisplayRaw(raw: string | null | undefined): string {
  if (!raw) return "";
  const text = String(raw).trim();
  if (/^\s*config\s+\S+/im.test(text)) {
    if (!/^\s*end\s*$/im.test(text)) return text + "\nend";
    return text;
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
 * Left nav: single flat list — "Category · Section".
 * One click → section raw. Middle-pane object click → object raw.
 */
export function ConfigExplorer({
  sections,
  selectedSection,
  selectedObjectId,
  onSelectSection,
}: Props) {
  const [query, setQuery] = useState("");
  const rawScrollRef = useRef<HTMLDivElement>(null);
  const selectedRowRef = useRef<HTMLButtonElement>(null);

  // Flat list preserving taxonomy order (sections already ordered)
  const flatItems = useMemo(() => {
    return sections
      .filter((s) => s.object_count > 0)
      .map((s) => ({
        section: s,
        label: `${s.category_display || "Other"} · ${s.display_name}`,
        cat: s.category_display || "Other",
        name: s.display_name,
      }));
  }, [sections]);

  const q = query.trim().toLowerCase();

  const filtered = useMemo(() => {
    if (!q) return flatItems;
    return flatItems.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.section.section_type.toLowerCase().includes(q) ||
        item.section.objects?.some((o) => o.name.toLowerCase().includes(q))
    );
  }, [flatItems, q]);

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
      body: "// Click a section above to view its raw configuration",
    };
  }, [activeSection, activeObject]);

  const lines = useMemo(() => raw.body.split("\n"), [raw.body]);

  useEffect(() => {
    if (rawScrollRef.current) rawScrollRef.current.scrollTop = 0;
    selectedRowRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [selectedSection, selectedObjectId]);

  return (
    <div className="flex h-full min-h-0 flex-col left-nav">
      <div className="left-nav-header shrink-0">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search"
          className="left-nav-search"
          aria-label="Search"
        />
      </div>

      {/* Single flat list: Category · Section */}
      <div className="left-nav-list shrink-0 overflow-y-auto">
        {filtered.length === 0 && (
          <p className="meta px-3 py-2">No matching sections</p>
        )}
        <ul className="left-nav-flat">
          {filtered.map((item) => {
            const active = selectedSection === item.section.section_type;
            return (
              <li key={item.section.section_type}>
                <button
                  type="button"
                  ref={active ? selectedRowRef : undefined}
                  className={`left-nav-item ${active ? "is-selected" : ""}`}
                  onClick={() => onSelectSection(item.section.section_type)}
                >
                  <span className="left-nav-item-label" title={item.label}>
                    <span className="left-nav-cat-prefix">{item.cat}</span>
                    <span className="left-nav-sep"> · </span>
                    <span className="left-nav-sec-name">{item.name}</span>
                  </span>
                  <span className="badge">{item.section.object_count}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>

      <div className="raw-pane">
        <div className="raw-toolbar">
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
              Select a section above. Raw config appears here in one click.
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
