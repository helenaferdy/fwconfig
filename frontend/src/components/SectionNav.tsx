"use client";

import React, { useMemo, useState } from "react";
import type { ParsedSection } from "@/lib/types";

interface Props {
  sections: ParsedSection[];
  selectedSection: string | null;
  onSelectSection: (sectionType: string) => void;
}

/**
 * Section picker as compact boxes (name + category) for denser packing.
 */
export function SectionNav({
  sections,
  selectedSection,
  onSelectSection,
}: Props) {
  const [query, setQuery] = useState("");

  const items = useMemo(() => {
    return sections
      .filter((s) => s.object_count > 0)
      .map((s) => ({
        id: s.section_type,
        name: s.display_name,
        category: s.category_display || "Other",
        search: `${s.display_name} ${s.category_display || ""} ${s.section_type}`.toLowerCase(),
      }));
  }, [sections]);

  const q = query.trim().toLowerCase();

  const filtered = useMemo(() => {
    if (!q) return items;
    return items.filter(
      (item) =>
        item.search.includes(q) ||
        sections
          .find((s) => s.section_type === item.id)
          ?.objects?.some((o) => o.name.toLowerCase().includes(q))
    );
  }, [items, q, sections]);

  return (
    <div className="flex h-full min-h-0 flex-col section-nav">
      <div className="pane-header shrink-0">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search"
          className="pane-header-search"
          aria-label="Search sections"
        />
      </div>
      <div className="section-nav-grid-wrap min-h-0 flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <p className="meta px-2 py-2">No matching sections</p>
        ) : (
          <div className="section-nav-grid" role="listbox" aria-label="Sections">
            {filtered.map((item) => {
              const active = selectedSection === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  role="option"
                  aria-selected={active}
                  className={`section-box ${active ? "is-selected" : ""}`}
                  title={`${item.name} · ${item.category}`}
                  onClick={() => onSelectSection(item.id)}
                >
                  <span className="section-box-name">{item.name}</span>
                  <span className="section-box-cat">{item.category}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
