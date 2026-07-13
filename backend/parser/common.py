"""Shared helpers for section parsers."""

from __future__ import annotations

import re
from typing import Any, Iterable

from model.enums import SectionType
from model.objects import CommonModel, ParsedSection
from parser.base import SectionParser


def extract_blocks(raw: str, start_pattern: str) -> list[str]:
    """Extract FortiOS `config ... end` blocks with nested depth awareness.

    Nested `config tagging` / `config members` etc. must not close the outer block.
    """
    blocks: list[str] = []
    lines = raw.splitlines()
    start_re = re.compile(start_pattern, re.IGNORECASE)
    collecting = False
    depth = 0
    current: list[str] = []

    for line in lines:
        if not collecting:
            if start_re.search(line):
                collecting = True
                depth = 1
                current = [line]
            continue

        current.append(line)
        # Nested config increases depth (including "config members" style)
        if re.match(r"^\s*config\s+\S+", line, re.IGNORECASE):
            depth += 1
        elif re.match(r"^\s*end\s*$", line, re.IGNORECASE):
            depth -= 1
            if depth <= 0:
                blocks.append("\n".join(current))
                collecting = False
                current = []
                depth = 0
    return blocks


def iter_edits(block: str) -> list[tuple[str, str, str]]:
    """Yield (name_or_id, body, raw_snippet) for each `edit ... next` in a block.

    Supports both `edit "name"` and `edit 123`.
    """
    results: list[tuple[str, str, str]] = []
    # Non-greedy until next/end; allow nested next inside config tagging via careful split
    # Strategy: line-based parse for edit/next at the same indent level as typical Forti (4 spaces)
    lines = block.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r'^(\s*)edit\s+(?:"([^"]+)"|(\S+))\s*$', lines[i], re.IGNORECASE)
        if not m:
            i += 1
            continue
        indent = m.group(1)
        name = m.group(2) or m.group(3)
        start = i
        i += 1
        body_lines = []
        nest = 0
        while i < len(lines):
            line = lines[i]
            if re.match(r"^\s*config\s+", line, re.I):
                nest += 1
            elif re.match(r"^\s*end\s*$", line, re.I):
                nest = max(0, nest - 1)
            # matching next at same or shallower indent ends the edit
            if nest == 0 and re.match(rf"^{re.escape(indent)}next\s*$", line, re.I):
                raw_snip = "\n".join(lines[start : i + 1])
                results.append((name, "\n".join(body_lines), raw_snip))
                i += 1
                break
            body_lines.append(line)
            i += 1
        else:
            raw_snip = "\n".join(lines[start:i])
            results.append((name, "\n".join(body_lines), raw_snip))
    return results


def set_val(body: str, key: str) -> str | None:
    """Extract `set <key> <value>` (handles quoted and multi-token values)."""
    m = re.search(rf"set\s+{re.escape(key)}\s+(.+?)\s*$", body, re.I | re.M)
    if not m:
        return None
    val = m.group(1).strip()
    # strip surrounding quotes for single token
    if val.startswith('"') and val.endswith('"') and val.count('"') == 2:
        return val[1:-1]
    return val


def set_quoted_list(body: str, key: str) -> list[str]:
    m = re.search(rf"set\s+{re.escape(key)}\s+(.+?)\s*$", body, re.I | re.M)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def set_tokens(body: str, key: str) -> list[str]:
    m = re.search(rf"set\s+{re.escape(key)}\s+(.+?)\s*$", body, re.I | re.M)
    if not m:
        return []
    line = m.group(1).strip()
    quoted = re.findall(r'"([^"]+)"', line)
    if quoted:
        return quoted
    return line.split()


def wrap_edit_raw(block: str, edit_snip: str) -> str:
    """Wrap an `edit ... next` snippet with its parent `config ... end`.

    Ensures the left-pane raw viewer never drops the section header/footer.
    """
    text = (edit_snip or "").strip("\n")
    if not text and block:
        return block.strip("\n") + ("\n" if not block.endswith("\n") else "")

    # Already a full config block
    if re.match(r"^\s*config\s+\S+", text, re.IGNORECASE):
        if not re.search(r"^\s*end\s*$", text, re.MULTILINE | re.IGNORECASE):
            return text.rstrip() + "\nend"
        return text

    header = ""
    for line in (block or "").splitlines():
        if re.match(r"^\s*config\s+\S+", line, re.IGNORECASE):
            header = line.rstrip()
            break
    if not header:
        return text

    # Avoid double-wrapping
    return f"{header}\n{text}\nend"


def ensure_config_block(raw: str, fallback_header: str | None = None) -> str:
    """If raw is an edit-only snippet, wrap it with fallback_header ... end."""
    text = (raw or "").strip("\n")
    if not text:
        return text
    if re.match(r"^\s*config\s+\S+", text, re.IGNORECASE):
        if not re.search(r"^\s*end\s*$", text, re.MULTILINE | re.IGNORECASE):
            return text.rstrip() + "\nend"
        return text
    if fallback_header:
        hdr = fallback_header if fallback_header.strip().lower().startswith("config") else f"config {fallback_header}"
        return f"{hdr}\n{text}\nend"
    return text


def count_named_objects(
    blocks: Iterable[str], name_pattern: str = r'edit\s+"([^"]+)"'
) -> list[dict]:
    objects = []
    for block in blocks:
        for name, body, raw in iter_edits(block):
            objects.append(
                {
                    "name": name,
                    "raw": wrap_edit_raw(block, raw),
                    "body": body,
                }
            )
    return objects


class StubSectionParser(SectionParser):
    """Fallback: extract all edit objects under matching config blocks."""

    section_type: SectionType
    config_patterns: list[str] = []  # regex for config lines
    search_patterns: list[str] = []  # legacy alias

    def parse(self, raw: str, model: CommonModel) -> ParsedSection:
        patterns = self.config_patterns or self.search_patterns
        objects: list[dict[str, Any]] = []
        full_blocks: list[str] = []
        for pattern in patterns:
            # If pattern is a full config start, extract blocks
            if pattern.strip().startswith("config") or r"config\s+" in pattern:
                # normalize to start-of-line config pattern
                pat = pattern
                if not pat.startswith("^"):
                    if r"config\s+" in pat and not pat.strip().startswith("config"):
                        pat = rf"^{pat}"
                    elif pat.startswith("config"):
                        pat = rf"^{pat}"
                    else:
                        pat = rf"^config\s+{pat}"
                for block in extract_blocks(raw, pat):
                    full_blocks.append(block)
                    for name, body, raw_snip in iter_edits(block):
                        objects.append(
                            {
                                "id": f"{self.section_type.value}-{name}",
                                "name": name,
                                "raw": wrap_edit_raw(block, raw_snip),
                                "properties": {"Name": name},
                                "preview": name,
                            }
                        )
            else:
                # line-level match fallback
                for m in re.finditer(pattern, raw, re.I | re.M):
                    snip = m.group(0).strip()
                    objects.append(
                        {
                            "id": f"{self.section_type.value}-{len(objects)+1}",
                            "name": snip[:80],
                            "raw": snip[:500],
                            "properties": {"Name": snip[:80]},
                            "preview": snip[:120],
                        }
                    )

        # dedupe by name
        seen: set[str] = set()
        deduped = []
        for o in objects:
            if o["name"] in seen:
                continue
            seen.add(o["name"])
            deduped.append(o)

        return ParsedSection(
            section_type=self.section_type.value,
            display_name=self.section_type.display_name,
            object_count=len(deduped),
            parsed_ok=True,
            objects=deduped,
            # Prefer complete config...end blocks for section-level raw view
            raw_snippets=full_blocks or [o["raw"] for o in deduped[:50] if o.get("raw")],
        )
