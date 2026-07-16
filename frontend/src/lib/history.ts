/**
 * Per-browser run history (localStorage).
 *
 * - Survives page refresh and closing/reopening the browser on the same machine.
 * - Stays on this browser/origin only — not a shared server list, so other users
 *   on the server cannot see your history.
 * - Entries are session IDs; reopening a run loads it from the server if still
 *   available (sessions may expire/be cleaned up independently).
 */

export interface HistoryEntry {
  id: string;
  filename: string;
  vendor: string;
  vendorDisplay: string;
  /** ISO timestamp when this run was recorded */
  at: string;
}

const STORAGE_KEY = "fwconfig_run_history_v1";
const MAX_ENTRIES = 10;

function storage(): Storage | null {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    return null;
  }
}

/** One-time migrate from older sessionStorage history if present. */
function migrateFromSessionStorage(store: Storage): void {
  try {
    if (typeof sessionStorage === "undefined") return;
    if (store.getItem(STORAGE_KEY)) return;
    const legacy = sessionStorage.getItem(STORAGE_KEY);
    if (!legacy) return;
    store.setItem(STORAGE_KEY, legacy);
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

function parseList(raw: string | null): HistoryEntry[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (e): e is HistoryEntry =>
          !!e &&
          typeof e === "object" &&
          typeof (e as HistoryEntry).id === "string" &&
          !!(e as HistoryEntry).id
      )
      .slice(0, MAX_ENTRIES);
  } catch {
    return [];
  }
}

export function readHistory(): HistoryEntry[] {
  const store = storage();
  if (!store) return [];
  migrateFromSessionStorage(store);
  return parseList(store.getItem(STORAGE_KEY));
}

function writeHistory(entries: HistoryEntry[]): void {
  const store = storage();
  if (!store) return;
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(entries.slice(0, MAX_ENTRIES)));
  } catch {
    /* quota / private mode */
  }
}

/** Record or bump a successful analysis run (max 10, most recent first). */
export function recordHistoryEntry(entry: {
  id: string;
  filename?: string | null;
  vendor?: string | null;
  vendorDisplay?: string | null;
}): HistoryEntry[] {
  if (!entry.id) return readHistory();
  const next: HistoryEntry = {
    id: entry.id,
    filename: entry.filename || "configuration",
    vendor: entry.vendor || "unknown",
    vendorDisplay: entry.vendorDisplay || entry.vendor || "Unknown",
    at: new Date().toISOString(),
  };
  const prev = readHistory().filter((e) => e.id !== next.id);
  const list = [next, ...prev].slice(0, MAX_ENTRIES);
  writeHistory(list);
  return list;
}

export function removeHistoryEntry(id: string): HistoryEntry[] {
  const list = readHistory().filter((e) => e.id !== id);
  writeHistory(list);
  return list;
}

export function formatHistoryWhen(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}
