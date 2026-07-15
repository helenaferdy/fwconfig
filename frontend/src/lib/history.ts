/**
 * Per-browser-tab run history (sessionStorage only).
 * Never stored server-side as a user feed — other users cannot see these entries.
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

function canUseStorage(): boolean {
  try {
    return typeof sessionStorage !== "undefined";
  } catch {
    return false;
  }
}

export function readHistory(): HistoryEntry[] {
  if (!canUseStorage()) return [];
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
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

function writeHistory(entries: HistoryEntry[]): void {
  if (!canUseStorage()) return;
  try {
    sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(entries.slice(0, MAX_ENTRIES))
    );
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
