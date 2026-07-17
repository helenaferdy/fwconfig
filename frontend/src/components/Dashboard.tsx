"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "@/lib/api";
import {
  buildCompareDiff,
  matchMapBoth,
  mergeSections,
  objectMatchKey,
  sharedSectionTypes,
} from "@/lib/compareDiff";
import {
  formatHistoryWhen,
  readHistory,
  recordHistoryEntry,
  removeHistoryEntry,
  type HistoryEntry,
} from "@/lib/history";
import type { AIAction, MigrationSession, ParsedObject, SummarySection } from "@/lib/types";
import { ConfigExplorer } from "./ConfigExplorer";
import { CenterPane } from "./CenterPane";
import { RightPane } from "./RightPane";
import { SectionNav } from "./SectionNav";
import { LandingArt } from "./LandingArt";
import { UploadPane } from "./UploadPane";
import { ChevronIcon, ResetIcon, ShieldIcon } from "./icons";

function summarySectionsOf(s: MigrationSession | null): SummarySection[] {
  if (!s) return [];
  return s.summary_sections || s.generated_sections || [];
}

function hasSummary(s: MigrationSession | null): boolean {
  if (!s) return false;
  return Boolean(s.has_summary ?? s.has_generated_config ?? summarySectionsOf(s).length);
}

function rememberRun(s: MigrationSession): HistoryEntry[] {
  return recordHistoryEntry({
    id: s.id,
    filename: s.filename,
    vendor: s.source_vendor,
    vendorDisplay: s.source_vendor_display || s.source_vendor,
  });
}

export function Dashboard() {
  const [session, setSession] = useState<MigrationSession | null>(null);
  const [sessionB, setSessionB] = useState<MigrationSession | null>(null);
  const [compareMode, setCompareMode] = useState(false);
  const [selectedSection, setSelectedSection] = useState<string | null>(null);
  const [selectedObjectId, setSelectedObjectId] = useState<string | null>(null);
  const [selectedObjectName, setSelectedObjectName] = useState<string | null>(null);
  const [selectedMatchKey, setSelectedMatchKey] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadingB, setUploadingB] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [chatBusy, setChatBusy] = useState(false);
  const [introPending, setIntroPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyLoadingId, setHistoryLoadingId] = useState<string | null>(null);

  const [aiHighlights, setAiHighlights] = useState<string[]>([]);
  const [aiNotes, setAiNotes] = useState<Record<string, string>>({});

  const [ratios, setRatios] = useState([3, 5, 2.5]);
  const dragging = useRef<number | null>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const introPollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const introSessionRef = useRef<string | null>(null);
  const historyWrapRef = useRef<HTMLDivElement>(null);

  const stopIntroPoll = useCallback(() => {
    if (introPollRef.current) {
      clearTimeout(introPollRef.current);
      introPollRef.current = null;
    }
    introSessionRef.current = null;
    setIntroPending(false);
  }, []);

  /** Poll session until AI intro assistant message appears (or timeout). */
  const pollForIntro = useCallback(
    (sessionId: string) => {
      stopIntroPoll();
      introSessionRef.current = sessionId;
      setIntroPending(true);
      const started = Date.now();
      const maxMs = 90_000;
      const tick = async () => {
        if (introSessionRef.current !== sessionId) return;
        try {
          const s = await api.getSession(sessionId);
          if (introSessionRef.current !== sessionId) return;
          const hasAssistant = (s.chat_history || []).some(
            (m) => m.role === "assistant" && m.content?.trim()
          );
          if (hasAssistant) {
            // Intro only — keep left/mid on full overview (no section jump)
            setSession((prev) => {
              if (!prev || prev.id !== sessionId) return prev;
              return {
                ...prev,
                chat_history: s.chat_history,
                original_config: prev.original_config ?? s.original_config,
              };
            });
            setIntroPending(false);
            introSessionRef.current = null;
            return;
          }
        } catch {
          /* keep polling */
        }
        if (Date.now() - started >= maxMs) {
          setIntroPending(false);
          introSessionRef.current = null;
          return;
        }
        introPollRef.current = setTimeout(tick, 1200);
      };
      introPollRef.current = setTimeout(tick, 800);
    },
    [stopIntroPoll]
  );

  /**
   * After config B loads: schedule compare intro (async) and poll A’s chat
   * until a compare_intro message for this B appears.
   */
  const triggerCompareIntro = useCallback(
    async (sessionAId: string, sessionBId: string) => {
      if (!sessionAId || !sessionBId || sessionAId === sessionBId) return;
      stopIntroPoll();
      introSessionRef.current = `compare:${sessionAId}:${sessionBId}`;
      setIntroPending(true);
      try {
        await api.scheduleCompareIntro(sessionAId, sessionBId);
      } catch (e) {
        setIntroPending(false);
        introSessionRef.current = null;
        setError(
          e instanceof Error ? e.message : "Could not start compare intro"
        );
        return;
      }
      const pollKey = `compare:${sessionAId}:${sessionBId}`;
      const started = Date.now();
      const maxMs = 90_000;
      const hasCompareIntro = (hist: MigrationSession["chat_history"]) =>
        (hist || []).some(
          (m) =>
            m.role === "assistant" &&
            m.content?.trim() &&
            (m.metadata as { kind?: string; compare_session_id?: string } | null)
              ?.kind === "compare_intro" &&
            (m.metadata as { compare_session_id?: string } | null)
              ?.compare_session_id === sessionBId
        );

      const tick = async () => {
        if (introSessionRef.current !== pollKey) return;
        try {
          const s = await api.getSession(sessionAId);
          if (introSessionRef.current !== pollKey) return;
          if (hasCompareIntro(s.chat_history)) {
            setSession((prev) => {
              if (!prev || prev.id !== sessionAId) return prev;
              return {
                ...prev,
                chat_history: s.chat_history,
                original_config: prev.original_config ?? s.original_config,
              };
            });
            setIntroPending(false);
            introSessionRef.current = null;
            return;
          }
        } catch {
          /* keep polling */
        }
        if (Date.now() - started >= maxMs) {
          setIntroPending(false);
          introSessionRef.current = null;
          return;
        }
        introPollRef.current = setTimeout(tick, 1200);
      };
      introPollRef.current = setTimeout(tick, 600);
    },
    [stopIntroPoll]
  );

  useEffect(() => {
    return () => {
      if (introPollRef.current) clearTimeout(introPollRef.current);
    };
  }, []);

  // Per-browser history (localStorage) — survives refresh; not shared server-side
  useEffect(() => {
    setHistory(readHistory());
  }, []);

  useEffect(() => {
    if (!historyOpen) return;
    const onDoc = (e: MouseEvent) => {
      const el = historyWrapRef.current;
      if (el && !el.contains(e.target as Node)) setHistoryOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setHistoryOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [historyOpen]);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (dragging.current === null || !gridRef.current) return;
      const rect = gridRef.current.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const total = rect.width;
      const handle = dragging.current;
      const min = 0.12;
      setRatios((prev) => {
        const next = [...prev];
        const sum = prev.reduce((a, b) => a + b, 0);
        if (handle === 0) {
          const leftFrac = Math.min(Math.max(x / total, min), 1 - min * 2);
          const left = leftFrac * sum;
          const rest = sum - left;
          const centerShare = prev[1] / (prev[1] + prev[2]);
          next[0] = left;
          next[1] = rest * centerShare;
          next[2] = rest * (1 - centerShare);
        } else {
          const leftPx = (prev[0] / sum) * total;
          const midFrac = Math.min(
            Math.max((x - leftPx) / total, min),
            1 - prev[0] / sum - min
          );
          next[1] = midFrac * sum;
          next[2] = sum - next[0] - next[1];
        }
        return next;
      });
    };
    const onUp = () => {
      dragging.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  const startDrag = (index: number) => {
    dragging.current = index;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  const applyAiActions = useCallback((actions: AIAction[]) => {
    if (!actions?.length) return;
    let highlights: string[] = [];
    let clear = false;
    const notes: Record<string, string> = {};

    for (const a of actions) {
      if (a.type === "clear_highlights") {
        clear = true;
        highlights = [];
        continue;
      }
      if (
        (a.type === "highlight" || a.type === "annotate") &&
        a.section
      ) {
        highlights.push(a.section);
      }
      if (a.section && a.note) {
        notes[a.section] = a.note;
      }
    }

    if (clear) {
      setAiHighlights([]);
      setAiNotes({});
    }
    if (highlights.length) {
      // Dedupe while preserving order; mid pane shows the first section
      const unique = Array.from(new Set(highlights));
      setAiHighlights(unique);
      setSelectedSection(unique[0]);
      setSelectedObjectId(null);
      setSelectedObjectName(null);
      setSelectedMatchKey(null);
    }
    if (Object.keys(notes).length) {
      setAiNotes((prev) => ({ ...prev, ...notes }));
    }
  }, []);

  const handleUpload = useCallback(
    async (
      fileOrFiles: File | File[],
      sourceVendor: string,
      onProgress: (p: api.UploadProgress) => void
    ) => {
      setUploading(true);
      setError(null);
      stopIntroPoll();
      try {
        const s = await api.uploadConfigWithProgress(
          fileOrFiles,
          sourceVendor,
          onProgress
        );
        // Show left/mid panes — AI intro may still arrive async
        setSession(s);
        setSelectedSection(null);
        setSelectedObjectId(null);
        setSelectedObjectName(null);
      setSelectedMatchKey(null);
        setAiHighlights([]);
        setAiNotes({});
        setHistory(rememberRun(s));
        const needsIntro =
          (s.pipeline_stage || "").toLowerCase() === "done" &&
          !(s.chat_history || []).some((m) => m.role === "assistant");
        if (needsIntro) {
          pollForIntro(s.id);
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Upload failed");
        throw e;
      } finally {
        setUploading(false);
      }
    },
    [pollForIntro, stopIntroPoll]
  );

  const handleAnalyze = useCallback(async () => {
    if (!session) return;
    setAnalyzing(true);
    setError(null);
    stopIntroPoll();
    try {
      const s = await api.analyzeSession(session.id);
      setSession((prev) => ({
        ...s,
        original_config: s.original_config ?? prev?.original_config,
        // preserve chat if re-analyze kept history
        chat_history: s.chat_history?.length
          ? s.chat_history
          : prev?.chat_history || [],
      }));
      setHistory(rememberRun(s));
      const needsIntro =
        (s.pipeline_stage || "").toLowerCase() === "done" &&
        !(s.chat_history || []).some((m) => m.role === "assistant");
      if (needsIntro) {
        pollForIntro(s.id);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  }, [session, pollForIntro, stopIntroPoll]);

  const openHistoryRun = useCallback(
    async (entry: HistoryEntry) => {
      if (historyLoadingId) return;
      if (session?.id === entry.id) {
        setHistoryOpen(false);
        return;
      }
      setHistoryLoadingId(entry.id);
      setError(null);
      stopIntroPoll();
      try {
        const s = await api.getSession(entry.id, true);
        setSession(s);
        // If new A is the same run as B, drop B
        setSessionB((prev) => (prev && prev.id === s.id ? null : prev));
        setSelectedSection(null);
        setSelectedObjectId(null);
        setSelectedObjectName(null);
      setSelectedMatchKey(null);
        setAiHighlights([]);
        setAiNotes({});
        setHistory(rememberRun(s));
        setHistoryOpen(false);
        const needsIntro =
          (s.pipeline_stage || "").toLowerCase() === "done" &&
          !(s.chat_history || []).some((m) => m.role === "assistant");
        if (needsIntro) {
          pollForIntro(s.id);
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Could not open run";
        // Expired / deleted server-side — drop from this browser's history
        if (/404|not found/i.test(msg)) {
          setHistory(removeHistoryEntry(entry.id));
          setError("That run is no longer available on the server.");
        } else {
          setError(msg);
        }
      } finally {
        setHistoryLoadingId(null);
      }
    },
    [historyLoadingId, session?.id, pollForIntro, stopIntroPoll]
  );

  const handleChat = useCallback(
    async (message: string) => {
      if (!session) return;
      setChatBusy(true);
      const tempId = `tmp-${Date.now()}`;
      setSession((prev) =>
        prev
          ? {
              ...prev,
              chat_history: [
                ...prev.chat_history,
                {
                  id: tempId,
                  role: "user",
                  content: message,
                  timestamp: new Date().toISOString(),
                },
              ],
            }
          : prev
      );
      try {
        const res = await api.chat(
          session.id,
          message,
          false,
          compareMode && sessionB ? sessionB.id : null
        );
        applyAiActions(res.actions || []);

        setSession((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            chat_history: [
              ...prev.chat_history.filter((m) => m.id !== tempId),
              {
                id: tempId,
                role: "user",
                content: message,
                timestamp: new Date().toISOString(),
              },
              {
                id: res.message_id,
                role: "assistant",
                content: res.reply,
                timestamp: new Date().toISOString(),
              },
            ],
            summary_sections:
              res.generated_sections?.length > 0
                ? res.generated_sections
                : prev.summary_sections,
            generated_sections:
              res.generated_sections?.length > 0
                ? res.generated_sections
                : prev.generated_sections,
            generated_config:
              res.generated_config !== undefined
                ? res.generated_config
                : prev.generated_config,
            has_summary:
              res.has_generated_config ?? prev.has_summary ?? prev.has_generated_config,
            has_generated_config:
              res.has_generated_config ?? prev.has_generated_config,
            pipeline_log: res.pipeline_log?.length
              ? res.pipeline_log
              : prev.pipeline_log,
          };
        });
      } catch (e) {
        setSession((prev) =>
          prev
            ? {
                ...prev,
                chat_history: [
                  ...prev.chat_history,
                  {
                    id: `err-${Date.now()}`,
                    role: "assistant",
                    content: e instanceof Error ? e.message : "Chat failed",
                    timestamp: new Date().toISOString(),
                  },
                ],
              }
            : prev
        );
      } finally {
        setChatBusy(false);
      }
    },
    [session, sessionB, compareMode, applyAiActions]
  );

  const handleSelectSection = useCallback((sectionType: string) => {
    if (!sectionType) {
      setSelectedSection(null);
      setSelectedObjectId(null);
      setSelectedObjectName(null);
      setSelectedMatchKey(null);
      return;
    }
    setSelectedSection(sectionType);
    setSelectedObjectId(null);
    setSelectedObjectName(null);
    setSelectedMatchKey(null);
  }, []);

  const handleSelectObject = useCallback(
    (sectionType: string, obj: ParsedObject) => {
      setSelectedSection(sectionType);
      setSelectedObjectId(obj.id ? String(obj.id) : obj.name);
      setSelectedObjectName(obj.name);
      setSelectedMatchKey(objectMatchKey(obj, sectionType));
    },
    []
  );

  const enterCompare = useCallback(() => {
    if (!session) return;
    setCompareMode(true);
    setError(null);
  }, [session]);

  const exitCompare = useCallback(() => {
    setCompareMode(false);
    setSessionB(null);
    setUploadingB(false);
  }, []);

  const handleUploadB = useCallback(
    async (
      fileOrFiles: File | File[],
      sourceVendor: string,
      onProgress: (p: api.UploadProgress) => void
    ) => {
      if (!session) return;
      setUploadingB(true);
      setError(null);
      try {
        const s = await api.uploadConfigWithProgress(
          fileOrFiles,
          sourceVendor,
          onProgress
        );
        if (s.id === session.id) {
          setError("Compare target must be a different configuration.");
          return;
        }
        setSessionB(s);
        setHistory(rememberRun(s));
        void triggerCompareIntro(session.id, s.id);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Upload failed");
        throw e;
      } finally {
        setUploadingB(false);
      }
    },
    [session, triggerCompareIntro]
  );

  const openHistoryRunB = useCallback(
    async (entry: HistoryEntry) => {
      if (!session || historyLoadingId) return;
      if (entry.id === session.id) {
        setError("That run is already the primary configuration (A).");
        return;
      }
      if (sessionB?.id === entry.id) return;
      setHistoryLoadingId(entry.id);
      setError(null);
      try {
        const s = await api.getSession(entry.id, true);
        if (s.id === session.id) {
          setError("Compare target must be a different configuration.");
          return;
        }
        setSessionB(s);
        setHistory(rememberRun(s));
        void triggerCompareIntro(session.id, s.id);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Could not open run";
        if (/404|not found/i.test(msg)) {
          setHistory(removeHistoryEntry(entry.id));
          setError("That run is no longer available on the server.");
        } else {
          setError(msg);
        }
      } finally {
        setHistoryLoadingId(null);
      }
    },
    [session, sessionB?.id, historyLoadingId, triggerCompareIntro]
  );

  const resetSession = () => {
    stopIntroPoll();
    setSession(null);
    setSessionB(null);
    setCompareMode(false);
    setUploadingB(false);
    setSelectedSection(null);
    setSelectedObjectId(null);
    setSelectedObjectName(null);
      setSelectedMatchKey(null);
    setError(null);
    setAiHighlights([]);
    setAiNotes({});
  };

  const navSections = useMemo(() => {
    if (!session) return [];
    if (compareMode && sessionB) {
      return mergeSections(session.parsed_sections, sessionB.parsed_sections);
    }
    if (compareMode) {
      return mergeSections(session.parsed_sections, undefined);
    }
    return session.parsed_sections;
  }, [session, sessionB, compareMode]);

  const diffBySection = useMemo(() => {
    if (!compareMode || !session || !sessionB) return null;
    return buildCompareDiff(session.parsed_sections, sessionB.parsed_sections);
  }, [compareMode, session, sessionB]);

  const sharedSections = useMemo(() => {
    if (!compareMode || !session || !sessionB) return undefined;
    return sharedSectionTypes(session.parsed_sections, sessionB.parsed_sections);
  }, [compareMode, session, sessionB]);

  /** Objects present on both A and B — green highlight in mid panes */
  const matchMap = useMemo(() => {
    if (!diffBySection || !selectedSection) return undefined;
    return matchMapBoth(diffBySection.get(selectedSection));
  }, [diffBySection, selectedSection]);

  const historyForB = useMemo(
    () => history.filter((e) => e.id !== session?.id),
    [history, session?.id]
  );

  const sectionOnA = useMemo(() => {
    if (!selectedSection || !session) return true;
    return session.parsed_sections.some(
      (s) =>
        s.section_type === selectedSection &&
        (s.object_count > 0 || (s.objects || []).length > 0)
    );
  }, [session, selectedSection]);

  const sectionOnB = useMemo(() => {
    if (!selectedSection || !sessionB) return true;
    return sessionB.parsed_sections.some(
      (s) =>
        s.section_type === selectedSection &&
        (s.object_count > 0 || (s.objects || []).length > 0)
    );
  }, [sessionB, selectedSection]);

  const style = {
    ["--pane-left" as string]: `${ratios[0]}fr`,
    ["--pane-center" as string]: `${ratios[1]}fr`,
    ["--pane-right" as string]: `${ratios[2]}fr`,
  };

  return (
    <div className="flex h-screen flex-col bg-[var(--bg)] text-[var(--fg)] font-mono">
      <header className="app-topbar flex h-9 shrink-0 items-center justify-between gap-3 border-b border-[var(--border)] px-3">
        <div className="flex min-w-0 items-center gap-2">
          <ShieldIcon className="h-3.5 w-3.5 shrink-0" />
          <h1 className="shrink-0 text-[12px] tracking-wide font-medium">
            FW Config Analyzer
          </h1>
          {(session || history.length > 0) && (
            <>
              <span
                className="shrink-0 text-[var(--fg-inverse-faint)] select-none"
                aria-hidden
              >
                |
              </span>
              <div className="relative min-w-0" ref={historyWrapRef}>
                <button
                  type="button"
                  className="history-trigger"
                  aria-haspopup="listbox"
                  aria-expanded={historyOpen}
                  aria-label={
                    session
                      ? `Current configuration ${[
                          session.source_vendor_display,
                          session.filename,
                        ]
                          .filter(Boolean)
                          .join(" ")}. Open run history`
                      : "Open run history"
                  }
                  title="Click to open recent runs (saved in this browser)"
                  onClick={() => setHistoryOpen((v) => !v)}
                >
                  <span className="history-trigger-label">
                    {session
                      ? [
                          session.source_vendor_display || null,
                          session.filename || null,
                        ]
                          .filter(Boolean)
                          .join(" · ")
                      : "Recent runs"}
                  </span>
                  <ChevronIcon
                    open={historyOpen}
                    className="history-trigger-chevron"
                  />
                </button>
                {historyOpen && (
                  <div
                    className="history-menu"
                    role="listbox"
                    aria-label="Recent analysis runs"
                  >
                    {history.length === 0 ? (
                      <div className="history-menu-empty">
                        No previous runs yet.
                      </div>
                    ) : (
                      history.map((entry) => {
                        const active = session?.id === entry.id;
                        const busy = historyLoadingId === entry.id;
                        const label = [entry.vendorDisplay, entry.filename]
                          .filter(Boolean)
                          .join(" · ");
                        return (
                          <button
                            key={entry.id}
                            type="button"
                            role="option"
                            aria-selected={active}
                            className={`history-menu-item ${active ? "is-active" : ""}`}
                            disabled={!!historyLoadingId}
                            onClick={() => void openHistoryRun(entry)}
                          >
                            <span className="history-menu-title">
                              {busy ? "Opening… " : ""}
                              {label}
                            </span>
                            <span className="history-menu-meta">
                              {formatHistoryWhen(entry.at)}
                              {active ? " · current" : ""}
                            </span>
                          </button>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
              {session && !compareMode && (
                <button
                  type="button"
                  className="btn-outline"
                  onClick={enterCompare}
                  title="Compare with another configuration"
                >
                  compare
                </button>
              )}
              {session && compareMode && (
                <>
                  <button
                    type="button"
                    className="btn-outline btn-compare-active"
                    onClick={exitCompare}
                    title="Exit compare mode"
                  >
                    exit compare
                  </button>
                  {sessionB && (
                    <span
                      className="compare-vs-label"
                      title={[
                        sessionB.source_vendor_display,
                        sessionB.filename,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    >
                      vs{" "}
                      {[
                        sessionB.source_vendor_display || null,
                        sessionB.filename || null,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </span>
                  )}
                </>
              )}
            </>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {error && (
            <span className="max-w-[200px] truncate text-[10px] text-[var(--fg)]">
              {error}
            </span>
          )}
          {session && (
            <button type="button" className="btn-outline" onClick={resetSession}>
              <ResetIcon className="h-3 w-3" /> new
            </button>
          )}
        </div>
      </header>

      {!session ? (
        <div className="dashboard-landing panel min-h-0">
          <LandingArt />
          <div className="landing-upload-slot">
            <UploadPane
              onUpload={handleUpload}
              busy={uploading}
              history={history}
              historyLoadingId={historyLoadingId}
              onPickHistory={(entry) => void openHistoryRun(entry)}
            />
          </div>
        </div>
      ) : (
      <div
        ref={gridRef}
        className="dashboard-grid min-h-0 flex-1 p-0"
        style={style}
      >
        <div className="panel min-h-0 overflow-hidden border-r border-[var(--border)]">
          {compareMode ? (
            <div className="compare-stack">
              <div className="compare-half">
                <ConfigExplorer
                  sections={session.parsed_sections}
                  originalConfig={session.original_config}
                  selectedSection={selectedSection}
                  selectedObjectId={selectedObjectId}
                  selectedMatchKey={selectedMatchKey}
                  onSelectSection={handleSelectSection}
                  sideLabel="A"
                  emptySectionMessage={
                    selectedSection && !sectionOnA
                      ? "Not present in A"
                      : null
                  }
                />
              </div>
              <div className="compare-half">
                {sessionB ? (
                  <ConfigExplorer
                    sections={sessionB.parsed_sections}
                    originalConfig={sessionB.original_config}
                    selectedSection={selectedSection}
                    selectedObjectId={selectedObjectId}
                    selectedMatchKey={selectedMatchKey}
                    onSelectSection={handleSelectSection}
                    sideLabel="B"
                    emptySectionMessage={
                      selectedSection && !sectionOnB
                        ? "Not present in B"
                        : null
                    }
                  />
                ) : (
                  <CompareLoadPane
                    history={historyForB}
                    historyLoadingId={historyLoadingId}
                    uploading={uploadingB}
                    onUpload={handleUploadB}
                    onPickHistory={openHistoryRunB}
                  />
                )}
              </div>
            </div>
          ) : (
            <ConfigExplorer
              sections={session.parsed_sections}
              originalConfig={session.original_config}
              selectedSection={selectedSection}
              selectedObjectId={selectedObjectId}
              selectedMatchKey={selectedMatchKey}
              onSelectSection={handleSelectSection}
            />
          )}
        </div>

        <div
          className="resize-handle"
          onMouseDown={() => startDrag(0)}
          role="separator"
          aria-orientation="vertical"
        />

        <div className="panel min-h-0 overflow-hidden">
          {compareMode && session ? (
            <div className="compare-stack">
              <div className="compare-half">
                <CenterPane
                  analyzing={analyzing || uploading}
                  hasSession
                  hasSummary={hasSummary(session)}
                  parsedSections={session.parsed_sections}
                  summarySections={summarySectionsOf(session)}
                  selectedSection={selectedSection}
                  selectedObjectId={selectedObjectId}
                  selectedObjectName={selectedObjectName}
                  selectedMatchKey={selectedMatchKey}
                  aiHighlights={aiHighlights}
                  aiNotes={aiNotes}
                  vendorDisplay={session.source_vendor_display}
                  onAnalyze={handleAnalyze}
                  onSelectSection={handleSelectSection}
                  onSelectObject={handleSelectObject}
                  matchMap={matchMap}
                  sideLabel="A"
                  emptySectionMessage={
                    selectedSection && !sectionOnA
                      ? "Not present in A"
                      : null
                  }
                />
              </div>
              <div className="compare-half">
                {sessionB ? (
                  <CenterPane
                    analyzing={uploadingB}
                    hasSession
                    hasSummary={hasSummary(sessionB)}
                    parsedSections={sessionB.parsed_sections}
                    summarySections={summarySectionsOf(sessionB)}
                    selectedSection={selectedSection}
                    selectedObjectId={selectedObjectId}
                    selectedObjectName={selectedObjectName}
                    selectedMatchKey={selectedMatchKey}
                    vendorDisplay={sessionB.source_vendor_display}
                    onSelectSection={handleSelectSection}
                    onSelectObject={handleSelectObject}
                    matchMap={matchMap}
                    sideLabel="B"
                    hideRefresh
                    emptySectionMessage={
                      selectedSection && !sectionOnB
                        ? "Not present in B"
                        : null
                    }
                  />
                ) : (
                  <div className="compare-mid-empty">
                    <p className="meta">
                      Load configuration B in the left pane to compare
                    </p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <CenterPane
              analyzing={analyzing || uploading}
              hasSession={!!session}
              hasSummary={hasSummary(session)}
              parsedSections={session?.parsed_sections || []}
              summarySections={summarySectionsOf(session)}
              selectedSection={selectedSection}
              selectedObjectId={selectedObjectId}
              selectedObjectName={selectedObjectName}
              selectedMatchKey={selectedMatchKey}
              aiHighlights={aiHighlights}
              aiNotes={aiNotes}
              vendorDisplay={session?.source_vendor_display}
              onAnalyze={session ? handleAnalyze : undefined}
              onSelectSection={handleSelectSection}
              onSelectObject={handleSelectObject}
            />
          )}
        </div>

        <div
          className="resize-handle"
          onMouseDown={() => startDrag(1)}
          role="separator"
          aria-orientation="vertical"
        />

        <div className="panel min-h-0 overflow-hidden border-l border-[var(--border)]">
          <div className="right-pane-split">
            {session && (
              <div className="right-pane-sections">
                <SectionNav
                  sections={navSections}
                  selectedSection={selectedSection}
                  onSelectSection={handleSelectSection}
                  sharedSections={sharedSections}
                />
              </div>
            )}
            <div className="right-pane-chat">
              <RightPane
                chatHistory={session?.chat_history || []}
                onSendChat={handleChat}
                chatBusy={chatBusy}
                introPending={introPending}
                hasSession={!!session}
                hasSummary={hasSummary(session)}
              />
            </div>
          </div>
        </div>
      </div>
      )}
    </div>
  );
}

/** Compact centered load-B panel: 4-brand upload + history dropdown. */
function CompareLoadPane({
  history,
  historyLoadingId,
  uploading,
  onUpload,
  onPickHistory,
}: {
  history: HistoryEntry[];
  historyLoadingId: string | null;
  uploading: boolean;
  onUpload: (
    files: File | File[],
    sourceVendor: string,
    onProgress: (p: api.UploadProgress) => void
  ) => Promise<void>;
  onPickHistory: (entry: HistoryEntry) => void;
}) {
  return (
    <div className="compare-load">
      <div className="pane-header shrink-0">
        <span className="font-medium">Compare · B</span>
        <span className="meta"> · pick a configuration</span>
      </div>
      <div className="compare-load-body compare-load-body-center">
        <div className="compare-load-center">
          <p className="compare-load-history-label">Upload</p>
          <UploadPane onUpload={onUpload} busy={uploading} compact />
          <p className="compare-load-history-label" style={{ marginTop: 10 }}>
            Or load from history
          </p>
          <select
            className="compare-history-select"
            disabled={uploading || !!historyLoadingId || history.length === 0}
            value=""
            aria-label="Load configuration from history"
            onChange={(e) => {
              const id = e.target.value;
              if (!id) return;
              const entry = history.find((h) => h.id === id);
              if (entry) onPickHistory(entry);
              e.target.value = "";
            }}
          >
            <option value="">
              {history.length === 0
                ? "No other runs yet"
                : historyLoadingId
                  ? "Opening…"
                  : "Select a recent run…"}
            </option>
            {history.map((entry) => {
              const label = [entry.vendorDisplay, entry.filename]
                .filter(Boolean)
                .join(" · ");
              const when = formatHistoryWhen(entry.at);
              return (
                <option key={entry.id} value={entry.id}>
                  {label}
                  {when ? ` · ${when}` : ""}
                </option>
              );
            })}
          </select>
        </div>
      </div>
    </div>
  );
}
