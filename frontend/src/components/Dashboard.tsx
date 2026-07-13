"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "@/lib/api";
import type { AIAction, MigrationSession, ParsedObject, SummarySection } from "@/lib/types";
import { ConfigExplorer } from "./ConfigExplorer";
import { CenterPane } from "./CenterPane";
import { RightPane } from "./RightPane";
import { UploadPane } from "./UploadPane";
import { ResetIcon, ShieldIcon } from "./icons";

function summarySectionsOf(s: MigrationSession | null): SummarySection[] {
  if (!s) return [];
  return s.summary_sections || s.generated_sections || [];
}

function hasSummary(s: MigrationSession | null): boolean {
  if (!s) return false;
  return Boolean(s.has_summary ?? s.has_generated_config ?? summarySectionsOf(s).length);
}

export function Dashboard() {
  const [session, setSession] = useState<MigrationSession | null>(null);
  const [selectedSection, setSelectedSection] = useState<string | null>(null);
  const [selectedObjectId, setSelectedObjectId] = useState<string | null>(null);
  const [selectedObjectName, setSelectedObjectName] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [chatBusy, setChatBusy] = useState(false);
  const [introPending, setIntroPending] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [aiHighlights, setAiHighlights] = useState<string[]>([]);
  const [aiNotes, setAiNotes] = useState<Record<string, string>>({});

  const [ratios, setRatios] = useState([4, 4, 2]);
  const dragging = useRef<number | null>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const introPollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const introSessionRef = useRef<string | null>(null);

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

  useEffect(() => {
    return () => {
      if (introPollRef.current) clearTimeout(introPollRef.current);
    };
  }, []);

  useEffect(() => {
    api
      .getHealth()
      .then((h) => setAiEnabled(h.ai_enabled))
      .catch(() => {});
  }, []);

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
    }
    if (Object.keys(notes).length) {
      setAiNotes((prev) => ({ ...prev, ...notes }));
    }
  }, []);

  const handleUpload = useCallback(
    async (file: File) => {
      setUploading(true);
      setError(null);
      stopIntroPoll();
      try {
        const s = await api.uploadConfig(file);
        // Show left/mid panes immediately — AI intro arrives async
        setSession(s);
        setSelectedSection(null);
        setSelectedObjectId(null);
        setSelectedObjectName(null);
        setAiHighlights([]);
        setAiNotes({});
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
        const res = await api.chat(session.id, message);
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
    [session, applyAiActions]
  );

  const handleSelectSection = useCallback((sectionType: string) => {
    if (!sectionType) {
      setSelectedSection(null);
      setSelectedObjectId(null);
      setSelectedObjectName(null);
      return;
    }
    setSelectedSection(sectionType);
    setSelectedObjectId(null);
    setSelectedObjectName(null);
  }, []);

  const handleSelectObject = useCallback(
    (sectionType: string, obj: ParsedObject) => {
      setSelectedSection(sectionType);
      setSelectedObjectId(obj.id ? String(obj.id) : obj.name);
      setSelectedObjectName(obj.name);
    },
    []
  );

  const resetSession = () => {
    stopIntroPoll();
    setSession(null);
    setSelectedSection(null);
    setSelectedObjectId(null);
    setSelectedObjectName(null);
    setError(null);
    setAiHighlights([]);
    setAiNotes({});
  };

  const style = {
    ["--pane-left" as string]: `${ratios[0]}fr`,
    ["--pane-center" as string]: `${ratios[1]}fr`,
    ["--pane-right" as string]: `${ratios[2]}fr`,
  };

  return (
    <div className="flex h-screen flex-col bg-[var(--bg)] text-[var(--fg)] font-mono">
      <header className="flex h-9 shrink-0 items-center justify-between border-b border-[var(--border)] bg-[var(--bg-panel)] px-3">
        <div className="flex items-center gap-1.5">
          <ShieldIcon className="h-3.5 w-3.5 text-[var(--fg)]" />
          <h1 className="text-[11px] text-[var(--fg)] tracking-wider uppercase font-medium">
            FWM
          </h1>
          <span className="badge">analysis</span>
        </div>
        <div className="flex items-center gap-2">
          {error && (
            <span className="max-w-[200px] truncate text-[10px] text-[var(--fg)]">
              {error}
            </span>
          )}
          <span className="badge">{aiEnabled ? "ai on" : "ai off"}</span>
          {session && (
            <button type="button" className="btn-ghost" onClick={resetSession}>
              <ResetIcon className="h-3 w-3" /> reset
            </button>
          )}
        </div>
      </header>

      <div
        ref={gridRef}
        className="dashboard-grid min-h-0 flex-1 p-0"
        style={style}
      >
        <div className="panel min-h-0 overflow-hidden border-r border-[var(--border)]">
          {!session ? (
            <UploadPane onUpload={handleUpload} busy={uploading} />
          ) : (
            <ConfigExplorer
              sections={session.parsed_sections}
              originalConfig={session.original_config}
              selectedSection={selectedSection}
              selectedObjectId={selectedObjectId}
              onSelectSection={handleSelectSection}
              onSelectObject={handleSelectObject}
              filename={session.filename}
              vendorDisplay={session.source_vendor_display}
              stats={{
                total_objects: session.statistics?.total_objects ?? 0,
                source_lines: session.statistics?.source_lines ?? 0,
              }}
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
          <CenterPane
            analyzing={analyzing || uploading}
            hasSession={!!session}
            hasSummary={hasSummary(session)}
            parsedSections={session?.parsed_sections || []}
            summarySections={summarySectionsOf(session)}
            selectedSection={selectedSection}
            selectedObjectId={selectedObjectId}
            selectedObjectName={selectedObjectName}
            aiHighlights={aiHighlights}
            aiNotes={aiNotes}
            vendorDisplay={session?.source_vendor_display}
            onAnalyze={session ? handleAnalyze : undefined}
            onSelectSection={handleSelectSection}
            onSelectObject={handleSelectObject}
          />
        </div>

        <div
          className="resize-handle"
          onMouseDown={() => startDrag(1)}
          role="separator"
          aria-orientation="vertical"
        />

        <div className="panel min-h-0 overflow-hidden border-l border-[var(--border)]">
          <RightPane
            log={session?.pipeline_log || []}
            warnings={session?.warnings || []}
            chatHistory={session?.chat_history || []}
            onSendChat={handleChat}
            chatBusy={chatBusy}
            introPending={introPending}
            hasSession={!!session}
            pipelineStage={session?.pipeline_stage}
            hasSummary={hasSummary(session)}
          />
        </div>
      </div>
    </div>
  );
}
