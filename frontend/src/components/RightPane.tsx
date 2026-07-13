"use client";

import React, { useEffect, useRef, useState } from "react";
import type { ChatMessage, MigrationWarning, PipelineLogEntry } from "@/lib/types";
import { SendIcon, SpinnerIcon } from "./icons";

interface Props {
  log: PipelineLogEntry[];
  warnings: MigrationWarning[];
  chatHistory: ChatMessage[];
  onSendChat: (message: string) => Promise<void>;
  chatBusy: boolean;
  introPending?: boolean;
  hasSession: boolean;
  pipelineStage?: string;
  hasSummary?: boolean;
}

export function RightPane({
  log,
  warnings,
  chatHistory,
  onSendChat,
  chatBusy,
  introPending = false,
  hasSession,
  pipelineStage,
  hasSummary,
}: Props) {
  const [input, setInput] = useState("");
  const [logOpen, setLogOpen] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatHistory.length, chatBusy, introPending]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const msg = input.trim();
    if (!msg || chatBusy || !hasSession) return;
    setInput("");
    await onSendChat(msg);
  };

  // Hide noisy AI focus entries from the process log
  const cleanLog = log.filter(
    (e) =>
      e.stage !== "ai_review" &&
      !String(e.message || "").toLowerCase().startsWith("ai focused")
  );
  const last = cleanLog[cleanLog.length - 1];
  const warnN = warnings.length;

  return (
    <div className="flex h-full min-h-0 flex-col bg-[var(--bg-panel)]">
      <div className="panel-header shrink-0">
        <div className="min-w-0 truncate">
          <span className="font-medium">AI</span>
          <span className="meta">
            {" "}
            · {(pipelineStage || "idle").toLowerCase()}
          </span>
        </div>
        {warnN > 0 && <span className="badge">{warnN}w</span>}
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        <div className="shrink-0 border-b border-[var(--border)] px-2 py-1">
          <button
            type="button"
            className="flex w-full items-center gap-1 text-left meta hover:text-[var(--fg)]"
            onClick={() => setLogOpen((v) => !v)}
          >
            <span className="uppercase tracking-wider">log</span>
            <span className="min-w-0 flex-1 truncate">
              {last ? last.message : "—"}
            </span>
            <span>{logOpen ? "−" : "+"}</span>
          </button>
          {logOpen && (
            <div className="mt-1 max-h-24 overflow-y-auto space-y-0.5 meta">
              {cleanLog.slice(-40).map((e, i) => (
                <div key={`${e.timestamp}-${i}`}>› {e.message}</div>
              ))}
              {warnings.slice(0, 8).map((w) => (
                <div key={w.id}>! {w.message}</div>
              ))}
            </div>
          )}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-2 py-2 space-y-1.5">
          {!hasSession && <p className="meta">Upload a config to start.</p>}
          {hasSession &&
            chatHistory.length === 0 &&
            !chatBusy &&
            !introPending && (
              <p className="meta leading-relaxed">
                {hasSummary
                  ? "Analysis ready — AI intro will appear shortly."
                  : "Upload or analyze a configuration to begin."}
              </p>
            )}
          {chatHistory.map((m) => (
            <div
              key={m.id}
              className={`px-2 py-1 text-[11px] leading-relaxed ${
                m.role === "user" ? "chat-user ml-4" : "chat-ai mr-1"
              }`}
            >
              {m.role === "assistant" && (
                <div className="mb-0.5 text-[9px] uppercase tracking-wider text-[var(--fg-faint)]">
                  AI
                </div>
              )}
              <div className="whitespace-pre-wrap">{m.content}</div>
            </div>
          ))}
          {(chatBusy || introPending) && (
            <div className="flex items-center gap-1 meta">
              <SpinnerIcon className="h-2.5 w-2.5" />
              {introPending && !chatBusy
                ? "Writing config introduction…"
                : "…"}
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        <form
          onSubmit={submit}
          className="shrink-0 border-t border-[var(--border)] p-1.5"
        >
          <div className="flex items-end gap-1">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void submit(e);
                }
              }}
              disabled={!hasSession || chatBusy}
              placeholder={hasSession ? "ask…" : "—"}
              rows={3}
              className="min-h-[4.5rem] min-w-0 flex-1 resize-none bg-transparent px-1.5 py-1.5 text-[11px] leading-relaxed text-[var(--fg)] placeholder:text-[var(--fg-faint)] focus:outline-none"
            />
            <button
              type="submit"
              disabled={!hasSession || chatBusy || !input.trim()}
              className="btn-primary mb-0.5 px-1.5 py-1.5"
              aria-label="Send"
            >
              <SendIcon className="h-3 w-3" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
