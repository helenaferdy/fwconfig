"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import type { ChatMessage } from "@/lib/types";
import { SendIcon, SpinnerIcon } from "./icons";

/** Light markdown for chat: **bold**, `code`, preserve newlines. */
function ChatText({ text }: { text: string }) {
  const nodes = useMemo(() => {
    const src = text || "";
    // Split on **bold** or `code`, keep delimiters
    const parts = src.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    return parts.map((part, i) => {
      if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
        return (
          <strong key={i} className="font-semibold">
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
        return (
          <code
            key={i}
            className="rounded-none px-0.5 font-mono"
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      return <React.Fragment key={i}>{part}</React.Fragment>;
    });
  }, [text]);

  return <div className="whitespace-pre-wrap">{nodes}</div>;
}

interface Props {
  chatHistory: ChatMessage[];
  onSendChat: (message: string) => Promise<void>;
  chatBusy: boolean;
  introPending?: boolean;
  hasSession: boolean;
  hasSummary?: boolean;
}

export function RightPane({
  chatHistory,
  onSendChat,
  chatBusy,
  introPending = false,
  hasSession,
  hasSummary,
}: Props) {
  const [input, setInput] = useState("");
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

  return (
    <div className="ai-chat-pane flex h-full min-h-0 flex-col">
      <div className="flex min-h-0 flex-1 flex-col">
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
              className={`px-2 py-1.5 leading-snug ${
                m.role === "user" ? "chat-user" : "chat-ai"
              }`}
            >
              {m.role === "assistant" && (
                <div className="chat-label mb-0.5 uppercase tracking-wider">
                  AI
                </div>
              )}
              <ChatText text={m.content} />
            </div>
          ))}
          {(chatBusy || introPending) && (
            <div className="flex items-center gap-1 meta">
              <SpinnerIcon className="h-2.5 w-2.5" />
              {introPending && !chatBusy
                ? "Writing introduction…"
                : "…"}
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        <form
          onSubmit={submit}
          className="chat-composer-wrap shrink-0 p-2"
        >
          <div className="chat-composer flex items-stretch gap-1.5">
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
              placeholder={
                hasSession
                  ? "Ask about policies, objects, IPs, interfaces…"
                  : "Upload a config to chat"
              }
              rows={3}
              className="chat-input min-w-0 flex-1 resize-none px-2.5 py-2 leading-snug focus:outline-none disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!hasSession || chatBusy || !input.trim()}
              className="chat-send shrink-0"
              aria-label="Send message"
              title="Send"
            >
              <SendIcon className="h-4 w-4" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
