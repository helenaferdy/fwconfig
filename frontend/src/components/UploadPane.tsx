"use client";

import React, { useCallback, useRef, useState } from "react";
import { SpinnerIcon, UploadIcon } from "./icons";

const SUPPORTED = [".conf", ".cfg", ".txt", ".xml", ".json", ".zip", ".tgz"];

interface Props {
  onUpload: (file: File) => Promise<void>;
  busy?: boolean;
}

export function UploadPane({ onUpload, busy }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFile = useCallback(
    async (file: File | null | undefined) => {
      if (!file) return;
      setError(null);
      try {
        await onUpload(file);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Upload failed");
      }
    },
    [onUpload]
  );

  const openPicker = () => {
    if (busy) return;
    inputRef.current?.click();
  };

  return (
    <div className="flex h-full flex-col items-center justify-center p-6 bg-[var(--bg-panel)]">
      <div
        role="button"
        tabIndex={busy ? -1 : 0}
        aria-label="Upload configuration file"
        aria-disabled={busy || undefined}
        className={`w-full max-w-xs cursor-pointer select-none p-6 text-center border border-[var(--border)] transition-colors ${
          dragOver ? "bg-[var(--bg-hover)]" : "bg-[var(--bg-panel)] hover:bg-[var(--bg-muted)]"
        } ${busy ? "cursor-wait opacity-80" : ""}`}
        onClick={openPicker}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            openPicker();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          void handleFile(e.dataTransfer.files?.[0]);
        }}
      >
        <div className="mx-auto mb-3 flex h-8 w-8 items-center justify-center text-[var(--fg)]">
          {busy ? (
            <SpinnerIcon className="h-4 w-4" />
          ) : (
            <UploadIcon className="h-4 w-4" />
          )}
        </div>
        <p className="mb-1 text-[var(--fg)] font-medium">Upload configuration</p>
        <p className="mb-4 meta">Fortigate · Palo · Check Point · FTD</p>
        <span className="btn-primary pointer-events-none inline-flex">
          {busy ? "Processing…" : "Choose file"}
        </span>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept={SUPPORTED.join(",")}
          onChange={(e) => {
            void handleFile(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
        {error && (
          <p
            className="mt-3 text-[11px] text-[var(--fg)]"
            onClick={(e) => e.stopPropagation()}
          >
            {error}
          </p>
        )}
        <p className="mt-4 meta">{SUPPORTED.join(" ")}</p>
      </div>
    </div>
  );
}
