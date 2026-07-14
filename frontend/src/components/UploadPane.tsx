"use client";

import React, { useCallback, useRef, useState } from "react";
import type { VendorId } from "@/lib/types";
import type { UploadProgress } from "@/lib/api";
import { SpinnerIcon, UploadIcon } from "./icons";

export type UploadVendor = VendorId;

const VENDORS: {
  id: UploadVendor;
  label: string;
  short: string;
  multi: boolean;
  accept: string;
  files: string[];
  notes?: string;
}[] = [
  {
    id: "fortigate",
    label: "Fortigate",
    short: "FortiGate",
    multi: false,
    accept: ".conf,.cfg,.txt",
    files: [
      "Gateway CLI export: show full-configuration",
      "Save as a text/.conf file and upload that single file",
    ],
    notes: "One file per session.",
  },
  {
    id: "palo",
    label: "Palo Alto",
    short: "Palo",
    multi: false,
    accept: ".xml,.conf,.cfg,.txt",
    files: [
      "Device or Panorama config export (XML preferred)",
      "Or running-config / candidate-config text export",
    ],
    notes: "One file per session.",
  },
  {
    id: "checkpoint",
    label: "Check Point",
    short: "Check Point",
    multi: true,
    accept: ".tgz,.tar.gz,.tar,.txt,.conf,.cfg",
    files: [
      "Management: migrate_server export -v R82.10 (or your version) → .tgz",
      "Gateway GAiA: show configuration → text file",
    ],
    notes: "Upload both files together (multi-select).",
  },
  {
    id: "ftd",
    label: "Cisco FTD",
    short: "FTD",
    multi: false,
    accept: ".txt,.cfg,.conf,.xml",
    files: [
      "FMC/FTD configuration export or show running-config",
      "Text/.cfg export from FMC backup or CLI is preferred",
    ],
    notes: "One file per session.",
  },
];

interface Props {
  onUpload: (
    files: File[],
    sourceVendor: UploadVendor,
    onProgress: (p: UploadProgress) => void
  ) => Promise<void>;
  busy?: boolean;
}

export function UploadPane({ onUpload, busy }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [vendor, setVendor] = useState<UploadVendor | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<File[]>([]);
  const [progress, setProgress] = useState<UploadProgress | null>(null);

  const guide = vendor ? VENDORS.find((v) => v.id === vendor) : null;
  const showProgress = busy || (progress && progress.phase !== "idle");

  const handleFiles = useCallback(
    async (list: FileList | File[] | null | undefined) => {
      if (!vendor) {
        setError("Select a firewall platform first.");
        return;
      }
      if (!list || list.length === 0) return;
      const files = Array.from(list as FileList | File[]);
      const info = VENDORS.find((v) => v.id === vendor);
      if (info && !info.multi && files.length > 1) {
        setError(`${info.label} expects a single file. Select one file only.`);
        return;
      }
      if (info?.id === "checkpoint" && files.length < 2) {
        setError(
          "Check Point needs both the migrate_server .tgz and the gateway show configuration file."
        );
        return;
      }
      setError(null);
      setPicked(files);
      setProgress({
        phase: "uploading",
        percent: 0,
        statusMessage: "Starting upload…",
      });
      try {
        await onUpload(files, vendor, (p) => setProgress({ ...p }));
        setProgress({
          phase: "done",
          percent: 100,
          statusMessage: "Analysis complete",
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Upload failed";
        setError(msg);
        setProgress({ phase: "error", percent: null, statusMessage: msg });
      }
    },
    [onUpload, vendor]
  );

  const openPicker = () => {
    if (busy || !vendor) return;
    inputRef.current?.click();
  };

  const barPercent =
    progress?.phase === "uploading" && progress.percent != null
      ? progress.percent
      : progress?.phase === "processing"
        ? null
        : progress?.phase === "done"
          ? 100
          : 0;

  return (
    <div className="flex h-full flex-col items-center justify-center overflow-y-auto p-4 bg-[var(--bg-panel)]">
      <div className="w-full max-w-md space-y-3">
        <div className="text-center">
          <p className="text-[var(--fg)] font-medium">Upload configuration</p>
          <p className="meta mt-0.5">Select the source platform first</p>
        </div>

        <div
          className="grid grid-cols-2 gap-1.5"
          role="radiogroup"
          aria-label="Source firewall platform"
        >
          {VENDORS.map((v) => {
            const active = vendor === v.id;
            return (
              <button
                key={v.id}
                type="button"
                role="radio"
                aria-checked={active}
                disabled={busy}
                onClick={() => {
                  setVendor(v.id);
                  setError(null);
                  setPicked([]);
                  setProgress(null);
                }}
                className={`rounded border px-2 py-2 text-[11px] transition-colors ${
                  active
                    ? "border-[var(--fg)] bg-[var(--fg)] text-white"
                    : "border-[var(--border-strong)] bg-[var(--bg-panel)] text-[var(--fg-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--fg)]"
                }`}
              >
                {v.label}
              </button>
            );
          })}
        </div>

        {!vendor && (
          <p className="meta text-center leading-relaxed">
            Choose Fortigate, Palo Alto, Check Point, or Cisco FTD to see the
            required files and enable upload.
          </p>
        )}

        {guide && (
          <div className="rounded border border-[var(--border)] bg-[var(--bg-muted)] px-3 py-2.5 text-left">
            <p className="mb-1.5 text-[11px] font-medium text-[var(--fg)]">
              {guide.label} — required input
            </p>
            <ul className="space-y-1 meta leading-relaxed">
              {guide.files.map((line) => (
                <li key={line} className="flex gap-1.5">
                  <span className="shrink-0 text-[var(--fg-faint)]">•</span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
            {guide.notes && (
              <p className="mt-2 text-[10px] text-[var(--fg-muted)]">
                {guide.notes}
              </p>
            )}
          </div>
        )}

        {vendor && !showProgress && (
          <div
            role="button"
            tabIndex={busy ? -1 : 0}
            aria-label="Upload configuration file(s)"
            className={`cursor-pointer select-none rounded border border-[var(--border)] p-5 text-center transition-colors ${
              dragOver
                ? "bg-[var(--bg-hover)]"
                : "bg-[var(--bg-panel)] hover:bg-[var(--bg-muted)]"
            }`}
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
              void handleFiles(e.dataTransfer.files);
            }}
          >
            <div className="mx-auto mb-2 flex h-8 w-8 items-center justify-center text-[var(--fg)]">
              <UploadIcon className="h-4 w-4" />
            </div>
            <p className="mb-2 meta">
              {guide?.multi
                ? "Drop files here or choose files"
                : "Drop file here or choose file"}
            </p>
            <span className="btn-primary pointer-events-none inline-flex">
              {guide?.multi ? "Choose files" : "Choose file"}
            </span>
            <input
              ref={inputRef}
              type="file"
              className="hidden"
              multiple={!!guide?.multi}
              accept={guide?.accept || ".conf,.cfg,.txt"}
              onChange={(e) => {
                void handleFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </div>
        )}

        {showProgress && progress && (
          <div className="rounded border border-[var(--border)] bg-[var(--bg-panel)] px-3 py-3">
            <div className="mb-2 flex items-center gap-2">
              {progress.phase !== "done" && progress.phase !== "error" && (
                <SpinnerIcon className="h-3.5 w-3.5 shrink-0" />
              )}
              <div className="min-w-0 flex-1">
                <p className="text-[11px] font-medium text-[var(--fg)]">
                  {progress.phase === "uploading"
                    ? "Uploading files"
                    : progress.phase === "processing"
                      ? "Analyzing configuration"
                      : progress.phase === "done"
                        ? "Complete"
                        : "Error"}
                </p>
                <p className="meta truncate leading-relaxed">
                  {progress.statusMessage || "…"}
                </p>
              </div>
              {progress.phase === "uploading" && progress.percent != null && (
                <span className="shrink-0 tabular-nums text-[11px] text-[var(--fg-muted)]">
                  {progress.percent}%
                </span>
              )}
            </div>

            {/* Determinate during upload; striped indeterminate while processing */}
            <div
              className="h-2 w-full overflow-hidden rounded-sm bg-[var(--bg-muted)]"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={barPercent ?? undefined}
              aria-label={progress.statusMessage || "Progress"}
            >
              {barPercent != null ? (
                <div
                  className="h-full rounded-sm bg-[var(--fg)] transition-[width] duration-150 ease-out"
                  style={{ width: `${barPercent}%` }}
                />
              ) : (
                <div className="progress-indeterminate h-full w-1/3 rounded-sm bg-[var(--fg)]" />
              )}
            </div>

            {picked.length > 0 && (
              <ul className="mt-2 space-y-0.5 text-left meta">
                {picked.map((f) => (
                  <li key={f.name} className="truncate">
                    · {f.name}
                    {f.size >= 1024 * 1024
                      ? ` (${(f.size / (1024 * 1024)).toFixed(1)} MB)`
                      : f.size >= 1024
                        ? ` (${(f.size / 1024).toFixed(0)} KB)`
                        : ""}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {error && (
          <p className="text-center text-[11px] text-[var(--fg)]">{error}</p>
        )}
      </div>
    </div>
  );
}
