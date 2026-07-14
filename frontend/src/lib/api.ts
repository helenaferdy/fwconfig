import type {
  ChatResponse,
  HealthResponse,
  MigrationSession,
  VendorInfo,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "/api";

export type UploadPhase = "idle" | "uploading" | "processing" | "done" | "error";

export interface UploadProgress {
  phase: UploadPhase;
  /** 0–100 while uploading; null while processing (indeterminate) */
  percent: number | null;
  loaded?: number;
  total?: number;
  /** Server pipeline stage when processing */
  pipelineStage?: string;
  /** Last pipeline log message */
  statusMessage?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...init?.headers,
    },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export async function getVendors(): Promise<VendorInfo[]> {
  return request<VendorInfo[]>("/vendors");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const STAGE_LABELS: Record<string, string> = {
  pending: "Queued for analysis…",
  reading: "Reading configuration…",
  detecting_vendor: "Detecting vendor…",
  parsing: "Parsing configuration…",
  resolving_references: "Resolving object references…",
  building_model: "Building configuration model…",
  building_graph: "Building dependency graph…",
  generating: "Generating summary…",
  validating: "Validating…",
  done: "Analysis complete",
  failed: "Analysis failed",
};

export function stageLabel(stage?: string | null): string {
  if (!stage) return "Processing…";
  return STAGE_LABELS[stage.toLowerCase()] || `Processing (${stage})…`;
}

/** Upload with transfer progress; polls server while analysis runs in the background. */
export function uploadConfigWithProgress(
  fileOrFiles: File | File[],
  sourceVendor: string | undefined,
  onProgress: (p: UploadProgress) => void,
  autoParse = true
): Promise<MigrationSession> {
  const files = Array.isArray(fileOrFiles) ? fileOrFiles : [fileOrFiles];
  const form = new FormData();
  if (files.length === 1) {
    form.append("file", files[0]);
  } else {
    for (const f of files) {
      form.append("files", f);
    }
  }
  const params = new URLSearchParams();
  if (sourceVendor) params.set("source_vendor", sourceVendor);
  params.set("auto_parse", String(autoParse));
  const url = `${API_BASE}/sessions/upload?${params.toString()}`;

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.responseType = "json";

    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) {
        onProgress({
          phase: "uploading",
          percent: null,
          statusMessage: "Uploading files…",
        });
        return;
      }
      const percent = Math.min(99, Math.round((ev.loaded / ev.total) * 100));
      onProgress({
        phase: "uploading",
        percent,
        loaded: ev.loaded,
        total: ev.total,
        statusMessage: `Uploading… ${formatBytes(ev.loaded)} / ${formatBytes(ev.total)}`,
      });
    };

    xhr.upload.onload = () => {
      onProgress({
        phase: "processing",
        percent: null,
        statusMessage: "Upload finished — analyzing on server…",
      });
    };

    xhr.onerror = () => {
      onProgress({
        phase: "error",
        percent: null,
        statusMessage: "Network error during upload",
      });
      reject(new Error("Network error during upload"));
    };

    xhr.onload = async () => {
      if (xhr.status < 200 || xhr.status >= 300) {
        let detail = xhr.statusText || `HTTP ${xhr.status}`;
        try {
          const body =
            typeof xhr.response === "object" && xhr.response
              ? xhr.response
              : JSON.parse(String(xhr.responseText || "{}"));
          detail = body.detail || detail;
        } catch {
          /* ignore */
        }
        onProgress({ phase: "error", percent: null, statusMessage: String(detail) });
        reject(new Error(String(detail)));
        return;
      }

      let session: MigrationSession;
      try {
        session =
          typeof xhr.response === "object" && xhr.response
            ? (xhr.response as MigrationSession)
            : (JSON.parse(String(xhr.responseText)) as MigrationSession);
      } catch {
        reject(new Error("Invalid server response"));
        return;
      }

      const stage = (session.pipeline_stage || "").toLowerCase();
      if (stage === "done" || stage === "failed") {
        onProgress({
          phase: stage === "done" ? "done" : "error",
          percent: 100,
          pipelineStage: session.pipeline_stage,
          statusMessage:
            stage === "failed"
              ? session.error || "Analysis failed"
              : "Analysis complete",
        });
        if (stage === "failed") {
          reject(new Error(session.error || "Analysis failed"));
          return;
        }
        resolve(session);
        return;
      }

      // Poll until analysis finishes
      onProgress({
        phase: "processing",
        percent: null,
        pipelineStage: session.pipeline_stage,
        statusMessage: stageLabel(session.pipeline_stage),
      });

      const maxMs = 15 * 60 * 1000;
      const started = Date.now();
      const poll = async () => {
        try {
          const s = await getSession(session.id);
          const st = (s.pipeline_stage || "").toLowerCase();
          const lastLog = (s.pipeline_log || [])[s.pipeline_log.length - 1];
          onProgress({
            phase: "processing",
            percent: null,
            pipelineStage: s.pipeline_stage,
            statusMessage:
              lastLog?.message || stageLabel(s.pipeline_stage),
          });
          if (st === "done") {
            onProgress({
              phase: "done",
              percent: 100,
              pipelineStage: s.pipeline_stage,
              statusMessage: "Analysis complete",
            });
            resolve(s);
            return;
          }
          if (st === "failed") {
            onProgress({
              phase: "error",
              percent: null,
              pipelineStage: s.pipeline_stage,
              statusMessage: s.error || "Analysis failed",
            });
            reject(new Error(s.error || "Analysis failed"));
            return;
          }
          if (Date.now() - started > maxMs) {
            reject(new Error("Analysis timed out — try again or use smaller files"));
            return;
          }
          setTimeout(poll, 900);
        } catch (e) {
          if (Date.now() - started > maxMs) {
            reject(e instanceof Error ? e : new Error("Polling failed"));
            return;
          }
          setTimeout(poll, 1500);
        }
      };
      setTimeout(poll, 600);
    };

    onProgress({
      phase: "uploading",
      percent: 0,
      statusMessage: "Starting upload…",
    });
    xhr.send(form);
  });
}

export async function uploadConfig(
  fileOrFiles: File | File[],
  sourceVendor?: string,
  autoParse = true
): Promise<MigrationSession> {
  return uploadConfigWithProgress(fileOrFiles, sourceVendor, () => {}, autoParse);
}

export async function getSession(
  id: string,
  includeConfig = false
): Promise<MigrationSession> {
  return request<MigrationSession>(
    `/sessions/${id}?include_config=${includeConfig}`
  );
}

/** Refresh / build human-readable analysis summary */
export async function analyzeSession(
  id: string,
  sourceVendor?: string
): Promise<MigrationSession> {
  return request<MigrationSession>(`/sessions/${id}/analyze`, {
    method: "POST",
    body: JSON.stringify({
      source_vendor: sourceVendor || null,
    }),
  });
}

/** @deprecated use analyzeSession */
export async function convertSession(
  id: string,
  _targetVendor?: string,
  sourceVendor?: string
): Promise<MigrationSession> {
  return analyzeSession(id, sourceVendor);
}

export async function chat(
  id: string,
  message: string,
  includeRaw = false
): Promise<ChatResponse> {
  return request<ChatResponse>(`/sessions/${id}/chat`, {
    method: "POST",
    body: JSON.stringify({ message, include_raw: includeRaw }),
  });
}

export async function deleteSession(id: string): Promise<void> {
  await request(`/sessions/${id}`, { method: "DELETE" });
}
