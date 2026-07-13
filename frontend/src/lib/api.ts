import type {
  ChatResponse,
  HealthResponse,
  MigrationSession,
  VendorInfo,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "/api";

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

export async function uploadConfig(
  file: File,
  sourceVendor?: string,
  autoParse = true
): Promise<MigrationSession> {
  const form = new FormData();
  form.append("file", file);
  const params = new URLSearchParams();
  if (sourceVendor) params.set("source_vendor", sourceVendor);
  params.set("auto_parse", String(autoParse));
  const qs = params.toString();
  return request<MigrationSession>(`/sessions/upload?${qs}`, {
    method: "POST",
    body: form,
    headers: {},
  });
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
