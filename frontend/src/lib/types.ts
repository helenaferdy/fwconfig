export type VendorId = "fortigate" | "palo" | "checkpoint" | "ftd" | "unknown";

export interface VendorInfo {
  id: VendorId;
  display_name: string;
  role: string;
}

export interface PipelineLogEntry {
  timestamp: string;
  stage: string;
  message: string;
  level: string;
  detail?: string | null;
}

export interface MigrationWarning {
  id: string;
  severity: "info" | "warning" | "error" | "critical";
  code: string;
  message: string;
  section?: string | null;
  object_name?: string | null;
  details?: Record<string, unknown>;
}

export interface ParsedObject {
  id?: string;
  name: string;
  preview?: string | null;
  raw?: string | null;
  properties?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ParsedSection {
  section_type: string;
  display_name: string;
  category?: string | null;
  category_display?: string | null;
  object_count: number;
  parsed_ok: boolean;
  objects: ParsedObject[];
  raw_snippets?: string[];
  errors?: string[];
}

export interface SummarySection {
  section_type: string;
  display_name: string;
  category?: string | null;
  category_display?: string | null;
  content: string;
  object_count: number;
  success: boolean;
  errors?: string[];
}

export type GeneratedSection = SummarySection;

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  metadata?: Record<string, unknown> | null;
}

export interface SessionStatistics {
  source_bytes: number;
  source_lines: number;
  object_counts: Record<string, number>;
  total_objects: number;
  warning_count: number;
  error_count: number;
  unsupported_count: number;
  parse_duration_ms?: number | null;
  generate_duration_ms?: number | null;
  validation_duration_ms?: number | null;
}

export interface SourceArtifact {
  name: string;
  role: string;
  content_type?: string | null;
  size_bytes?: number;
  stored_as?: string | null;
}

export interface MigrationSession {
  id: string;
  created_at: string;
  updated_at: string;
  filename?: string | null;
  content_type?: string | null;
  source_vendor: VendorId;
  source_vendor_display?: string;
  pipeline_stage: string;
  pipeline_log: PipelineLogEntry[];
  parsed_sections: ParsedSection[];
  summary_sections?: SummarySection[];
  generated_sections?: SummarySection[];
  warnings: MigrationWarning[];
  statistics: SessionStatistics;
  chat_history: ChatMessage[];
  error?: string | null;
  has_common_model: boolean;
  has_summary?: boolean;
  has_generated_config?: boolean;
  section_counts?: Record<string, number>;
  summary_document?: string | null;
  generated_config?: string | null;
  original_config?: string | null;
  source_artifacts?: SourceArtifact[];
}

export interface HealthResponse {
  status: string;
  version: string;
  ai_enabled: boolean;
}

export type AIActionType = "highlight" | "annotate" | "clear_highlights" | string;

export interface AIAction {
  type: AIActionType;
  section?: string | null;
  content?: string | null;
  object_count?: number | null;
  note?: string | null;
}

export interface ChatResponse {
  reply: string;
  message_id: string;
  session_id: string;
  actions: AIAction[];
  generated_sections: SummarySection[];
  generated_config?: string | null;
  pipeline_log?: PipelineLogEntry[];
  has_generated_config?: boolean;
}

export interface TaxonomyNode {
  id: string;
  name: string;
  children: { id: string; name: string }[];
}
