"""API request/response schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class VendorInfo(BaseModel):
    id: str
    display_name: str
    role: str  # source | target | both


class HealthResponse(BaseModel):
    status: str
    version: str
    ai_enabled: bool


class ConvertRequest(BaseModel):
    """Deprecated — analysis no longer uses a target vendor."""
    target_vendor: str | None = None
    source_vendor: str | None = None


class AnalyzeRequest(BaseModel):
    source_vendor: str | None = None


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=20000)
    include_raw: bool = False


class AIActionSchema(BaseModel):
    type: str
    section: str | None = None
    content: str | None = None
    object_count: int | None = None
    note: str | None = None


class ChatResponse(BaseModel):
    reply: str
    message_id: str
    session_id: str
    actions: list[AIActionSchema] = Field(default_factory=list)
    # Updated generated sections after AI patches (for middle-pane IDE sync)
    generated_sections: list[dict[str, Any]] = Field(default_factory=list)
    generated_config: str | None = None
    pipeline_log: list[dict[str, Any]] = Field(default_factory=list)
    has_generated_config: bool = False


class SessionSummary(BaseModel):
    id: str
    filename: str | None
    source_vendor: str | None
    target_vendor: str | None
    pipeline_stage: str
    created_at: str
    updated_at: str


class ErrorResponse(BaseModel):
    detail: str
    code: str | None = None


class ParseRequest(BaseModel):
    source_vendor: str | None = None
