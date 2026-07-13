"""Disk-backed session storage.

Sessions are independent, fully self-contained migration workspaces.
Storage is intentionally simple (JSON files on disk) so it can be swapped
for PostgreSQL later without changing API contracts.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiofiles
from pydantic import BaseModel, Field

from model.enums import PipelineStage, Vendor, WarningSeverity
from model.graph import DependencyGraph
from model.objects import CommonModel, GeneratedSection, ParsedSection

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PipelineLogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=_utcnow)
    stage: str
    message: str
    level: str = "info"  # info | warning | error | success
    detail: str | None = None


class MigrationWarning(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    severity: WarningSeverity = WarningSeverity.WARNING
    code: str
    message: str
    section: str | None = None
    object_name: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ChatMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    role: str  # user | assistant | system
    content: str
    timestamp: datetime = Field(default_factory=_utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionStatistics(BaseModel):
    source_bytes: int = 0
    source_lines: int = 0
    object_counts: dict[str, int] = Field(default_factory=dict)
    total_objects: int = 0
    warning_count: int = 0
    error_count: int = 0
    unsupported_count: int = 0
    parse_duration_ms: int | None = None
    generate_duration_ms: int | None = None
    validation_duration_ms: int | None = None


class MigrationSession(BaseModel):
    """Complete state for one independent migration session."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    filename: str | None = None
    content_type: str | None = None
    original_config: str | None = None

    source_vendor: Vendor = Vendor.UNKNOWN
    target_vendor: Vendor | None = None

    pipeline_stage: PipelineStage = PipelineStage.PENDING
    pipeline_log: list[PipelineLogEntry] = Field(default_factory=list)

    parsed_sections: list[ParsedSection] = Field(default_factory=list)
    common_model: CommonModel | None = None
    dependency_graph: DependencyGraph | None = None

    generated_sections: list[GeneratedSection] = Field(default_factory=list)
    generated_config: str | None = None

    warnings: list[MigrationWarning] = Field(default_factory=list)
    statistics: SessionStatistics = Field(default_factory=SessionStatistics)
    chat_history: list[ChatMessage] = Field(default_factory=list)

    error: str | None = None

    def touch(self) -> None:
        self.updated_at = _utcnow()

    def add_log(
        self,
        stage: str,
        message: str,
        level: str = "info",
        detail: str | None = None,
    ) -> PipelineLogEntry:
        entry = PipelineLogEntry(stage=stage, message=message, level=level, detail=detail)
        self.pipeline_log.append(entry)
        self.touch()
        return entry

    def add_warning(
        self,
        code: str,
        message: str,
        severity: WarningSeverity = WarningSeverity.WARNING,
        section: str | None = None,
        object_name: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> MigrationWarning:
        w = MigrationWarning(
            severity=severity,
            code=code,
            message=message,
            section=section,
            object_name=object_name,
            details=details or {},
        )
        self.warnings.append(w)
        self.statistics.warning_count = len(
            [x for x in self.warnings if x.severity in (WarningSeverity.WARNING, WarningSeverity.INFO)]
        )
        self.statistics.error_count = len(
            [x for x in self.warnings if x.severity in (WarningSeverity.ERROR, WarningSeverity.CRITICAL)]
        )
        self.touch()
        return w

    def summary_for_ai(self) -> dict[str, Any]:
        """Structured context for the AI consultant – parsed model + summaries."""
        model_summary: dict[str, Any] = {}
        if self.common_model:
            model_summary = {
                "source_vendor": self.common_model.source_vendor,
                "hostname": self.common_model.hostname,
                "section_counts": self.common_model.section_counts(),
                "total_objects": self.common_model.total_objects(),
                "sample_policies": [
                    p.model_dump() for p in self.common_model.policies[:20]
                ],
                "sample_addresses": [
                    a.model_dump() for a in self.common_model.addresses[:30]
                ],
                "sample_services": [
                    s.model_dump() for s in self.common_model.services[:20]
                ],
                "sample_interfaces": [
                    i.model_dump() for i in self.common_model.interfaces[:20]
                ],
                "unmapped_count": len(self.common_model.unmapped),
            }

        graph_summary = None
        if self.dependency_graph:
            graph_summary = self.dependency_graph.summary_for_ai()

        summary_sections = [
            {
                "section_type": s.section_type,
                "display_name": s.display_name,
                "object_count": s.object_count,
                "success": s.success,
                "errors": s.errors,
            }
            for s in self.generated_sections
        ]

        return {
            "session_id": self.id,
            "filename": self.filename,
            "source_vendor": self.source_vendor.value,
            "pipeline_stage": self.pipeline_stage.value,
            "statistics": self.statistics.model_dump(),
            "warnings": [w.model_dump() for w in self.warnings[:100]],
            "parsed_sections": [
                {
                    "section_type": s.section_type,
                    "display_name": s.display_name,
                    "object_count": s.object_count,
                    "parsed_ok": s.parsed_ok,
                    "errors": s.errors,
                }
                for s in self.parsed_sections
            ],
            "summary_sections": summary_sections,
            # aliases for older AI context keys
            "generated_sections": summary_sections,
            "common_model": model_summary,
            "dependency_graph": graph_summary,
            "pipeline_log_tail": [e.model_dump(mode="json") for e in self.pipeline_log[-30:]],
        }

    def public_view(self, include_config: bool = False) -> dict[str, Any]:
        """API-safe representation for the frontend (analysis terminology)."""
        summary_sections = [s.model_dump() for s in self.generated_sections]
        data: dict[str, Any] = {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "filename": self.filename,
            "content_type": self.content_type,
            "source_vendor": self.source_vendor.value,
            "source_vendor_display": self.source_vendor.display_name,
            "pipeline_stage": self.pipeline_stage.value,
            "pipeline_log": [e.model_dump(mode="json") for e in self.pipeline_log],
            "parsed_sections": [s.model_dump() for s in self.parsed_sections],
            # Human-readable summaries (middle pane)
            "summary_sections": summary_sections,
            "generated_sections": summary_sections,  # backward-compatible alias
            "summary_document": self.generated_config,
            "warnings": [w.model_dump(mode="json") for w in self.warnings],
            "statistics": self.statistics.model_dump(),
            "chat_history": [m.model_dump(mode="json") for m in self.chat_history],
            "error": self.error,
            "has_common_model": self.common_model is not None,
            "has_summary": bool(self.generated_config),
            "has_generated_config": bool(self.generated_config),  # alias
            "section_counts": (
                self.common_model.section_counts() if self.common_model else {}
            ),
            # Raw source for left-pane viewer (needed by UI)
            "original_config": self.original_config,
        }
        if include_config:
            data["generated_config"] = self.generated_config
            data["summary_document"] = self.generated_config
            if self.common_model:
                data["common_model"] = self.common_model.model_dump()
            if self.dependency_graph:
                data["dependency_graph"] = self.dependency_graph.model_dump()
        return data



class SessionStore:
    """Async disk-backed session repository."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    def _session_dir(self, session_id: str) -> Path:
        return self.root / session_id

    def _session_file(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "session.json"

    async def _get_lock(self, session_id: str) -> asyncio.Lock:
        async with self._global_lock:
            if session_id not in self._locks:
                self._locks[session_id] = asyncio.Lock()
            return self._locks[session_id]

    async def create(
        self,
        filename: str,
        content: str,
        content_type: str | None = None,
    ) -> MigrationSession:
        session = MigrationSession(
            filename=filename,
            content_type=content_type,
            original_config=content,
            statistics=SessionStatistics(
                source_bytes=len(content.encode("utf-8", errors="replace")),
                source_lines=content.count("\n") + (1 if content else 0),
            ),
        )
        session.add_log("pending", "Session created")
        await self.save(session)
        # Also write original config as a separate file for large configs
        session_dir = self._session_dir(session.id)
        async with aiofiles.open(session_dir / "original.conf", "w", encoding="utf-8") as f:
            await f.write(content)
        logger.info("Created session %s for file %s", session.id, filename)
        return session

    async def get(self, session_id: str) -> MigrationSession | None:
        path = self._session_file(session_id)
        if not path.exists():
            return None
        async with aiofiles.open(path, "r", encoding="utf-8") as f:
            raw = await f.read()
        data = json.loads(raw)
        return MigrationSession.model_validate(data)

    async def save(self, session: MigrationSession) -> None:
        session.touch()
        session_dir = self._session_dir(session.id)
        session_dir.mkdir(parents=True, exist_ok=True)
        path = self._session_file(session.id)
        lock = await self._get_lock(session.id)
        async with lock:
            payload = session.model_dump(mode="json")
            tmp = path.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(payload, indent=2, default=str))
            tmp.replace(path)

            if session.generated_config:
                async with aiofiles.open(
                    session_dir / "generated.conf", "w", encoding="utf-8"
                ) as f:
                    await f.write(session.generated_config)

    async def delete(self, session_id: str) -> bool:
        session_dir = self._session_dir(session_id)
        if not session_dir.exists():
            return False
        import shutil

        shutil.rmtree(session_dir)
        async with self._global_lock:
            self._locks.pop(session_id, None)
        return True

    async def list_ids(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(
            p.name for p in self.root.iterdir() if p.is_dir() and (p / "session.json").exists()
        )
