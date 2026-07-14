"""Configuration analysis pipeline orchestrator.

Stages:
  Reading → Detect vendor → Parse → Resolve refs → Build model
  → Build graph → Summarize → Validate → Done

All parsing and summary generation is deterministic. AI is never invoked here.
"""

from __future__ import annotations

import logging
import time
from typing import Awaitable, Callable

from model.enums import PipelineStage, Vendor, WarningSeverity
from parser.base import detect_vendor, ensure_parsers_loaded, get_parser
from pipeline.graph_builder import build_dependency_graph
from session.store import MigrationSession, SessionStore
from summary.enrich import enrich_parsed_sections
from summary.formatters import build_full_summary_document, build_summary_sections
from validator.base import run_validation

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[MigrationSession], Awaitable[None]]


class MigrationPipeline:
    def __init__(self, store: SessionStore) -> None:
        self.store = store
        ensure_parsers_loaded()

    async def _emit(self, session: MigrationSession, cb: ProgressCallback | None) -> None:
        await self.store.save(session)
        if cb:
            await cb(session)

    def _parse_checkpoint_multi(self, session: MigrationSession, parser: object):
        """Load GAiA text + migrate tgz from session artifacts and parse both."""
        gaia_text: str | None = None
        migrate_bytes: bytes | None = None

        for art in session.source_artifacts or []:
            path = self.store.artifact_path(session, art)
            if art.role == "gaia_config" and path and path.exists():
                gaia_text = path.read_text(encoding="utf-8", errors="replace")
            elif art.role == "mgmt_export" and path and path.exists():
                migrate_bytes = path.read_bytes()
            elif art.role in ("primary", "other") and path and path.exists():
                # Heuristic: text may still be GAiA
                if path.suffix.lower() in {".txt", ".conf", ".cfg", ""}:
                    try:
                        t = path.read_text(encoding="utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        t = ""
                    from parser.checkpoint.gaia import is_gaia_show_config

                    if is_gaia_show_config(t) and not gaia_text:
                        gaia_text = t
                elif path.suffix.lower() in {".tgz", ".gz", ".tar"} and not migrate_bytes:
                    migrate_bytes = path.read_bytes()

        if not gaia_text and session.original_config:
            from parser.checkpoint.gaia import is_gaia_show_config

            if is_gaia_show_config(session.original_config):
                gaia_text = session.original_config

        session.add_log(
            "parsing",
            "Check Point multi-source: "
            + (
                "GAiA" if gaia_text else "no GAiA"
            )
            + " + "
            + ("migrate_server tgz" if migrate_bytes else "no tgz"),
        )
        parse_sources = getattr(parser, "parse_sources", None)
        if callable(parse_sources):
            return parse_sources(gaia_text=gaia_text, migrate_tgz=migrate_bytes)
        return parser.parse(gaia_text or session.original_config or "")

    def _apply_summaries(self, session: MigrationSession) -> None:
        """Build human-readable summaries from the common model (no AI)."""
        if not session.common_model:
            return
        session.parsed_sections = enrich_parsed_sections(
            session.common_model, session.parsed_sections
        )
        summaries = build_summary_sections(session.common_model)
        session.generated_sections = summaries  # reused storage: human-readable summaries
        session.generated_config = build_full_summary_document(
            session.common_model, summaries
        )
        session.statistics.object_counts = session.common_model.section_counts()
        session.statistics.total_objects = session.common_model.total_objects()

    async def parse_session(
        self,
        session: MigrationSession,
        source_vendor: Vendor | None = None,
        on_progress: ProgressCallback | None = None,
        auto_summarize: bool = True,
    ) -> MigrationSession:
        raw = session.original_config or ""
        t0 = time.perf_counter()

        try:
            session.pipeline_stage = PipelineStage.READING
            session.add_log("reading", "Reading configuration")
            await self._emit(session, on_progress)

            session.pipeline_stage = PipelineStage.DETECTING_VENDOR
            if source_vendor and source_vendor != Vendor.UNKNOWN:
                vendor = source_vendor
                score = 1.0
                session.add_log(
                    "detecting_vendor",
                    f"Using specified vendor: {vendor.display_name}",
                )
            else:
                vendor, score = detect_vendor(raw)
                session.add_log(
                    "detecting_vendor",
                    f"Detected vendor: {vendor.display_name} (confidence {score:.0%})",
                    level="success" if vendor != Vendor.UNKNOWN else "warning",
                )
            session.source_vendor = vendor
            await self._emit(session, on_progress)

            if vendor == Vendor.UNKNOWN:
                session.pipeline_stage = PipelineStage.FAILED
                session.error = "Unable to detect firewall vendor"
                session.add_log("detecting_vendor", session.error, level="error")
                await self._emit(session, on_progress)
                return session

            session.pipeline_stage = PipelineStage.PARSING
            session.add_log("parsing", f"Parsing {vendor.display_name} configuration")
            await self._emit(session, on_progress)

            parser = get_parser(vendor)
            for sp in parser.section_parsers:
                session.add_log("parsing", f"Parsing {sp.section_type.display_name}")
            await self._emit(session, on_progress)

            # Check Point multi-source: GAiA CLI + migrate_server tgz
            if vendor == Vendor.CHECKPOINT and (
                session.source_artifacts
                and any(
                    a.role in ("gaia_config", "mgmt_export")
                    for a in session.source_artifacts
                )
            ):
                result = self._parse_checkpoint_multi(session, parser)
            else:
                result = parser.parse(raw)

            session.pipeline_stage = PipelineStage.RESOLVING_REFERENCES
            session.add_log("resolving_references", "Resolving object references")
            await self._emit(session, on_progress)

            session.pipeline_stage = PipelineStage.BUILDING_MODEL
            session.add_log("building_model", "Building structured configuration model")
            session.common_model = result.model
            session.parsed_sections = result.sections
            session.statistics.object_counts = result.model.section_counts()
            session.statistics.total_objects = result.model.total_objects()
            await self._emit(session, on_progress)

            for w in result.warnings:
                session.add_warning(
                    code=w.get("code", "PARSE_WARNING"),
                    message=w.get("message", ""),
                    severity=WarningSeverity(w.get("severity", "warning")),
                    section=w.get("section"),
                )

            session.pipeline_stage = PipelineStage.BUILDING_GRAPH
            session.add_log("building_graph", "Building dependency graph")
            session.dependency_graph = build_dependency_graph(result.model)
            await self._emit(session, on_progress)

            for warning in run_validation(result.model, session.dependency_graph):
                session.warnings.append(warning)

            if auto_summarize:
                session.pipeline_stage = PipelineStage.GENERATING
                session.add_log("summarizing", "Generating human-readable configuration summary")
                await self._emit(session, on_progress)
                self._apply_summaries(session)
                session.add_log(
                    "summarizing",
                    f"Summary ready – {session.statistics.total_objects} objects documented",
                    level="success",
                )
                session.statistics.generate_duration_ms = int(
                    (time.perf_counter() - t0) * 1000
                )

            session.statistics.warning_count = len(
                [x for x in session.warnings if x.severity in (WarningSeverity.WARNING, WarningSeverity.INFO)]
            )
            session.statistics.error_count = len(
                [x for x in session.warnings if x.severity in (WarningSeverity.ERROR, WarningSeverity.CRITICAL)]
            )
            session.statistics.unsupported_count = len(
                [x for x in session.warnings if x.code in ("UNSUPPORTED_FEATURE", "UNMAPPED_OBJECT", "PARTIAL_SSL_VPN")]
            )
            session.statistics.parse_duration_ms = int((time.perf_counter() - t0) * 1000)

            session.pipeline_stage = PipelineStage.DONE
            session.add_log(
                "done",
                f"Analysis complete – {session.statistics.total_objects} objects",
                level="success",
            )
            await self._emit(session, on_progress)
            return session

        except Exception as exc:  # noqa: BLE001
            logger.exception("Analysis pipeline failed for session %s", session.id)
            session.pipeline_stage = PipelineStage.FAILED
            session.error = str(exc)
            session.add_log("failed", f"Pipeline failed: {exc}", level="error")
            await self._emit(session, on_progress)
            return session

    async def analyze_session(
        self,
        session: MigrationSession,
        source_vendor: Vendor | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> MigrationSession:
        """Parse (if needed) and produce human-readable summaries."""
        if not session.common_model:
            return await self.parse_session(
                session, source_vendor=source_vendor, on_progress=on_progress, auto_summarize=True
            )

        t0 = time.perf_counter()
        try:
            session.pipeline_stage = PipelineStage.GENERATING
            session.add_log("summarizing", "Generating human-readable configuration summary")
            await self._emit(session, on_progress)

            self._apply_summaries(session)
            session.statistics.generate_duration_ms = int((time.perf_counter() - t0) * 1000)

            session.pipeline_stage = PipelineStage.VALIDATING
            session.add_log("validating", "Running validation")
            await self._emit(session, on_progress)

            t1 = time.perf_counter()
            new_warnings = run_validation(
                session.common_model,
                session.dependency_graph,
            )
            existing_keys = {(w.code, w.message, w.object_name) for w in session.warnings}
            for w in new_warnings:
                key = (w.code, w.message, w.object_name)
                if key not in existing_keys:
                    session.warnings.append(w)
            session.statistics.validation_duration_ms = int((time.perf_counter() - t1) * 1000)
            session.statistics.warning_count = len(
                [x for x in session.warnings if x.severity in (WarningSeverity.WARNING, WarningSeverity.INFO)]
            )
            session.statistics.error_count = len(
                [x for x in session.warnings if x.severity in (WarningSeverity.ERROR, WarningSeverity.CRITICAL)]
            )

            session.pipeline_stage = PipelineStage.DONE
            session.add_log("done", "Configuration analysis complete", level="success")
            await self._emit(session, on_progress)
            return session
        except Exception as exc:  # noqa: BLE001
            logger.exception("Analyze pipeline failed for session %s", session.id)
            session.pipeline_stage = PipelineStage.FAILED
            session.error = str(exc)
            session.add_log("failed", f"Analysis failed: {exc}", level="error")
            await self._emit(session, on_progress)
            return session

    # Backward-compatible alias (no longer takes target vendor)
    async def convert_session(
        self,
        session: MigrationSession,
        target_vendor: Vendor | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> MigrationSession:
        return await self.analyze_session(session, on_progress=on_progress)
