"""FastAPI route handlers – configuration analysis API."""

from __future__ import annotations

import logging
from typing import Any

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile

from ai.client import AIClient
from api.schemas import (
    ChatRequest,
    ChatResponse,
    HealthResponse,
    ParseRequest,
    VendorInfo,
)
from config import get_settings
from model.enums import Vendor
from parser.base import ensure_parsers_loaded, list_parsers
from pipeline.engine import MigrationPipeline
from session.store import ChatMessage, SessionStore
from utils.files import extract_text_from_upload

logger = logging.getLogger(__name__)

router = APIRouter()


def _store() -> SessionStore:
    return SessionStore(get_settings().resolved_sessions_dir)


def _pipeline() -> MigrationPipeline:
    return MigrationPipeline(_store())


def _parse_vendor(value: str | None) -> Vendor | None:
    if not value:
        return None
    try:
        return Vendor(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Unknown vendor: {value}") from exc


def _should_schedule_intro(session: Any) -> bool:
    """True when analysis is complete and no assistant intro exists yet."""
    from model.enums import PipelineStage

    if session.pipeline_stage != PipelineStage.DONE:
        return False
    if not session.common_model:
        return False
    if any(m.role == "assistant" for m in (session.chat_history or [])):
        return False
    return True


async def _run_ai_intro(session_id: str) -> None:
    """Background: generate AI intro after panes are already returned to the client."""
    store = _store()
    try:
        session = await store.get(session_id)
        if not session or not _should_schedule_intro(session):
            return

        client = AIClient()
        result = await client.generate_intro(session)
        reply = (result.reply or "").strip()
        if not reply:
            reply = client.build_intro_summary(session)
        # Intro is overview only — no highlight actions (leave panes on "all")
        applied: list[dict[str, Any]] = []

        # Re-load to avoid clobbering chat that arrived while intro ran
        session = await store.get(session_id)
        if not session or not _should_schedule_intro(session):
            return

        session.chat_history.append(
            ChatMessage(
                role="assistant",
                content=reply,
                metadata={"actions": applied, "kind": "intro"},
            )
        )
        await store.save(session)
        logger.info("AI intro saved for session %s (%d chars)", session_id, len(reply))
    except Exception:  # noqa: BLE001
        logger.exception("AI intro failed for session %s", session_id)
        # Last-resort deterministic intro so UI is not stuck empty
        try:
            session = await store.get(session_id)
            if session and _should_schedule_intro(session):
                client = AIClient()
                session.chat_history.append(
                    ChatMessage(
                        role="assistant",
                        content=client.build_intro_summary(session),
                        metadata={"actions": [], "kind": "intro_fallback"},
                    )
                )
                await store.save(session)
        except Exception:  # noqa: BLE001
            logger.exception("AI intro fallback also failed for %s", session_id)


def _schedule_intro(background_tasks: BackgroundTasks, session: Any) -> None:
    if _should_schedule_intro(session):
        background_tasks.add_task(_run_ai_intro, session.id)


async def _run_parse_and_intro(session_id: str, vendor_value: str | None) -> None:
    """Background analysis after files are stored so the client can poll progress."""
    from model.enums import PipelineStage

    store = _store()
    try:
        session = await store.get(session_id)
        if not session:
            return
        vendor = None
        if vendor_value:
            try:
                vendor = Vendor(vendor_value)
            except ValueError:
                vendor = None
        session.add_log("upload", "Upload complete — starting analysis")
        await store.save(session)
        pipeline = _pipeline()
        session = await pipeline.parse_session(
            session, source_vendor=vendor, auto_summarize=True
        )
        # Intro runs here (already in background worker)
        await _run_ai_intro(session.id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Background parse failed for session %s", session_id)
        try:
            session = await store.get(session_id)
            if session and session.pipeline_stage != PipelineStage.DONE:
                session.pipeline_stage = PipelineStage.FAILED
                session.error = f"Analysis failed: {exc}"
                session.add_log("parsing", session.error, level="error")
                await store.save(session)
        except Exception:  # noqa: BLE001
            logger.exception("Failed to mark session %s as failed", session_id)


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        ai_enabled=bool(settings.ai_enabled and settings.opencode_api_key),
    )


@router.get("/vendors", response_model=list[VendorInfo])
async def vendors() -> list[VendorInfo]:
    """Supported input vendors for configuration analysis."""
    ensure_parsers_loaded()
    sources = list_parsers()
    result = []
    for v in sources:
        if v == Vendor.UNKNOWN:
            continue
        result.append(VendorInfo(id=v.value, display_name=v.display_name, role="source"))
    order = [Vendor.FORTIGATE, Vendor.PALO_ALTO, Vendor.CHECKPOINT, Vendor.CISCO_FTD]
    result.sort(key=lambda x: order.index(Vendor(x.id)) if Vendor(x.id) in order else 99)
    return result


@router.get("/taxonomy")
async def taxonomy() -> dict[str, Any]:
    """Hierarchical categorization tree used by the explorer."""
    from model.taxonomy import taxonomy_tree_for_api

    return {"tree": taxonomy_tree_for_api()}


@router.post("/sessions/upload")
async def upload_config(
    background_tasks: BackgroundTasks,
    file: UploadFile | None = File(None),
    files: list[UploadFile] | None = File(None),
    source_vendor: str | None = None,
    auto_parse: bool = True,
) -> dict[str, Any]:
    """Upload one or more configuration files.

    Single-file vendors (Fortigate, …): one `file` field.
    Check Point: upload both migrate_server `.tgz` and GAiA `show configuration`
    as repeated `files` (or `file` + `files`).
    """
    settings = get_settings()
    uploads: list[UploadFile] = []
    if files:
        uploads.extend([f for f in files if f is not None])
    if file is not None:
        uploads.append(file)
    if not uploads:
        raise HTTPException(status_code=400, detail="No file uploaded")

    payloads: list[tuple[str, bytes, str | None]] = []
    for uf in uploads:
        filename = uf.filename or "config.conf"
        data = await uf.read()
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File {filename} exceeds maximum upload size",
            )
        if not data:
            raise HTTPException(status_code=400, detail=f"Empty file: {filename}")
        payloads.append((filename, data, uf.content_type))

    store = _store()
    multi = len(payloads) > 1

    # Detect Check Point multi-source even for a single tgz / gaia file
    from parser.checkpoint.gaia import is_gaia_show_config
    from parser.checkpoint.migrate_export import is_migrate_server_tgz
    from utils.files import decode_bytes

    looks_cp = False
    for name, data, _ct in payloads:
        low = name.lower()
        if is_migrate_server_tgz(data) or low.endswith((".tgz", ".tar.gz")):
            looks_cp = True
            break
        if low.endswith((".txt", ".conf", ".cfg")) or not Path(name).suffix:
            try:
                if is_gaia_show_config(decode_bytes(data)):
                    looks_cp = True
                    break
            except Exception:  # noqa: BLE001
                pass

    vendor_hint = _parse_vendor(source_vendor)
    if looks_cp and (multi or vendor_hint in (None, Vendor.CHECKPOINT)):
        # Always use multi-create so tgz is stored as binary artifact
        session = await store.create_multi(payloads)
        if vendor_hint is None:
            vendor_hint = Vendor.CHECKPOINT
    elif multi:
        session = await store.create_multi(payloads)
    else:
        filename, data, content_type = payloads[0]
        try:
            text = extract_text_from_upload(filename, data)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=400, detail=f"Failed to read upload: {exc}"
            ) from exc
        session = await store.create(
            filename=filename,
            content=text,
            content_type=content_type,
        )

    if auto_parse:
        from model.enums import PipelineStage

        total_bytes = sum(len(d) for _, d, _ in payloads)
        # Large / multi-file (e.g. Check Point tgz): parse in background so UI can poll stages
        async_parse = (
            multi
            or looks_cp
            or (vendor_hint == Vendor.CHECKPOINT)
            or total_bytes >= 2 * 1024 * 1024
        )
        if async_parse:
            session.pipeline_stage = PipelineStage.PENDING
            session.add_log(
                "upload",
                f"Received {len(payloads)} file(s) ({total_bytes // 1024} KB) — analysis queued",
                level="info",
            )
            await store.save(session)
            background_tasks.add_task(
                _run_parse_and_intro,
                session.id,
                vendor_hint.value if vendor_hint else None,
            )
        else:
            pipeline = _pipeline()
            session = await pipeline.parse_session(
                session, source_vendor=vendor_hint, auto_summarize=True
            )
            _schedule_intro(background_tasks, session)

    return session.public_view()


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, include_config: bool = False) -> dict[str, Any]:
    session = await _store().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.public_view(include_config=include_config)


@router.get("/sessions/{session_id}/log")
async def get_pipeline_log(session_id: str) -> dict[str, Any]:
    session = await _store().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.id,
        "pipeline_stage": session.pipeline_stage.value,
        "log": [e.model_dump(mode="json") for e in session.pipeline_log],
    }


@router.get("/sessions/{session_id}/warnings")
async def get_warnings(session_id: str) -> dict[str, Any]:
    session = await _store().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.id,
        "warnings": [w.model_dump(mode="json") for w in session.warnings],
    }


@router.post("/sessions/{session_id}/parse")
async def parse_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    body: ParseRequest | None = None,
) -> dict[str, Any]:
    store = _store()
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    vendor = _parse_vendor(body.source_vendor if body else None)
    session = await _pipeline().parse_session(session, source_vendor=vendor, auto_summarize=True)
    _schedule_intro(background_tasks, session)
    return session.public_view()


@router.post("/sessions/{session_id}/analyze")
async def analyze_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    body: ParseRequest | None = None,
) -> dict[str, Any]:
    """Build / refresh human-readable configuration summary."""
    store = _store()
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    vendor = _parse_vendor(body.source_vendor if body else None)
    session = await _pipeline().analyze_session(session, source_vendor=vendor)
    # Intro runs async; left/mid panes return immediately
    _schedule_intro(background_tasks, session)
    return session.public_view()


@router.post("/sessions/{session_id}/convert")
async def convert_session_compat(session_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Deprecated alias → analyze (keeps older clients working)."""
    store = _store()
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session = await _pipeline().analyze_session(session)
    return session.public_view()


@router.get("/sessions/{session_id}/sections/source")
async def source_sections(session_id: str) -> dict[str, Any]:
    session = await _store().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.id,
        "sections": [s.model_dump() for s in session.parsed_sections],
    }


@router.get("/sessions/{session_id}/sections/summary")
async def summary_sections(session_id: str) -> dict[str, Any]:
    session = await _store().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.id,
        "sections": [s.model_dump() for s in session.generated_sections],
        "summary_document": session.generated_config,
    }


@router.get("/sessions/{session_id}/sections/target")
async def target_sections_compat(session_id: str) -> dict[str, Any]:
    """Deprecated alias for summary sections."""
    return await summary_sections(session_id)


@router.get("/sessions/{session_id}/model")
async def get_common_model(session_id: str) -> dict[str, Any]:
    session = await _store().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.common_model:
        raise HTTPException(status_code=404, detail="Common model not available – parse first")
    return {
        "session_id": session.id,
        "model": session.common_model.model_dump(),
        "graph": session.dependency_graph.model_dump() if session.dependency_graph else None,
    }


@router.post("/sessions/{session_id}/chat", response_model=ChatResponse)
async def chat(session_id: str, body: ChatRequest) -> ChatResponse:
    store = _store()
    session = await store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    user_msg = ChatMessage(role="user", content=body.message)
    session.chat_history.append(user_msg)

    client = AIClient()
    result = await client.chat(session, body.message, include_raw=body.include_raw)
    applied = client.apply_actions(session, result.actions)

    assistant_msg = ChatMessage(
        role="assistant",
        content=result.reply,
        metadata={"actions": applied},
    )
    session.chat_history.append(assistant_msg)
    await store.save(session)

    from api.schemas import AIActionSchema

    return ChatResponse(
        reply=result.reply,
        message_id=assistant_msg.id,
        session_id=session.id,
        actions=[AIActionSchema(**a) for a in applied],
        generated_sections=[s.model_dump() for s in session.generated_sections],
        generated_config=session.generated_config,
        pipeline_log=[e.model_dump(mode="json") for e in session.pipeline_log],
        has_generated_config=bool(session.generated_config),
    )


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str) -> dict[str, str]:
    ok = await _store().delete(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "deleted", "id": session_id}


@router.get("/sessions")
async def list_sessions() -> dict[str, Any]:
    store = _store()
    ids = await store.list_ids()
    summaries = []
    for sid in ids[:100]:
        s = await store.get(sid)
        if s:
            summaries.append(
                {
                    "id": s.id,
                    "filename": s.filename,
                    "source_vendor": s.source_vendor.value,
                    "pipeline_stage": s.pipeline_stage.value,
                    "created_at": s.created_at.isoformat(),
                    "updated_at": s.updated_at.isoformat(),
                    "has_summary": bool(s.generated_config),
                }
            )
    return {"sessions": summaries}
