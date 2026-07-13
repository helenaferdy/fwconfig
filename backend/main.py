"""FW Config Analyzer – FastAPI entrypoint."""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Ensure backend package root is on sys.path when run as script / uvicorn module
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.routes import router  # noqa: E402
from config import get_settings  # noqa: E402
from generator.base import ensure_generators_loaded  # noqa: E402
from parser.base import ensure_parsers_loaded  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("fwmigrate")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.resolved_sessions_dir.mkdir(parents=True, exist_ok=True)
    ensure_parsers_loaded()
    ensure_generators_loaded()
    logger.info(
        "Starting %s v%s on port %s",
        settings.app_name,
        settings.app_version,
        settings.port,
    )
    logger.info("Sessions dir: %s", settings.resolved_sessions_dir)
    logger.info("AI enabled: %s", bool(settings.ai_enabled and settings.opencode_api_key))
    yield
    logger.info("Shutting down")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list + ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router, prefix="/api")

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    # Serve built Next.js static export if present
    static_dir = settings.project_root / "frontend" / "out"
    if static_dir.is_dir():
        assets = static_dir / "_next"
        if assets.is_dir():
            app.mount("/_next", StaticFiles(directory=str(assets)), name="next-static")

        @app.get("/")
        async def index():
            return FileResponse(static_dir / "index.html")

        @app.get("/{full_path:path}")
        async def spa_fallback(full_path: str):
            # Do not shadow API
            if full_path.startswith("api"):
                return JSONResponse(status_code=404, content={"detail": "Not found"})
            candidate = static_dir / full_path
            if candidate.is_file():
                return FileResponse(candidate)
            # Next.js export may use trailing dirs
            html_candidate = static_dir / full_path / "index.html"
            if html_candidate.is_file():
                return FileResponse(html_candidate)
            return FileResponse(static_dir / "index.html")
    else:

        @app.get("/")
        async def root():
            return {
                "name": settings.app_name,
                "version": settings.app_version,
                "docs": "/api/docs",
                "message": "Frontend not built yet. API is available under /api",
            }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    s = get_settings()
    uvicorn.run(
        "main:app",
        host=s.host,
        port=s.port,
        reload=s.debug,
        factory=False,
    )
