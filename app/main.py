"""
Bug Hunter AI — FastAPI Application Factory
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database.session import init_db
from app.utils.logging_config import configure_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup → yield → shutdown."""
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_file)

    logger.info("Bug Hunter AI starting up")
    logger.info(f"Dashboard: http://{settings.app_host}:{settings.app_port}")

    # Initialize database (creates tables if missing)
    init_db()
    logger.info(f"Database: {settings.db_path}")

    # Log startup event to activity log
    try:
        from app.activity.logger import ActivityLogger
        ActivityLogger.log_event("APPLICATION_STARTED", "Bug Hunter AI started successfully")
    except Exception as exc:
        logger.warning(f"Could not write startup activity log: {exc}")

    yield

    logger.info("Bug Hunter AI shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="Bug Hunter AI",
        description="Local-first AI cybersecurity assistant — Find. Explain. Fix. Verify.",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # CORS: localhost only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            f"http://{settings.app_host}:{settings.app_port}",
            "http://localhost:5173",   # Vite dev server
            "http://127.0.0.1:5173",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routers
    from app.api.routes import (
        activity,
        findings,
        health,
        remediation,
        reports,
        scans,
        settings as settings_router,
        targets,
        tools,
    )

    app.include_router(health.router, prefix="/api", tags=["Health"])
    app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
    app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
    app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
    app.include_router(remediation.router, prefix="/api/remediation", tags=["Remediation"])
    app.include_router(activity.router, prefix="/api/activity", tags=["Activity"])
    app.include_router(tools.router, prefix="/api/tools", tags=["Tools"])
    app.include_router(settings_router.router, prefix="/api/settings", tags=["Settings"])
    app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

    # Serve React frontend (production build) with SPA fallback
    import os
    from starlette.responses import FileResponse

    static_dirs = [
        os.path.join(os.path.dirname(__file__), "static"),
        os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"),
    ]
    static_dir = next((d for d in static_dirs if os.path.isdir(d)), None)

    if static_dir and os.path.exists(os.path.join(static_dir, "index.html")):
        assets_dir = os.path.join(static_dir, "assets")
        if os.path.isdir(assets_dir):
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str):
            # Don't intercept API or docs routes
            if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("redoc"):
                return None
            target = os.path.join(static_dir, full_path)
            if os.path.isfile(target):
                return FileResponse(target)
            return FileResponse(os.path.join(static_dir, "index.html"))

    return app


app = create_app()
