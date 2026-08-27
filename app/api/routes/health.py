"""
Bug Hunter AI — Health & Status Routes
"""
from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_settings_dep
from app.config import Settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    python_version: str
    platform: str


class StatusResponse(BaseModel):
    status: str
    database: str
    ollama: str
    ollama_model: str
    tools: Dict[str, Any]
    findings_count: int
    scans_count: int
    open_findings: int


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Basic health check endpoint."""
    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        python_version=sys.version,
        platform=platform.platform(),
    )


@router.get("/status", response_model=StatusResponse)
async def system_status(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> StatusResponse:
    """Full system status including Ollama and tool availability."""
    from app.ai.ollama_client import OllamaClient
    from app.database.repository import FindingRepository, ScanRepository
    from app.scanners.registry import ScannerRegistry

    # Check Ollama
    ollama_status = "unknown"
    try:
        client = OllamaClient(settings)
        reachable = await client.is_reachable()
        if reachable:
            model_ok = await client.model_exists(settings.ollama_model)
            ollama_status = "ready" if model_ok else "model_missing"
        else:
            ollama_status = "unreachable"
    except Exception:
        ollama_status = "error"

    # Check tools
    registry = ScannerRegistry()
    tool_statuses: Dict[str, Any] = {}
    for scanner in registry.all_scanners():
        tool_statuses[scanner.name] = {
            "installed": scanner.is_available(),
            "version": scanner.get_version() if scanner.is_available() else None,
        }

    # DB counts
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)

    return StatusResponse(
        status="ok",
        database=str(settings.db_path),
        ollama=ollama_status,
        ollama_model=settings.ollama_model,
        tools=tool_statuses,
        findings_count=finding_repo.count(),
        scans_count=scan_repo.count(),
        open_findings=finding_repo.count_open(),
    )


@router.get("/dashboard")
async def dashboard_stats(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> Dict[str, Any]:
    """Aggregated dashboard statistics for the frontend."""
    from app.database.repository import FindingRepository, ScanRepository, TargetRepository
    from app.scanners.registry import ScannerRegistry

    target_repo = TargetRepository(db)
    scan_repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    registry = ScannerRegistry()

    all_targets = target_repo.list(limit=1000)
    all_scans = scan_repo.list(limit=1000)
    all_findings = finding_repo.list(limit=5000)

    sev_counts: Dict[str, int] = {}
    status_counts: Dict[str, int] = {}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1

    scan_status_counts: Dict[str, int] = {}
    for s in all_scans:
        k = s.status.upper()
        scan_status_counts[k] = scan_status_counts.get(k, 0) + 1

    return {
        "targets": {
            "total": len(all_targets),
            "active": sum(1 for t in all_targets if t.is_active),
        },
        "scans": {
            "total": len(all_scans),
            "running": scan_status_counts.get("RUNNING", 0),
            "completed": scan_status_counts.get("COMPLETED", 0),
            "failed": scan_status_counts.get("FAILED", 0),
        },
        "findings": {
            "total": len(all_findings),
            "by_severity": sev_counts,
            "by_status": status_counts,
        },
        "tools": {s.name: s.is_available() for s in registry.all_scanners()},
    }
