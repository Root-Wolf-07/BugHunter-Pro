"""
Bug Hunter AI — Scan Routes
Handles scan creation, execution orchestration, and status updates.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_settings_dep
from app.config import Settings
from app.database.repository import (
    ActivityRepository,
    FindingRepository,
    ScanRepository,
    ScanResultRepository,
    TargetRepository,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class ScanCreate(BaseModel):
    target_id: str
    tools: List[str]  # ["nmap", "nuclei", "nikto", "ffuf"]
    scan_type: Optional[str] = "full"
    authorization_confirmed: bool = False
    options: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    id: str
    target_id: str
    scan_type: str
    tools_used: Optional[List[str]]
    status: str
    authorization_confirmed: bool
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str
    error_message: Optional[str]
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    model_config = {"from_attributes": True}


def _to_response(scan, findings=None) -> ScanResponse:
    fc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if findings:
        for f in findings:
            fc[f.severity] = fc.get(f.severity, 0) + 1
    return ScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        scan_type=scan.scan_type,
        tools_used=scan.tools_used,
        status=scan.status,
        authorization_confirmed=scan.authorization_confirmed,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        created_at=scan.created_at.isoformat(),
        error_message=scan.error_message,
        findings_count=len(findings) if findings else 0,
        critical_count=fc["CRITICAL"],
        high_count=fc["HIGH"],
        medium_count=fc["MEDIUM"],
        low_count=fc["LOW"],
        info_count=fc["INFO"],
    )


async def _run_scan(scan_id: str, settings: Settings) -> None:
    """Background task: orchestrate scanner + AI pipeline."""
    from app.database.session import db_session
    from app.scanners.registry import ScannerRegistry
    from app.ai.analyzer import AIAnalyzer
    from app.findings.parser import FindingParser
    from app.findings.deduplicator import Deduplicator

    registry = ScannerRegistry()

    with db_session() as db:
        scan_repo = ScanRepository(db)
        scan_result_repo = ScanResultRepository(db)
        finding_repo = FindingRepository(db)
        activity_repo = ActivityRepository(db)
        target_repo = TargetRepository(db)

        scan = scan_repo.get(scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found in background task")
            return

        target = target_repo.get(scan.target_id)
        if not target:
            scan_repo.update_status(scan_id, "failed", error_message="Target not found")
            return

        scan_repo.update_status(
            scan_id, "running", started_at=datetime.now(timezone.utc)
        )
        activity_repo.log(
            "SCAN_STARTED",
            f"Scan started on {target.value}",
            scan_id=scan_id,
            target_id=target.id,
        )

        all_raw_results = []
        tools_used = scan.tools_used or []

        for tool_name in tools_used:
            scanner = registry.get(tool_name)
            if not scanner:
                activity_repo.log(
                    "TOOL_MISSING",
                    f"Scanner '{tool_name}' not registered",
                    level="WARNING",
                    scan_id=scan_id,
                )
                continue

            if not scanner.is_available():
                activity_repo.log(
                    "TOOL_MISSING",
                    f"Tool '{tool_name}' is not installed",
                    level="WARNING",
                    scan_id=scan_id,
                )
                continue

            logger.info(f"Running {tool_name} against {target.value}")
            try:
                raw_output, parsed = await asyncio.to_thread(
                    scanner.scan, target.value, scan.id, {}
                )
                result_row = scan_result_repo.create(
                    scan_id=scan_id,
                    tool_name=tool_name,
                    raw_output=raw_output,
                    parsed_data=parsed,
                    success=True,
                )
                all_raw_results.append((tool_name, parsed))
                activity_repo.log(
                    "TOOL_COMPLETED",
                    f"{tool_name} completed",
                    scan_id=scan_id,
                )
            except Exception as exc:
                logger.error(f"{tool_name} failed: {exc}")
                scan_result_repo.create(
                    scan_id=scan_id,
                    tool_name=tool_name,
                    success=False,
                    error_message=str(exc),
                )
                activity_repo.log(
                    "TOOL_EXECUTION_FAILED",
                    f"{tool_name} failed: {exc}",
                    level="ERROR",
                    scan_id=scan_id,
                )

        # Parse and normalize findings
        parser = FindingParser()
        dedup = Deduplicator()
        raw_findings = []
        for tool_name, parsed in all_raw_results:
            raw_findings.extend(parser.parse(tool_name, parsed, target.id, scan_id))

        unique_findings = dedup.deduplicate(raw_findings)

        # AI Analysis
        activity_repo.log(
            "AI_ANALYSIS_STARTED",
            f"AI analysis starting for {len(unique_findings)} findings",
            scan_id=scan_id,
        )

        analyzer = AIAnalyzer(settings)
        analyzed_findings = []
        for finding_data in unique_findings:
            try:
                enriched = await analyzer.analyze_finding(finding_data)
                analyzed_findings.append(enriched)
            except Exception as exc:
                logger.warning(f"AI analysis failed for finding: {exc}")
                analyzed_findings.append(finding_data)

        # Store findings
        for finding_data in analyzed_findings:
            # Check dedup by fingerprint
            existing = finding_repo.get_by_fingerprint(finding_data.get("fingerprint", ""))
            if existing:
                continue
            finding_repo.create(**finding_data)

        activity_repo.log(
            "AI_ANALYSIS_COMPLETED",
            f"AI analysis completed. {len(analyzed_findings)} findings stored.",
            scan_id=scan_id,
        )

        scan_repo.update_status(
            scan_id,
            "completed",
            completed_at=datetime.now(timezone.utc),
        )
        activity_repo.log(
            "SCAN_COMPLETED",
            f"Scan completed. {len(analyzed_findings)} findings.",
            scan_id=scan_id,
        )


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> List[ScanResponse]:
    repo = ScanRepository(db)
    finding_repo = FindingRepository(db)
    result = []
    for s in repo.list(limit=limit, offset=offset):
        findings = finding_repo.list(scan_id=s.id)
        result.append(_to_response(s, findings))
    return result


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> ScanResponse:
    """Create and immediately start a new scan."""
    # Authorization gate
    if not body.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail=(
                "Authorization confirmation is required. "
                "You must confirm you are authorized to scan this target."
            ),
        )

    # Verify target exists
    target_repo = TargetRepository(db)
    target = target_repo.get(body.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Update target auth flag
    target_repo.update(body.target_id, authorization_confirmed=True)

    scan_repo = ScanRepository(db)
    scan = scan_repo.create(
        target_id=body.target_id,
        scan_type=body.scan_type or "full",
        tools_used=body.tools,
        authorization_confirmed=True,
        status="pending",
    )
    db.commit()

    # Launch background scan
    background_tasks.add_task(_run_scan, scan.id, settings)

    return _to_response(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanResponse:
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    finding_repo = FindingRepository(db)
    count = len(finding_repo.list(scan_id=scan_id))
    return _to_response(scan, findings_count=count)


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, str]:
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled in current state")
    repo.update_status(scan_id, "cancelled")
    db.commit()
    return {"message": "Scan cancellation requested"}
