"""
Bug Hunter AI — Reports Routes
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db

router = APIRouter()


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "html"  # html | json | markdown


@router.post("/generate")
async def generate_report(
    body: ReportRequest,
    db: Session = Depends(get_db),
) -> Response:
    """Generate a security report for a scan."""
    from app.database.repository import FindingRepository, ScanRepository, TargetRepository
    from app.utils.reporter import ReportGenerator

    scan_repo = ScanRepository(db)
    scan = scan_repo.get(body.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding_repo = FindingRepository(db)
    findings = finding_repo.list(scan_id=body.scan_id, limit=1000)

    target_repo = TargetRepository(db)
    target = target_repo.get(scan.target_id)

    generator = ReportGenerator()
    content, content_type = generator.generate(
        scan=scan,
        target=target,
        findings=findings,
        fmt=body.format,
    )

    filename = f"bug-hunter-report-{body.scan_id[:8]}.{body.format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type=content_type, headers=headers)
