"""
Bug Hunter AI — Finding Routes
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.database.repository import FindingRepository

router = APIRouter()


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    target_id: str
    title: str
    category: str
    severity: str
    confidence: str
    affected_component: Optional[str]
    description: Optional[str]
    evidence: Optional[str]
    potential_impact: Optional[str]
    root_cause: Optional[str]
    remediation: Optional[str]
    references: Optional[List[str]]
    detected_by: str
    ai_analysis: Optional[str]
    ai_severity: Optional[str]
    status: str
    verification_status: Optional[str]
    detected_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: str


def _to_response(f) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        target_id=f.target_id,
        title=f.title,
        category=f.category,
        severity=f.severity,
        confidence=f.confidence,
        affected_component=f.affected_component,
        description=f.description,
        evidence=f.evidence,
        potential_impact=f.potential_impact,
        root_cause=f.root_cause,
        remediation=f.remediation,
        references=f.references,
        detected_by=f.detected_by,
        ai_analysis=f.ai_analysis,
        ai_severity=f.ai_severity,
        status=f.status,
        verification_status=f.verification_status,
        detected_at=f.detected_at.isoformat(),
        updated_at=f.updated_at.isoformat(),
    )


@router.get("/", response_model=List[FindingResponse])
def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> List[FindingResponse]:
    repo = FindingRepository(db)
    return [
        _to_response(f)
        for f in repo.list(
            severity=severity,
            status=status,
            target_id=target_id,
            scan_id=scan_id,
            category=category,
            limit=limit,
            offset=offset,
        )
    ]


@router.get("/stats", response_model=Dict[str, Any])
def finding_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    repo = FindingRepository(db)
    return {
        "by_severity": repo.count_by_severity(),
        "by_status": repo.count_by_status(),
        "total": repo.count(),
        "open": repo.count_open(),
    }


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)) -> FindingResponse:
    repo = FindingRepository(db)
    f = repo.get(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_response(f)


@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: str, body: FindingStatusUpdate, db: Session = Depends(get_db)
) -> FindingResponse:
    valid_statuses = {
        "NEW", "ANALYZING", "CONFIRMED", "FALSE_POSITIVE",
        "REMEDIATION_AVAILABLE", "FIX_APPROVED", "FIX_APPLIED",
        "VERIFYING", "FIXED", "REOPENED",
    }
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    repo = FindingRepository(db)
    f = repo.update(finding_id, status=body.status)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.commit()

    from app.activity.logger import ActivityLogger
    ActivityLogger.log_event(
        "FINDING_STATUS_UPDATED",
        f"Finding status changed to {body.status}",
        finding_id=finding_id,
    )
    return _to_response(f)
