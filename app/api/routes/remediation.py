"""
Bug Hunter AI — Remediation Routes
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_settings_dep
from app.config import Settings
from app.database.repository import FindingRepository, RemediationRepository

router = APIRouter()


class RemediationResponse(BaseModel):
    id: str
    finding_id: str
    action_type: str
    title: str
    description: Optional[str]
    steps: Optional[List[str]]
    target_file: Optional[str]
    patch_diff: Optional[str]
    backup_path: Optional[str]
    status: str
    approved_at: Optional[str]
    applied_at: Optional[str]
    created_at: str

    model_config = {"from_attributes": True}


def _to_response(a) -> RemediationResponse:
    return RemediationResponse(
        id=a.id,
        finding_id=a.finding_id,
        action_type=a.action_type,
        title=a.title,
        description=a.description,
        steps=a.steps,
        target_file=a.target_file,
        patch_diff=a.patch_diff,
        backup_path=a.backup_path,
        status=a.status,
        approved_at=a.approved_at.isoformat() if a.approved_at else None,
        applied_at=a.applied_at.isoformat() if a.applied_at else None,
        created_at=a.created_at.isoformat(),
    )


@router.get("/finding/{finding_id}", response_model=List[RemediationResponse])
def list_for_finding(finding_id: str, db: Session = Depends(get_db)) -> List[RemediationResponse]:
    repo = RemediationRepository(db)
    return [_to_response(a) for a in repo.list_for_finding(finding_id)]


@router.post("/generate/{finding_id}", response_model=RemediationResponse)
async def generate_remediation(
    finding_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> RemediationResponse:
    """Use AI to generate a remediation recommendation for a finding."""
    finding_repo = FindingRepository(db)
    finding = finding_repo.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    from app.ai.remediation import RemediationAdvisor
    advisor = RemediationAdvisor(settings)
    plan = await advisor.generate(finding)

    rem_repo = RemediationRepository(db)
    action = rem_repo.create(
        finding_id=finding_id,
        action_type=plan.get("action_type", "RECOMMENDATION"),
        title=plan.get("title", "Remediation Plan"),
        description=plan.get("description"),
        steps=plan.get("steps"),
        target_file=plan.get("target_file"),
        patch_diff=plan.get("patch_diff"),
        status="PROPOSED",
    )

    # Update finding status
    finding_repo.update(finding_id, status="REMEDIATION_AVAILABLE")
    db.commit()

    from app.activity.logger import ActivityLogger
    ActivityLogger.log_event(
        "REMEDIATION_GENERATED",
        f"Remediation generated for finding: {finding.title}",
        finding_id=finding_id,
    )

    return _to_response(action)


@router.post("/{action_id}/approve")
def approve_action(
    action_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Approve a remediation action — does NOT automatically apply it."""
    repo = RemediationRepository(db)
    action = repo.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    repo.update(
        action_id,
        status="APPROVED",
        approved_at=datetime.now(timezone.utc),
        approved_by="user",
    )

    finding_repo = FindingRepository(db)
    finding_repo.update(action.finding_id, status="FIX_APPROVED")
    db.commit()

    from app.activity.logger import ActivityLogger
    ActivityLogger.log_event(
        "PATCH_APPROVED",
        f"Remediation action approved: {action.title}",
        finding_id=action.finding_id,
    )
    return {"message": "Action approved. Review the diff before applying."}


@router.post("/{action_id}/reject")
def reject_action(action_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    repo = RemediationRepository(db)
    action = repo.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    repo.update(action_id, status="REJECTED")
    db.commit()

    from app.activity.logger import ActivityLogger
    ActivityLogger.log_event(
        "PATCH_REJECTED",
        f"Remediation action rejected: {action.title}",
        finding_id=action.finding_id,
    )
    return {"message": "Action rejected"}


@router.post("/{action_id}/apply")
async def apply_action(
    action_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> Dict[str, Any]:
    """Apply an approved patch after creating a backup."""
    if settings.auto_apply_fixes:
        pass  # auto apply is enabled
    repo = RemediationRepository(db)
    action = repo.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    if action.status != "APPROVED":
        raise HTTPException(
            status_code=400,
            detail="Action must be approved before applying",
        )

    from app.remediation.patch_generator import PatchApplicator
    applicator = PatchApplicator()
    try:
        backup_path = applicator.apply(action)
        repo.update(
            action_id,
            status="APPLIED",
            applied_at=datetime.now(timezone.utc),
            backup_path=backup_path,
        )
        finding_repo = FindingRepository(db)
        finding_repo.update(action.finding_id, status="FIX_APPLIED")
        db.commit()

        from app.activity.logger import ActivityLogger
        ActivityLogger.log_event(
            "PATCH_APPLIED",
            f"Patch applied for finding. Backup: {backup_path}",
            finding_id=action.finding_id,
        )
        return {"message": "Patch applied successfully", "backup_path": backup_path}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Patch application failed: {exc}")
