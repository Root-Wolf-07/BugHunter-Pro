"""
Bug Hunter AI — Activity Log Routes
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.database.repository import ActivityRepository

router = APIRouter()


class ActivityResponse(BaseModel):
    id: int
    event_type: str
    message: str
    level: str
    details: Optional[Dict[str, Any]]
    scan_id: Optional[str]
    finding_id: Optional[str]
    target_id: Optional[str]
    created_at: str

    model_config = {"from_attributes": True}


@router.get("/", response_model=List[ActivityResponse])
def list_activity(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> List[ActivityResponse]:
    repo = ActivityRepository(db)
    logs = repo.list(limit=limit, offset=offset)
    return [
        ActivityResponse(
            id=log.id,
            event_type=log.event_type,
            message=log.message,
            level=log.level,
            details=log.details,
            scan_id=log.scan_id,
            finding_id=log.finding_id,
            target_id=log.target_id,
            created_at=log.created_at.isoformat(),
        )
        for log in logs
    ]
