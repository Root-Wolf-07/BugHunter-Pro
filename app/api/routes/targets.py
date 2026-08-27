"""
Bug Hunter AI — Target Routes
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_settings_dep
from app.config import Settings
from app.database.repository import TargetRepository

router = APIRouter()


class TargetCreate(BaseModel):
    name: str
    target_type: str
    value: str
    description: Optional[str] = None
    authorization_confirmed: bool = False
    authorization_note: Optional[str] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    authorization_confirmed: Optional[bool] = None
    authorization_note: Optional[str] = None


class TargetResponse(BaseModel):
    id: str
    name: str
    target_type: str
    value: str
    description: Optional[str]
    authorization_confirmed: bool
    authorization_note: Optional[str]
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


def _to_response(t) -> TargetResponse:
    return TargetResponse(
        id=t.id,
        name=t.name,
        target_type=t.target_type,
        value=t.value,
        description=t.description,
        authorization_confirmed=t.authorization_confirmed,
        authorization_note=t.authorization_note,
        created_at=t.created_at.isoformat(),
        updated_at=t.updated_at.isoformat(),
    )


@router.get("/", response_model=List[TargetResponse])
def list_targets(db: Session = Depends(get_db)) -> List[TargetResponse]:
    repo = TargetRepository(db)
    return [_to_response(t) for t in repo.list()]


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    body: TargetCreate,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> TargetResponse:
    if settings.require_authorization and not body.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Authorization confirmation is required. You must confirm you are authorized to scan this target.",
        )
    repo = TargetRepository(db)
    t = repo.create(**body.model_dump())
    db.commit()
    from app.activity.logger import ActivityLogger
    ActivityLogger.log_event(
        "TARGET_CREATED", f"Target created: {t.name} ({t.value})", target_id=t.id
    )
    return _to_response(t)


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(target_id: str, db: Session = Depends(get_db)) -> TargetResponse:
    repo = TargetRepository(db)
    t = repo.get(target_id)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    return _to_response(t)


@router.patch("/{target_id}", response_model=TargetResponse)
def update_target(
    target_id: str, body: TargetUpdate, db: Session = Depends(get_db)
) -> TargetResponse:
    repo = TargetRepository(db)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    t = repo.update(target_id, **updates)
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    db.commit()
    return _to_response(t)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: str, db: Session = Depends(get_db)) -> None:
    repo = TargetRepository(db)
    if not repo.delete(target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    db.commit()
