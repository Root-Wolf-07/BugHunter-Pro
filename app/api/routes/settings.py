"""
Bug Hunter AI — Settings Routes
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.database.repository import SettingsRepository

router = APIRouter()


class SettingItem(BaseModel):
    key: str
    value: Optional[str]
    description: Optional[str]


class SettingUpdate(BaseModel):
    value: str


@router.get("/", response_model=List[SettingItem])
def get_settings(db: Session = Depends(get_db)) -> List[SettingItem]:
    repo = SettingsRepository(db)
    return [
        SettingItem(key=s.key, value=s.value, description=s.description)
        for s in repo.all()
    ]


@router.put("/{key}", response_model=SettingItem)
def update_setting(key: str, body: SettingUpdate, db: Session = Depends(get_db)) -> SettingItem:
    repo = SettingsRepository(db)
    s = repo.set(key, body.value)
    db.commit()
    return SettingItem(key=s.key, value=s.value, description=s.description)


@router.get("/runtime", response_model=Dict[str, Any])
def get_runtime_config() -> Dict[str, Any]:
    """Return non-sensitive runtime configuration."""
    from app.config import get_settings
    s = get_settings()
    return {
        "app_host": s.app_host,
        "app_port": s.app_port,
        "ollama_host": s.ollama_host,
        "ollama_model": s.ollama_model,
        "log_level": s.log_level,
        "require_authorization": s.require_authorization,
        "auto_apply_fixes": s.auto_apply_fixes,
        "scan_timeout": s.scan_timeout,
    }
