"""
Bug Hunter AI — FastAPI Dependencies
"""
from __future__ import annotations

from typing import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database.session import get_db


def get_settings_dep() -> Settings:
    """FastAPI dependency for application settings."""
    return get_settings()


# Re-export get_db for use in route files
__all__ = ["get_db", "get_settings_dep", "Settings", "Session", "Depends", "Generator"]
