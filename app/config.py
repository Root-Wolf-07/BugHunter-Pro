"""
Bug Hunter AI — Application Configuration
Loaded from environment variables / .env file.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ────────────────────────────────────────────────────────────
    app_host: str = "127.0.0.1"
    app_port: int = 8787
    app_debug: bool = False

    # ── Ollama ─────────────────────────────────────────────────────────────────
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3"
    ollama_timeout: int = 120

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = f"sqlite:///{Path.home()}/.bug-hunter/bug_hunter.db"

    # ── Logging ────────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # ── Security Behavior ──────────────────────────────────────────────────────
    require_authorization: bool = True
    auto_apply_fixes: bool = False

    # ── Scanner Defaults ───────────────────────────────────────────────────────
    nmap_default_flags: str = "-sV --open"
    scan_timeout: int = 300

    @field_validator("database_url")
    @classmethod
    def expand_db_path(cls, v: str) -> str:
        """Expand ~ in SQLite paths."""
        if v.startswith("sqlite:///~"):
            expanded = str(Path(v.replace("sqlite:///", "")).expanduser())
            return f"sqlite:///{expanded}"
        return v

    @field_validator("log_file")
    @classmethod
    def expand_log_path(cls, v: Optional[str]) -> Optional[str]:
        """Expand ~ in log file paths."""
        if v:
            return str(Path(v).expanduser())
        return v

    @property
    def db_path(self) -> Path:
        """Return the filesystem path of the SQLite database."""
        url = self.database_url
        if url.startswith("sqlite:///"):
            return Path(url[len("sqlite:///"):])
        raise ValueError(f"Unsupported database URL: {url}")

    @property
    def data_dir(self) -> Path:
        """Return the Bug Hunter data directory (parent of the DB)."""
        return self.db_path.parent


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
