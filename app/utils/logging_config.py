"""
Bug Hunter AI — Logging Configuration
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


def configure_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure structured application logging."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list = [logging.StreamHandler(sys.stdout)]

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_path), encoding="utf-8"))

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )

    # Quiet down noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
