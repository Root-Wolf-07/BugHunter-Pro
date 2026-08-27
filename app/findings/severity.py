"""
Bug Hunter AI — Severity Helpers
"""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

_NORMALIZATION_MAP = {
    "informational": "INFO",
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "med": "MEDIUM",
    "moderate": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
    "urgent": "CRITICAL",
}


def normalize_severity(raw: str) -> str:
    """Normalize any severity string to an uppercase Bug Hunter severity."""
    clean = str(raw).strip().lower()
    return _NORMALIZATION_MAP.get(clean, "LOW")


def severity_score(severity: str) -> int:
    """Return a numeric score for sorting (higher = more severe)."""
    return SEVERITY_ORDER.get(severity.upper(), 0)


def severity_color(severity: str) -> str:
    """Return an ANSI color code for terminal display."""
    colors = {
        "INFO": "\033[36m",       # cyan
        "LOW": "\033[32m",        # green
        "MEDIUM": "\033[33m",     # yellow
        "HIGH": "\033[91m",       # bright red
        "CRITICAL": "\033[31;1m", # bold red
    }
    return colors.get(severity.upper(), "\033[0m")
