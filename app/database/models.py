"""
Bug Hunter AI — SQLAlchemy ORM Models
All tables stored in the local SQLite database.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Declarative base for all models."""


# ─────────────────────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────────────────────
class Setting(Base):
    """Key-value application settings stored in the database."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tool Status
# ─────────────────────────────────────────────────────────────────────────────
class ToolStatus(Base):
    """Tracks whether external security tools are installed and their versions."""

    __tablename__ = "tool_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    installed: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


# ─────────────────────────────────────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────────────────────────────────────
class Target(Base):
    """A scan target (IP, hostname, URL, etc.)."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), default="hostname", nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target")


# ─────────────────────────────────────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────────────────────────────────────
class Scan(Base):
    """A security scanning session."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False, index=True
    )
    scan_type: Mapped[str] = mapped_column(String(64), default="full")
    tools_used: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # list of tool names
    status: Mapped[str] = mapped_column(
        Enum(
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            name="scan_status_enum",
        ),
        default="pending",
    )
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    results: Mapped[list["ScanResult"]] = relationship("ScanResult", back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan")


# ─────────────────────────────────────────────────────────────────────────────
# Scan Results (raw tool output)
# ─────────────────────────────────────────────────────────────────────────────
class ScanResult(Base):
    """Raw output from a single scanner tool."""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parsed_data: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")


# ─────────────────────────────────────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────────────────────────────────────
class Finding(Base):
    """A normalized security vulnerability finding."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=False, index=True
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False, index=True
    )

    # Classification
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(
        Enum("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity_enum"),
        nullable=False,
        index=True,
    )
    confidence: Mapped[str] = mapped_column(
        Enum("CONFIRMED", "LIKELY", "POTENTIAL", "INFORMATIONAL", name="confidence_enum"),
        default="POTENTIAL",
    )

    # Details
    affected_component: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    potential_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # list of URLs

    # Source
    detected_by: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_finding: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # AI Analysis
    ai_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    ai_confidence: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # Status lifecycle
    status: Mapped[str] = mapped_column(
        Enum(
            "NEW",
            "ANALYZING",
            "CONFIRMED",
            "FALSE_POSITIVE",
            "REMEDIATION_AVAILABLE",
            "FIX_APPROVED",
            "FIX_APPLIED",
            "VERIFYING",
            "FIXED",
            "REOPENED",
            name="finding_status_enum",
        ),
        default="NEW",
        index=True,
    )
    verification_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Dedup fingerprint
    fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    remediation_actions: Mapped[list["RemediationAction"]] = relationship(
        "RemediationAction", back_populates="finding"
    )
    verification_results: Mapped[list["VerificationResult"]] = relationship(
        "VerificationResult", back_populates="finding"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Remediation Actions
# ─────────────────────────────────────────────────────────────────────────────
class RemediationAction(Base):
    """A proposed or applied remediation for a finding."""

    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=False, index=True
    )

    action_type: Mapped[str] = mapped_column(
        Enum("RECOMMENDATION", "PATCH", "COMMAND", "MANUAL", name="action_type_enum"),
        default="RECOMMENDATION",
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    steps: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)  # list of step strings

    # Patch proposal
    target_file: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    patch_diff: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    backup_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    # Approval state
    status: Mapped[str] = mapped_column(
        Enum("PROPOSED", "APPROVED", "REJECTED", "APPLIED", "FAILED", name="action_status_enum"),
        default="PROPOSED",
    )
    approved_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    finding: Mapped["Finding"] = relationship("Finding", back_populates="remediation_actions")


# ─────────────────────────────────────────────────────────────────────────────
# Verification Results
# ─────────────────────────────────────────────────────────────────────────────
class VerificationResult(Base):
    """Result of a re-scan performed to verify a fix."""

    __tablename__ = "verification_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=False, index=True
    )
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scans.id"), nullable=True
    )

    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    method: Mapped[str] = mapped_column(String(128), default="rescan")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="verification_results")


# ─────────────────────────────────────────────────────────────────────────────
# Activity Log
# ─────────────────────────────────────────────────────────────────────────────
class ActivityLog(Base):
    """Chronological log of all important application events."""

    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(JSON, nullable=True)

    # Optional references
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    level: Mapped[str] = mapped_column(String(16), default="INFO")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
