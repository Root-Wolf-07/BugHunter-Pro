"""
Bug Hunter AI — Activity Logger
Writes structured events to the local activity_logs table.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ActivityLogger:
    """
    Writes important application events to the activity_logs database table.
    All events are stored locally — no telemetry, no cloud upload.
    """

    # Standard event types
    APPLICATION_STARTED = "APPLICATION_STARTED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    TOOL_MISSING = "TOOL_MISSING"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"
    AI_ANALYSIS_STARTED = "AI_ANALYSIS_STARTED"
    AI_ANALYSIS_COMPLETED = "AI_ANALYSIS_COMPLETED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_STATUS_UPDATED = "FINDING_STATUS_UPDATED"
    REMEDIATION_GENERATED = "REMEDIATION_GENERATED"
    PATCH_APPROVED = "PATCH_APPROVED"
    PATCH_REJECTED = "PATCH_REJECTED"
    PATCH_APPLIED = "PATCH_APPLIED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    TARGET_CREATED = "TARGET_CREATED"

    @staticmethod
    def log_event(
        event_type: str,
        message: str,
        level: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> None:
        """
        Write an event to the activity log.
        Falls back to standard logging if the database is unavailable.
        """
        try:
            from app.database.session import db_session
            from app.database.repository import ActivityRepository

            with db_session() as db:
                repo = ActivityRepository(db)
                repo.log(
                    event_type=event_type,
                    message=message,
                    level=level,
                    details=details,
                    scan_id=scan_id,
                    finding_id=finding_id,
                    target_id=target_id,
                )
        except Exception as exc:
            # Never crash the application because of a logging failure
            logger.warning(f"Activity log write failed: {exc}")

        # Also log to standard logger
        log_fn = getattr(logger, level.lower(), logger.info)
        log_fn(f"[{event_type}] {message}")
