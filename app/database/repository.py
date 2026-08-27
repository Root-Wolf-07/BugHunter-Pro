"""
Bug Hunter AI — Database Repository Layer
Typed CRUD helpers that wrap SQLAlchemy sessions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database.models import (
    ActivityLog,
    Finding,
    RemediationAction,
    Scan,
    ScanResult,
    Setting,
    Target,
    ToolStatus,
    VerificationResult,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Settings Repository
# ─────────────────────────────────────────────────────────────────────────────
class SettingsRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get(self, key: str) -> Optional[str]:
        row = self.db.query(Setting).filter(Setting.key == key).first()
        return row.value if row else None

    def set(self, key: str, value: str, description: Optional[str] = None) -> Setting:
        row = self.db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
            if description:
                row.description = description
        else:
            row = Setting(key=key, value=value, description=description)
            self.db.add(row)
        self.db.flush()
        return row

    def all(self) -> List[Setting]:
        return self.db.query(Setting).order_by(Setting.key).all()


# ─────────────────────────────────────────────────────────────────────────────
# Target Repository
# ─────────────────────────────────────────────────────────────────────────────
class TargetRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **kwargs: Any) -> Target:
        target = Target(**kwargs)
        self.db.add(target)
        self.db.flush()
        return target

    def get(self, target_id: str) -> Optional[Target]:
        return self.db.query(Target).filter(Target.id == target_id).first()

    def list(self, limit: Optional[int] = None, offset: int = 0) -> List[Target]:
        query = self.db.query(Target).order_by(desc(Target.created_at)).offset(offset)
        if limit is not None:
            query = query.limit(limit)
        return query.all()

    def update(self, target_id: str, **kwargs: Any) -> Optional[Target]:
        target = self.get(target_id)
        if not target:
            return None
        for k, v in kwargs.items():
            setattr(target, k, v)
        self.db.flush()
        return target

    def delete(self, target_id: str) -> bool:
        target = self.get(target_id)
        if not target:
            return False
        self.db.delete(target)
        self.db.flush()
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Scan Repository
# ─────────────────────────────────────────────────────────────────────────────
class ScanRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **kwargs: Any) -> Scan:
        scan = Scan(**kwargs)
        self.db.add(scan)
        self.db.flush()
        return scan

    def get(self, scan_id: str) -> Optional[Scan]:
        return self.db.query(Scan).filter(Scan.id == scan_id).first()

    def list(self, limit: int = 50, offset: int = 0) -> List[Scan]:
        return (
            self.db.query(Scan)
            .order_by(desc(Scan.created_at))
            .limit(limit)
            .offset(offset)
            .all()
        )

    def update_status(self, scan_id: str, status: str, **extra: Any) -> Optional[Scan]:
        scan = self.get(scan_id)
        if not scan:
            return None
        scan.status = status
        for k, v in extra.items():
            setattr(scan, k, v)
        self.db.flush()
        return scan

    def count(self) -> int:
        return self.db.query(Scan).count()


# ─────────────────────────────────────────────────────────────────────────────
# ScanResult Repository
# ─────────────────────────────────────────────────────────────────────────────
class ScanResultRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **kwargs: Any) -> ScanResult:
        result = ScanResult(**kwargs)
        self.db.add(result)
        self.db.flush()
        return result

    def list_for_scan(self, scan_id: str) -> List[ScanResult]:
        return self.db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()


# ─────────────────────────────────────────────────────────────────────────────
# Finding Repository
# ─────────────────────────────────────────────────────────────────────────────
class FindingRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **kwargs: Any) -> Finding:
        finding = Finding(**kwargs)
        self.db.add(finding)
        self.db.flush()
        return finding

    def get(self, finding_id: str) -> Optional[Finding]:
        return self.db.query(Finding).filter(Finding.id == finding_id).first()

    def list(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        target_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        q = self.db.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity)
        if status:
            q = q.filter(Finding.status == status)
        if target_id:
            q = q.filter(Finding.target_id == target_id)
        if scan_id:
            q = q.filter(Finding.scan_id == scan_id)
        if category:
            q = q.filter(Finding.category == category)
        return q.order_by(desc(Finding.detected_at)).limit(limit).offset(offset).all()

    def count_by_severity(self) -> Dict[str, int]:
        from sqlalchemy import func
        rows = (
            self.db.query(Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity)
            .all()
        )
        return {sev: count for sev, count in rows}

    def count_by_status(self) -> Dict[str, int]:
        from sqlalchemy import func
        rows = (
            self.db.query(Finding.status, func.count(Finding.id))
            .group_by(Finding.status)
            .all()
        )
        return {st: count for st, count in rows}

    def get_by_fingerprint(self, fingerprint: str) -> Optional[Finding]:
        return self.db.query(Finding).filter(Finding.fingerprint == fingerprint).first()

    def update(self, finding_id: str, **kwargs: Any) -> Optional[Finding]:
        finding = self.get(finding_id)
        if not finding:
            return None
        for k, v in kwargs.items():
            setattr(finding, k, v)
        self.db.flush()
        return finding

    def count(self) -> int:
        return self.db.query(Finding).count()

    def count_open(self) -> int:
        return (
            self.db.query(Finding)
            .filter(Finding.status.notin_(["FALSE_POSITIVE", "FIXED"]))
            .count()
        )


# ─────────────────────────────────────────────────────────────────────────────
# RemediationAction Repository
# ─────────────────────────────────────────────────────────────────────────────
class RemediationRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **kwargs: Any) -> RemediationAction:
        action = RemediationAction(**kwargs)
        self.db.add(action)
        self.db.flush()
        return action

    def get(self, action_id: str) -> Optional[RemediationAction]:
        return self.db.query(RemediationAction).filter(RemediationAction.id == action_id).first()

    def list_for_finding(self, finding_id: str) -> List[RemediationAction]:
        return (
            self.db.query(RemediationAction)
            .filter(RemediationAction.finding_id == finding_id)
            .order_by(desc(RemediationAction.created_at))
            .all()
        )

    def update(self, action_id: str, **kwargs: Any) -> Optional[RemediationAction]:
        action = self.get(action_id)
        if not action:
            return None
        for k, v in kwargs.items():
            setattr(action, k, v)
        self.db.flush()
        return action


# ─────────────────────────────────────────────────────────────────────────────
# VerificationResult Repository
# ─────────────────────────────────────────────────────────────────────────────
class VerificationRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, **kwargs: Any) -> VerificationResult:
        vr = VerificationResult(**kwargs)
        self.db.add(vr)
        self.db.flush()
        return vr

    def list_for_finding(self, finding_id: str) -> List[VerificationResult]:
        return (
            self.db.query(VerificationResult)
            .filter(VerificationResult.finding_id == finding_id)
            .order_by(desc(VerificationResult.verified_at))
            .all()
        )


# ─────────────────────────────────────────────────────────────────────────────
# ActivityLog Repository
# ─────────────────────────────────────────────────────────────────────────────
class ActivityRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def log(
        self,
        event_type: str,
        message: str,
        level: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> ActivityLog:
        entry = ActivityLog(
            event_type=event_type,
            message=message,
            level=level,
            details=details,
            scan_id=scan_id,
            finding_id=finding_id,
            target_id=target_id,
        )
        self.db.add(entry)
        self.db.flush()
        return entry

    def list(self, limit: int = 100, offset: int = 0) -> List[ActivityLog]:
        return (
            self.db.query(ActivityLog)
            .order_by(desc(ActivityLog.created_at))
            .limit(limit)
            .offset(offset)
            .all()
        )

    def count(self) -> int:
        return self.db.query(ActivityLog).count()


# ─────────────────────────────────────────────────────────────────────────────
# ToolStatus Repository
# ─────────────────────────────────────────────────────────────────────────────
class ToolRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def upsert(self, name: str, installed: bool, version: Optional[str] = None,
               path: Optional[str] = None) -> ToolStatus:
        row = self.db.query(ToolStatus).filter(ToolStatus.name == name).first()
        if row:
            row.installed = installed
            row.version = version
            row.path = path
        else:
            row = ToolStatus(name=name, installed=installed, version=version, path=path)
            self.db.add(row)
        self.db.flush()
        return row

    def all(self) -> List[ToolStatus]:
        return self.db.query(ToolStatus).order_by(ToolStatus.name).all()

    def get(self, name: str) -> Optional[ToolStatus]:
        return self.db.query(ToolStatus).filter(ToolStatus.name == name).first()
