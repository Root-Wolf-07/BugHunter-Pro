"""
Bug Hunter AI — Database Session Management
Creates the SQLAlchemy engine and session factory.
The database file is stored locally at ~/.bug-hunter/bug_hunter.db by default.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.database.models import Base


def _ensure_data_dir(db_url: str) -> None:
    """Create the data directory if it does not exist."""
    if db_url.startswith("sqlite:///"):
        db_path = Path(db_url[len("sqlite:///"):])
        db_path.parent.mkdir(parents=True, exist_ok=True)


def _set_sqlite_pragmas(dbapi_conn, _connection_record) -> None:  # type: ignore[no-untyped-def]
    """Enable WAL mode and foreign keys for each new SQLite connection."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


_engine = None
_SessionLocal = None


def init_db() -> None:
    """
    Initialize the database engine and create all tables.
    Must be called once at application startup.
    """
    global _engine, _SessionLocal

    settings = get_settings()
    _ensure_data_dir(settings.database_url)

    _engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        echo=settings.app_debug,
    )

    # Apply SQLite-specific pragmas
    event.listen(_engine, "connect", _set_sqlite_pragmas)

    # Create all tables (no-op for existing tables)
    Base.metadata.create_all(bind=_engine)

    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def get_engine():
    """Return the SQLAlchemy engine, initializing if needed."""
    if _engine is None:
        init_db()
    return _engine


def get_session_factory():
    """Return the session factory, initializing if needed."""
    if _SessionLocal is None:
        init_db()
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session per request.
    Usage:
        def my_endpoint(db: Session = Depends(get_db)):
            ...
    """
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager for use outside of FastAPI request scope."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
