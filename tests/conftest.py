"""
Bug Hunter AI — Pytest Fixtures
"""
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings, get_settings
from app.database.models import Base
from app.database.session import get_db
from app.main import create_app


@pytest.fixture(scope="session")
def test_settings():
    """Create test settings pointing to a temp SQLite database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    settings = Settings(
        app_env="testing",
        debug=True,
        db_path=db_path,
        ollama_host="http://localhost:11434",
        ollama_model="llama3",
        require_authorization=True,
        auto_apply_fixes=False,
    )
    yield settings
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture(scope="function")
def db_session():
    """In-memory SQLite database session for unit tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session, test_settings):
    """FastAPI TestClient with overridden database session and settings."""
    app = create_app()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    def override_get_settings():
        return test_settings

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_get_settings

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
