"""
Bug Hunter AI — Configuration Unit Tests
"""
from app.config import Settings


def test_default_settings():
    settings = Settings()
    assert settings.app_port == 8787
    assert settings.app_host == "127.0.0.1"
    assert settings.ollama_model == "llama3"
    assert settings.require_authorization is True
    assert settings.auto_apply_fixes is False


def test_custom_settings():
    settings = Settings(
        app_port=9000,
        app_host="0.0.0.0",
        ollama_model="mistral:latest",
        require_authorization=False,
    )
    assert settings.app_port == 9000
    assert settings.ollama_model == "mistral:latest"
    assert settings.require_authorization is False
