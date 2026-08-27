"""
Bug Hunter AI — Ollama HTTP Client
Wraps the Ollama REST API with graceful error handling.
"""
from __future__ import annotations

import logging
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

OLLAMA_UNREACHABLE_MSG = """
Ollama is not reachable.

Expected: {host}

Please start Ollama and try again:
  Linux:   systemctl start ollama  (or: ollama serve)
  macOS:   open -a Ollama  (or: ollama serve)

If Ollama is not installed:
  Linux:   curl -fsSL https://ollama.com/install.sh | sh
  macOS:   brew install ollama
"""

MODEL_MISSING_MSG = """
Ollama model '{model}' is not available.

To install it, run:
  ollama pull {model}

Available models on your system:
{available}

You can also change the model in your .env file:
  OLLAMA_MODEL=llama3
"""


class OllamaClient:
    """Async HTTP client for the Ollama REST API."""

    def __init__(self, settings: Settings) -> None:
        self.host = settings.ollama_host.rstrip("/")
        self.model = settings.ollama_model
        self.timeout = settings.ollama_timeout

    async def is_reachable(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.host}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def get_version(self) -> Optional[str]:
        """Return the Ollama version string or None."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.host}/api/version")
                if resp.status_code == 200:
                    return resp.json().get("version")
        except Exception:
            pass
        return None

    async def list_models(self) -> List[str]:
        """Return a list of model names available on this Ollama instance."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.host}/api/tags")
                if resp.status_code == 200:
                    data = resp.json()
                    return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            pass
        return []

    async def model_exists(self, model: Optional[str] = None) -> bool:
        """Return True if the configured model exists locally."""
        target = model or self.model
        models = await self.list_models()
        # Ollama model names may include tags (e.g. "llama3:latest")
        for m in models:
            base = m.split(":")[0]
            if base == target or m == target:
                return True
        return False

    async def assert_ready(self) -> None:
        """
        Raise a descriptive RuntimeError if Ollama or the model is not available.
        """
        if not await self.is_reachable():
            raise RuntimeError(
                OLLAMA_UNREACHABLE_MSG.format(host=self.host)
            )
        if not await self.model_exists():
            available = await self.list_models()
            available_str = "\n".join(f"  - {m}" for m in available) or "  (none installed)"
            raise RuntimeError(
                MODEL_MISSING_MSG.format(
                    model=self.model,
                    available=available_str,
                )
            )

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> str:
        """
        Send a chat completion request to Ollama.
        Returns the assistant's reply as a string.
        """
        target_model = model or self.model
        payload: Dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.host}/api/chat",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")
        except httpx.ConnectError:
            raise RuntimeError(OLLAMA_UNREACHABLE_MSG.format(host=self.host))
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"Ollama API error {exc.response.status_code}: {exc.response.text}")
        except Exception as exc:
            raise RuntimeError(f"Ollama request failed: {exc}")

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.1,
    ) -> str:
        """Send a generate (non-chat) request to Ollama."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.chat(messages, model=model, temperature=temperature)
