"""
Bug Hunter AI — Tool Status Routes
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.dependencies import get_db

router = APIRouter()


class ToolInfo(BaseModel):
    name: str
    installed: bool
    version: Optional[str]
    install_linux: str
    install_macos: str
    description: str


TOOL_INSTALL_INFO: Dict[str, Dict[str, str]] = {
    "nmap": {
        "install_linux": "sudo apt install nmap",
        "install_macos": "brew install nmap",
        "description": "Network mapper — host discovery, port scanning, service/version detection",
    },
    "nuclei": {
        "install_linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "install_macos": "brew install nuclei",
        "description": "Vulnerability scanner based on customizable YAML templates",
    },
    "nikto": {
        "install_linux": "sudo apt install nikto",
        "install_macos": "brew install nikto",
        "description": "Web server scanner — checks for dangerous files, outdated software",
    },
    "ffuf": {
        "install_linux": "go install github.com/ffuf/ffuf/v2@latest",
        "install_macos": "brew install ffuf",
        "description": "Web fuzzer — authorized content/path discovery",
    },
    "ollama": {
        "install_linux": "curl -fsSL https://ollama.com/install.sh | sh",
        "install_macos": "brew install ollama",
        "description": "Local AI model runner — required for AI analysis",
    },
}


@router.get("/", response_model=List[ToolInfo])
async def list_tools() -> List[ToolInfo]:
    from app.scanners.registry import ScannerRegistry
    from app.ai.ollama_client import OllamaClient
    from app.config import get_settings

    registry = ScannerRegistry()
    settings = get_settings()
    results: List[ToolInfo] = []

    for scanner in registry.all_scanners():
        available = scanner.is_available()
        version = scanner.get_version() if available else None
        info = TOOL_INSTALL_INFO.get(scanner.name, {})
        results.append(
            ToolInfo(
                name=scanner.name,
                installed=available,
                version=version,
                install_linux=info.get("install_linux", "See documentation"),
                install_macos=info.get("install_macos", "See documentation"),
                description=info.get("description", ""),
            )
        )

    # Check Ollama separately
    ollama_info = TOOL_INSTALL_INFO["ollama"]
    try:
        client = OllamaClient(settings)
        reachable = await client.is_reachable()
        ollama_installed = reachable
        ollama_version = await client.get_version() if reachable else None
    except Exception:
        ollama_installed = False
        ollama_version = None

    results.append(
        ToolInfo(
            name="ollama",
            installed=ollama_installed,
            version=ollama_version,
            install_linux=ollama_info["install_linux"],
            install_macos=ollama_info["install_macos"],
            description=ollama_info["description"],
        )
    )

    return results


@router.get("/status")
async def tool_status() -> Dict[str, Any]:
    """Return tool installation status as a mapping."""
    from app.scanners.registry import ScannerRegistry
    from app.ai.ollama_client import OllamaClient
    from app.config import get_settings

    registry = ScannerRegistry()
    settings = get_settings()

    status_dict: Dict[str, Any] = {}
    for scanner in registry.all_scanners():
        available = scanner.is_available()
        status_dict[scanner.name] = {
            "installed": available,
            "version": scanner.get_version() if available else None,
        }

    try:
        client = OllamaClient(settings)
        reachable = await client.is_reachable()
        version = await client.get_version() if reachable else None
    except Exception:
        reachable = False
        version = None

    status_dict["ollama"] = {
        "installed": reachable,
        "version": version,
    }
    return status_dict


@router.post("/refresh")
async def refresh_tool_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Re-check all tool statuses and update the database."""
    from app.scanners.registry import ScannerRegistry
    from app.database.repository import ToolRepository

    registry = ScannerRegistry()
    tool_repo = ToolRepository(db)
    updated = []

    for scanner in registry.all_scanners():
        available = scanner.is_available()
        version = scanner.get_version() if available else None
        tool_repo.upsert(scanner.name, installed=available, version=version)
        updated.append({"name": scanner.name, "installed": available, "version": version})

    db.commit()
    return {"updated": updated}
