"""
Bug Hunter AI — Scanner Registry
Discovers and manages all registered security scanner plugins.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from app.scanners.base import SecurityScanner
from app.scanners.ffuf_scanner import FfufScanner
from app.scanners.nikto_scanner import NiktoScanner
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.nuclei_scanner import NucleiScanner


class ScannerRegistry:
    """Central registry for all available security scanner plugins."""

    def __init__(self) -> None:
        self._scanners: Dict[str, SecurityScanner] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register all built-in scanners."""
        for scanner in [
            NmapScanner(),
            NucleiScanner(),
            NiktoScanner(),
            FfufScanner(),
        ]:
            self._scanners[scanner.name] = scanner

    def register(self, scanner: SecurityScanner) -> None:
        """Register a custom scanner plugin."""
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> Optional[SecurityScanner]:
        """Return a scanner by name, or None."""
        return self._scanners.get(name)

    def all_scanners(self) -> List[SecurityScanner]:
        """Return all registered scanners."""
        return list(self._scanners.values())

    def available_scanners(self) -> List[SecurityScanner]:
        """Return only scanners whose binaries are installed."""
        return [s for s in self._scanners.values() if s.is_available()]

    def tool_status_summary(self) -> Dict[str, bool]:
        """Return a dict of {name: installed} for all registered scanners."""
        return {s.name: s.is_available() for s in self._scanners.values()}
