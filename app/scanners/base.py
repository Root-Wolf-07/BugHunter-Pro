"""
Bug Hunter AI — Scanner Base Class
Defines the interface all security scanner plugins must implement.
"""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class SecurityScanner(ABC):
    """Abstract base class for all Bug Hunter security scanner plugins."""

    name: str = "base"
    description: str = ""
    category: str = "general"

    @abstractmethod
    def scan(
        self,
        target: str,
        scan_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Any]:
        """
        Execute the scanner against the given target.

        Args:
            target: The target address (IP, hostname, URL, etc.)
            scan_id: The ID of the parent Scan record (for logging)
            options: Optional scanner-specific settings

        Returns:
            Tuple of (raw_output: str, parsed_data: Any)
        """
        ...

    @abstractmethod
    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse raw scanner output into a list of normalized finding dicts.

        Args:
            raw_output: The raw string output from the scanner

        Returns:
            List of finding dictionaries with keys matching the Finding model
        """
        ...

    def is_available(self) -> bool:
        """Return True if the scanner binary is installed and executable."""
        return shutil.which(self._binary_name()) is not None

    def get_version(self) -> Optional[str]:
        """Return the installed version string, or None on failure."""
        try:
            result = subprocess.run(
                self._version_args(),
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.strip() or result.stderr.strip()
            return output.splitlines()[0] if output else None
        except Exception:
            return None

    def _binary_name(self) -> str:
        """Return the name of the scanner binary (override if different from self.name)."""
        return self.name

    def _version_args(self) -> List[str]:
        """Return the command to get the scanner version."""
        return [self._binary_name(), "--version"]

    def _run_subprocess(
        self,
        args: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
    ) -> Tuple[str, str, int]:
        """
        Safely run an external command using an argument array (no shell injection).

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                # Do NOT use shell=True — prevents shell injection
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Scanner {self.name} timed out after {timeout}s")
        except FileNotFoundError:
            raise RuntimeError(
                f"Scanner binary '{self._binary_name()}' not found. "
                f"Please install {self.name} first."
            )
