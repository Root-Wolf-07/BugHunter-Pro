"""
Bug Hunter AI — Verification Engine
Re-scans after remediation to verify whether a finding is resolved.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.config import Settings
from app.database.models import Finding

logger = logging.getLogger(__name__)


class VerificationEngine:
    """Performs lightweight re-verification scans after remediation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def verify(self, finding: Finding) -> Dict[str, Any]:
        """
        Perform a targeted re-scan for a specific finding.

        Returns:
            Dict with keys: passed, method, notes, evidence
        """
        method = _select_method(finding)
        logger.info(f"Verifying finding {finding.id} using method: {method}")

        if method == "http_header":
            return await self._verify_http_header(finding)
        elif method == "port_check":
            return await self._verify_port(finding)
        else:
            return {
                "passed": False,
                "method": "manual",
                "notes": (
                    "Automated verification is not available for this finding type. "
                    "Please verify manually using the recommended steps in the finding."
                ),
                "evidence": None,
            }

    async def _verify_http_header(self, finding: Finding) -> Dict[str, Any]:
        """Verify that a security header is now present."""
        import httpx

        target = finding.affected_component or ""
        if not target.startswith("http"):
            target = f"http://{target}"

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(target)
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                # Check for common header findings
                missing_headers = _check_security_headers(finding.title, headers_lower)

                if not missing_headers:
                    return {
                        "passed": True,
                        "method": "http_header",
                        "notes": "Security headers verified present",
                        "evidence": str(dict(resp.headers)),
                    }
                return {
                    "passed": False,
                    "method": "http_header",
                    "notes": f"Missing headers: {missing_headers}",
                    "evidence": str(dict(resp.headers)),
                }
        except Exception as exc:
            return {
                "passed": False,
                "method": "http_header",
                "notes": f"Verification request failed: {exc}",
                "evidence": None,
            }

    async def _verify_port(self, finding: Finding) -> Dict[str, Any]:
        """Verify that an exposed port is now closed."""
        import asyncio

        component = finding.affected_component or ""
        # Parse host:port from component
        parts = component.rsplit(":", 1)
        if len(parts) != 2:
            return {
                "passed": False,
                "method": "port_check",
                "notes": "Could not parse host:port from affected component",
                "evidence": None,
            }

        host = parts[0]
        try:
            port = int(parts[1].split("/")[0])
        except ValueError:
            port = 80

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
            writer.close()
            return {
                "passed": False,
                "method": "port_check",
                "notes": f"Port {port} on {host} is still open",
                "evidence": f"Successfully connected to {host}:{port}",
            }
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            return {
                "passed": True,
                "method": "port_check",
                "notes": f"Port {port} on {host} appears closed",
                "evidence": f"Connection to {host}:{port} refused or timed out",
            }


def _select_method(finding: Finding) -> str:
    """Select a verification method based on finding category."""
    category = finding.category.lower() if finding.category else ""
    title = finding.title.lower() if finding.title else ""

    if "header" in title or "header" in category:
        return "http_header"
    if "port" in title or "network_exposure" in category:
        return "port_check"
    return "manual"


def _check_security_headers(title: str, headers: Dict[str, str]) -> list:
    """Return list of expected headers that are missing."""
    title_lower = title.lower()
    missing = []

    checks = {
        "content-security-policy": "content-security-policy",
        "x-frame-options": "x-frame-options",
        "x-content-type-options": "x-content-type-options",
        "strict-transport-security": "strict-transport-security",
        "x-xss-protection": "x-xss-protection",
        "referrer-policy": "referrer-policy",
    }

    for keyword, header_name in checks.items():
        if keyword in title_lower and header_name not in headers:
            missing.append(header_name)

    return missing
