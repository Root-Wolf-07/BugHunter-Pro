"""
Bug Hunter AI — Nikto Web Server Scanner Integration
"""
from __future__ import annotations

import json
import logging
import tempfile
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from app.scanners.base import SecurityScanner

logger = logging.getLogger(__name__)


class NiktoScanner(SecurityScanner):
    """Nikto web server vulnerability scanner integration."""

    name = "nikto"
    description = "Web server scanner — checks for dangerous files, outdated server software"
    category = "web"

    def _binary_name(self) -> str:
        return "nikto"

    def _version_args(self) -> List[str]:
        return ["nikto", "-Version"]

    def scan(
        self,
        target: str,
        scan_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Any]:
        opts = options or {}

        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as tf:
            output_path = tf.name

        try:
            args = [
                "nikto",
                "-host", target,
                "-output", output_path,
                "-Format", "json",
                "-nointeractive",
            ]

            # Optional: follow SSL
            if target.startswith("https://"):
                args.extend(["-ssl"])

            timeout_val = str(opts.get("timeout", 10))
            args.extend(["-timeout", timeout_val])

            logger.info(f"Running nikto: {' '.join(args)}")
            stdout, stderr, rc = self._run_subprocess(args, timeout=600)

            raw_output = stdout
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_output = f.read()

            parsed = self.parse_results(raw_output)
            return raw_output, parsed

        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse nikto JSON output."""
        findings: List[Dict[str, Any]] = []

        if not raw_output.strip():
            return findings

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            # Try to extract line-by-line
            return self._parse_text_output(raw_output)

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            osvdb = vuln.get("id", "")
            method = vuln.get("method", "GET")
            url = vuln.get("url", "")
            message = vuln.get("msg", "")

            severity = _nikto_severity(message, osvdb)

            findings.append({
                "title": _nikto_title(message),
                "category": "web_server",
                "severity": severity,
                "confidence": "LIKELY",
                "affected_component": url or "web server",
                "description": message,
                "evidence": f"Method: {method}\nURL: {url}\nMessage: {message}",
                "detected_by": "nikto",
                "raw_finding": vuln,
            })

        return findings

    def _parse_text_output(self, raw: str) -> List[Dict[str, Any]]:
        """Fallback: parse nikto plain text output."""
        findings: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("+ "):
                message = line[2:]
                findings.append({
                    "title": _nikto_title(message),
                    "category": "web_server",
                    "severity": _nikto_severity(message, ""),
                    "confidence": "POTENTIAL",
                    "affected_component": "web server",
                    "description": message,
                    "evidence": f"Nikto output line: {message}",
                    "detected_by": "nikto",
                    "raw_finding": {"line": message},
                })
        return findings


def _nikto_title(message: str) -> str:
    """Create a short title from a nikto message."""
    if not message:
        return "Nikto Finding"
    # Take first sentence or up to 80 chars
    short = message.split(".")[0][:80]
    return short if short else message[:80]


def _nikto_severity(message: str, osvdb: str) -> str:
    """Estimate severity from nikto message content."""
    msg_lower = message.lower()
    if any(k in msg_lower for k in ["remote code", "rce", "command injection", "sql injection"]):
        return "CRITICAL"
    if any(k in msg_lower for k in ["directory traversal", "path traversal", "admin", "password",
                                     "default credential", "authentication bypass"]):
        return "HIGH"
    if any(k in msg_lower for k in ["xss", "cross-site", "csrf", "clickjacking",
                                     "missing header", "insecure"]):
        return "MEDIUM"
    if any(k in msg_lower for k in ["server version", "php version", "apache version",
                                     "nginx version", "disclosure"]):
        return "LOW"
    return "INFO"
