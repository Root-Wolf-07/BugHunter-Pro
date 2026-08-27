"""
Bug Hunter AI — ffuf Web Fuzzer Integration
Used only for authorized content/path discovery.
"""
from __future__ import annotations

import json
import logging
import tempfile
import os
from typing import Any, Dict, List, Optional, Tuple

from app.scanners.base import SecurityScanner

logger = logging.getLogger(__name__)

# Safe default wordlist relative paths (user must supply)
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
MACOS_WORDLIST = "/usr/local/share/wordlists/dirb/common.txt"


class FfufScanner(SecurityScanner):
    """ffuf web content/path discovery scanner for authorized targets."""

    name = "ffuf"
    description = "Web fuzzer — authorized content and path discovery"
    category = "web"

    def _version_args(self) -> List[str]:
        return ["ffuf", "-V"]

    def scan(
        self,
        target: str,
        scan_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Any]:
        opts = options or {}

        # Wordlist: user must provide or use default
        wordlist = opts.get("wordlist", DEFAULT_WORDLIST)
        if not os.path.exists(wordlist):
            wordlist = MACOS_WORDLIST
        if not os.path.exists(wordlist):
            logger.warning(
                f"ffuf: wordlist not found at {wordlist}. "
                "Provide a wordlist via scan options."
            )
            return "", []

        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False
        ) as tf:
            output_path = tf.name

        try:
            # Ensure target ends with FUZZ placeholder
            fuzz_url = target.rstrip("/") + "/FUZZ"

            args = [
                "ffuf",
                "-w", wordlist,
                "-u", fuzz_url,
                "-o", output_path,
                "-of", "json",
                "-t", str(opts.get("threads", 20)),
                "-rate", str(opts.get("rate", 100)),
                "-mc", opts.get("match_codes", "200,204,301,302,307,401,403"),
                "-timeout", str(opts.get("timeout", 10)),
                "-s",  # silent
            ]

            logger.info(f"Running ffuf: {' '.join(args)}")
            stdout, stderr, rc = self._run_subprocess(args, timeout=300)

            raw_output = ""
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_output = f.read()

            parsed = self.parse_results(raw_output)
            return raw_output, parsed

        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse ffuf JSON output into normalized finding dicts."""
        findings: List[Dict[str, Any]] = []

        if not raw_output.strip():
            return findings

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.warning("ffuf: could not parse JSON output")
            return findings

        results = data.get("results", [])
        for result in results:
            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)

            severity = _status_severity(status)

            findings.append({
                "title": f"Discovered Path: {result.get('input', {}).get('FUZZ', url)}",
                "category": "information_disclosure",
                "severity": severity,
                "confidence": "CONFIRMED",
                "affected_component": url,
                "description": (
                    f"ffuf discovered an accessible path: {url} "
                    f"(HTTP {status}, {length} bytes)"
                ),
                "evidence": (
                    f"URL: {url}\n"
                    f"Status: {status}\n"
                    f"Response length: {length} bytes\n"
                    f"Words: {words}"
                ),
                "detected_by": "ffuf",
                "raw_finding": result,
            })

        return findings


def _status_severity(status: int) -> str:
    """Map HTTP status code to a base severity for discovered paths."""
    if status in (200, 204):
        return "LOW"
    if status in (401, 403):
        return "INFO"
    if status in (301, 302, 307):
        return "INFO"
    return "INFO"
