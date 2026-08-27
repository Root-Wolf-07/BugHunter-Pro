"""
Bug Hunter AI — Nuclei Scanner Integration
Nuclei scans using YAML templates for known vulnerability detection.
"""
from __future__ import annotations

import json
import logging
import tempfile
import os
from typing import Any, Dict, List, Optional, Tuple

from app.scanners.base import SecurityScanner

logger = logging.getLogger(__name__)

NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "LOW",
}


class NucleiScanner(SecurityScanner):
    """Nuclei vulnerability scanner integration."""

    name = "nuclei"
    description = "Template-based vulnerability scanner for known CVEs and misconfigurations"
    category = "vulnerability"

    def _version_args(self) -> List[str]:
        return ["nuclei", "-version"]

    def scan(
        self,
        target: str,
        scan_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Any]:
        opts = options or {}

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", mode="w", delete=False
        ) as tf:
            output_path = tf.name

        try:
            args = [
                "nuclei",
                "-target", target,
                "-json-export", output_path,
                "-silent",
                "-no-color",
            ]

            # Template severity filter (default: medium and above)
            severities = opts.get("severities", "critical,high,medium")
            args.extend(["-severity", severities])

            # Rate limiting for safety
            rate_limit = str(opts.get("rate_limit", 25))
            args.extend(["-rate-limit", rate_limit])

            logger.info(f"Running nuclei: {' '.join(args)}")
            stdout, stderr, rc = self._run_subprocess(args, timeout=600)

            # Read JSON Lines output
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
        """Parse nuclei JSONL output into normalized finding dicts."""
        findings: List[Dict[str, Any]] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            template_id = entry.get("template-id", "unknown")
            name = info.get("name", template_id)
            severity_raw = info.get("severity", "unknown").lower()
            severity = NUCLEI_SEVERITY_MAP.get(severity_raw, "LOW")

            matched_at = entry.get("matched-at", entry.get("host", ""))
            description = info.get("description", "")
            reference = info.get("reference", [])
            tags = info.get("tags", [])

            findings.append({
                "title": name,
                "category": _nuclei_category(tags),
                "severity": severity,
                "confidence": "LIKELY",
                "affected_component": matched_at,
                "description": description,
                "evidence": (
                    f"Template: {template_id}\n"
                    f"Matched at: {matched_at}\n"
                    f"Curl command: {entry.get('curl-command', 'N/A')}"
                ),
                "references": reference if isinstance(reference, list) else [reference],
                "detected_by": "nuclei",
                "raw_finding": entry,
            })

        return findings


def _nuclei_category(tags: List[str]) -> str:
    """Map nuclei template tags to a Bug Hunter category."""
    tag_set = {t.lower() for t in tags}
    if "cve" in tag_set:
        return "cve"
    if "misconfiguration" in tag_set or "misconfig" in tag_set:
        return "misconfiguration"
    if "xss" in tag_set:
        return "injection"
    if "sqli" in tag_set:
        return "injection"
    if "rce" in tag_set or "lfi" in tag_set or "rfi" in tag_set:
        return "injection"
    if "exposure" in tag_set:
        return "information_disclosure"
    if "ssl" in tag_set or "tls" in tag_set:
        return "cryptography"
    return "vulnerability"
