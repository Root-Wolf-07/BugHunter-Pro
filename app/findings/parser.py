"""
Bug Hunter AI — Finding Parser
Normalizes raw scanner output into consistent Finding dicts.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from app.findings.severity import normalize_severity


class FindingParser:
    """Normalizes scanner output into Bug Hunter Finding format."""

    REQUIRED_FIELDS = {
        "title",
        "category",
        "severity",
        "confidence",
        "detected_by",
    }

    def parse(
        self,
        tool_name: str,
        parsed_data: Any,
        target_id: str,
        scan_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Convert raw parsed scanner data into a list of normalized finding dicts.

        Args:
            tool_name: Name of the scanner that produced the data
            parsed_data: The parsed output from the scanner (list of dicts)
            target_id: ID of the target being scanned
            scan_id: ID of the current scan

        Returns:
            List of normalized finding dicts ready for DB insertion
        """
        if not parsed_data or not isinstance(parsed_data, list):
            return []

        findings: List[Dict[str, Any]] = []

        for raw in parsed_data:
            if not isinstance(raw, dict):
                continue

            # Normalize mandatory fields
            normalized = {
                "scan_id": scan_id,
                "target_id": target_id,
                "title": str(raw.get("title", "Unnamed Finding")),
                "category": str(raw.get("category", "unknown")),
                "severity": normalize_severity(raw.get("severity", "LOW")),
                "confidence": _normalize_confidence(raw.get("confidence", "POTENTIAL")),
                "affected_component": raw.get("affected_component"),
                "description": raw.get("description"),
                "evidence": raw.get("evidence"),
                "potential_impact": raw.get("potential_impact"),
                "root_cause": raw.get("root_cause"),
                "remediation": raw.get("remediation"),
                "references": raw.get("references") or [],
                "detected_by": tool_name,
                "raw_finding": raw.get("raw_finding", raw),
                "status": "NEW",
            }

            # Generate deduplication fingerprint
            normalized["fingerprint"] = _fingerprint(normalized)
            findings.append(normalized)

        return findings


def _normalize_confidence(raw: str) -> str:
    mapping = {
        "confirmed": "CONFIRMED",
        "likely": "LIKELY",
        "potential": "POTENTIAL",
        "informational": "INFORMATIONAL",
        "info": "INFORMATIONAL",
    }
    return mapping.get(str(raw).lower(), "POTENTIAL")


def _fingerprint(finding: Dict[str, Any]) -> str:
    """Generate a short deduplication fingerprint for a finding."""
    key = "|".join([
        finding.get("target_id", ""),
        finding.get("category", ""),
        finding.get("title", ""),
        finding.get("affected_component", "") or "",
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:32]
