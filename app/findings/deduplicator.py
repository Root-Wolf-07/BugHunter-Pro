"""
Bug Hunter AI — Finding Deduplicator
Removes duplicate findings based on fingerprints.
"""
from __future__ import annotations

from typing import Any, Dict, List


class Deduplicator:
    """Removes duplicate findings from a list using fingerprint comparison."""

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Return a de-duplicated list of findings.
        When duplicates are found, the one with the higher severity is kept.
        """
        seen: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            fp = finding.get("fingerprint", "")
            if not fp:
                # No fingerprint — keep all
                seen[id(finding)] = finding  # type: ignore[assignment]
                continue

            if fp not in seen:
                seen[fp] = finding
            else:
                # Keep higher severity
                from app.findings.severity import severity_score
                existing_score = severity_score(seen[fp].get("severity", "LOW"))
                new_score = severity_score(finding.get("severity", "LOW"))
                if new_score > existing_score:
                    seen[fp] = finding

        return list(seen.values())
