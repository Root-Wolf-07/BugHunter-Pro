"""
Bug Hunter AI — AI-Powered Remediation Advisor
Generates human-readable remediation plans. Never auto-applies.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.ai.ollama_client import OllamaClient
from app.ai.prompts import REMEDIATION_TEMPLATE, SECURITY_ANALYST_SYSTEM
from app.config import Settings
from app.database.models import Finding

logger = logging.getLogger(__name__)


def _parse_remediation_response(response: str) -> Dict[str, Any]:
    """Parse structured remediation response from the LLM."""
    clean_text = "\n".join(line.strip() for line in response.splitlines())

    def extract(field: str) -> Optional[str]:
        pattern = rf"^{re.escape(field)}:\s*(.*?)(?=\n[A-Z_]+:|\Z)"
        match = re.search(pattern, clean_text, re.MULTILINE | re.DOTALL)
        return match.group(1).strip() if match else None

    title = extract("REMEDIATION_TITLE") or "Remediation Plan"
    description = extract("DESCRIPTION")

    # Parse numbered steps
    steps_text = extract("STEPS") or ""
    steps: List[str] = []
    for line in steps_text.splitlines():
        line = line.strip()
        if line and re.match(r"^\d+\.", line):
            steps.append(re.sub(r"^\d+\.\s*", "", line))

    patch_applicable_raw = extract("PATCH_APPLICABLE") or "NO"
    patch_applicable = patch_applicable_raw.upper().startswith("YES")

    patch_diff = extract("PATCH_DIFF") if patch_applicable else None
    if patch_diff and patch_diff.upper() == "NONE":
        patch_diff = None

    references_raw = extract("REFERENCES") or ""
    references = [r.strip() for r in references_raw.split(",") if r.strip()]

    return {
        "action_type": "PATCH" if patch_diff else "RECOMMENDATION",
        "title": title,
        "description": description,
        "steps": steps,
        "patch_diff": patch_diff,
        "references": references,
    }


class RemediationAdvisor:
    """Generates AI-powered remediation recommendations for security findings."""

    def __init__(self, settings: Settings) -> None:
        self.client = OllamaClient(settings)
        self.settings = settings

    async def generate(self, finding: Finding) -> Dict[str, Any]:
        """
        Generate a remediation plan for a Finding ORM object.
        Returns a dict suitable for creating a RemediationAction.
        """
        if not await self.client.is_reachable():
            logger.warning("Ollama not reachable; returning generic remediation")
            return {
                "action_type": "RECOMMENDATION",
                "title": "Review and remediate manually",
                "description": (
                    "AI analysis is unavailable (Ollama not reachable). "
                    "Please review this finding manually and apply appropriate remediation."
                ),
                "steps": [
                    "Review the finding evidence",
                    "Apply industry-standard remediation for this vulnerability category",
                    "Verify the fix with a re-scan",
                ],
            }

        prompt = REMEDIATION_TEMPLATE.format(
            title=finding.title,
            severity=finding.severity,
            category=finding.category,
            description=finding.description or "",
            evidence=finding.evidence or "",
        )

        messages = [
            {"role": "system", "content": SECURITY_ANALYST_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self.client.chat(messages, temperature=0.05)
            return _parse_remediation_response(response)
        except Exception as exc:
            logger.error(f"Remediation generation failed: {exc}")
            return {
                "action_type": "RECOMMENDATION",
                "title": "Remediation (AI unavailable)",
                "description": f"AI remediation failed: {exc}. Please remediate manually.",
                "steps": [],
            }
