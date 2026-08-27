"""
Bug Hunter AI — AI Analysis Engine
Orchestrates scanner output → Ollama → structured findings.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional

from app.ai.ollama_client import OllamaClient
from app.ai.prompts import FINDING_ANALYSIS_TEMPLATE, SECURITY_ANALYST_SYSTEM
from app.config import Settings

logger = logging.getLogger(__name__)


def _extract_field(text: str, field: str) -> Optional[str]:
    """Extract a labeled field value from structured AI output."""
    pattern = rf"^{re.escape(field)}:\s*(.*?)(?=\n[A-Z _]+:|\Z)"
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _parse_analysis_response(response: str) -> Dict[str, Any]:
    """Parse the structured AI analysis response into a dictionary."""
    return {
        "ai_severity": _extract_field(response, "SEVERITY"),
        "ai_confidence": _extract_field(response, "CONFIDENCE"),
        "why_it_matters": _extract_field(response, "WHY IT MATTERS"),
        "evidence_summary": _extract_field(response, "EVIDENCE SUMMARY"),
        "root_cause": _extract_field(response, "POSSIBLE ROOT CAUSE"),
        "remediation": _extract_field(response, "RECOMMENDED FIX"),
        "verification_steps": _extract_field(response, "HOW TO VERIFY"),
        "false_positive_assessment": _extract_field(response, "FALSE POSITIVE ASSESSMENT"),
        "full_analysis": response,
    }


class AIAnalyzer:
    """Enriches normalized findings with AI-powered analysis."""

    def __init__(self, settings: Settings) -> None:
        self.client = OllamaClient(settings)
        self.settings = settings

    async def analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run AI analysis on a single finding dict.
        Returns an enriched copy of the finding.
        """
        enriched = dict(finding)

        # Check Ollama is available
        if not await self.client.is_reachable():
            logger.warning("Ollama not reachable; skipping AI analysis for this finding")
            enriched["ai_analysis"] = (
                "AI analysis skipped: Ollama is not reachable. "
                "Start Ollama and re-run analysis."
            )
            return enriched

        # Build prompt
        prompt = FINDING_ANALYSIS_TEMPLATE.format(
            tool=finding.get("detected_by", "unknown"),
            target=finding.get("target_id", "unknown"),
            title=finding.get("title", "Unknown Finding"),
            category=finding.get("category", "Unknown"),
            component=finding.get("affected_component", "Unknown"),
            evidence=finding.get("evidence", "No evidence provided"),
        )

        messages = [
            {"role": "system", "content": SECURITY_ANALYST_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await self.client.chat(messages, temperature=0.1)
            parsed = _parse_analysis_response(response)

            enriched["ai_analysis"] = parsed.get("full_analysis", response)
            enriched["ai_severity"] = parsed.get("ai_severity") or finding.get("severity")
            enriched["ai_confidence"] = parsed.get("ai_confidence") or finding.get("confidence")

            # Enrich fields if not already set
            if not enriched.get("root_cause") and parsed.get("root_cause"):
                enriched["root_cause"] = parsed["root_cause"]
            if not enriched.get("remediation") and parsed.get("remediation"):
                enriched["remediation"] = parsed["remediation"]

        except Exception as exc:
            logger.error(f"AI analysis failed: {exc}")
            enriched["ai_analysis"] = f"AI analysis failed: {exc}"

        return enriched

    async def health_check(self) -> Dict[str, Any]:
        """Return AI subsystem health."""
        reachable = await self.client.is_reachable()
        model_ok = await self.client.model_exists() if reachable else False
        models = await self.client.list_models() if reachable else []
        return {
            "ollama_reachable": reachable,
            "model_available": model_ok,
            "configured_model": self.settings.ollama_model,
            "available_models": models,
        }
