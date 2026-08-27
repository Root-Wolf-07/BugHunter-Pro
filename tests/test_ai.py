"""
Bug Hunter AI — AI Engine & Remediation Unit Tests (Mocked Ollama)
"""
import pytest
from unittest.mock import AsyncMock, patch
from app.config import Settings
from app.ai.analyzer import AIAnalyzer
from app.ai.remediation import RemediationAdvisor
from app.database.models import Finding


@pytest.mark.asyncio
async def test_ai_analyzer_enrichment():
    settings = Settings(ollama_host="http://localhost:11434", ollama_model="llama3")
    analyzer = AIAnalyzer(settings)

    mock_ollama_response = """
SEVERITY: LOW
CONFIDENCE: CONFIRMED

WHY IT MATTERS:
Port 22 is exposed to the local network which allows SSH connections.

EVIDENCE SUMMARY:
Port 22 is open running SSH service.

POSSIBLE ROOT CAUSE:
Default SSH daemon configuration leaves listening on 0.0.0.0.

RECOMMENDED FIX:
Restrict SSH listening interface or configure firewall / key-only auth.

HOW TO VERIFY:
Check sshd_config and test connection with ssh.

FALSE POSITIVE ASSESSMENT:
LOW. Direct port scan confirmed open port.
"""

    with patch("app.ai.ollama_client.OllamaClient.is_reachable", new_callable=AsyncMock) as mock_reach:
        mock_reach.return_value = True
        with patch("app.ai.ollama_client.OllamaClient.chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = mock_ollama_response

            finding_input = {
                "title": "Exposed SSH Port",
                "category": "network_exposure",
                "severity": "LOW",
                "affected_component": "127.0.0.1:22",
                "description": "Port 22 is open",
                "evidence": "22/tcp open ssh",
            }

            enriched = await analyzer.analyze_finding(finding_input)
            assert enriched["ai_analysis"] is not None
            assert "Port 22" in enriched["ai_analysis"]
            assert enriched["root_cause"] is not None
            assert enriched["remediation"] is not None


@pytest.mark.asyncio
async def test_remediation_advisor():
    settings = Settings(ollama_host="http://localhost:11434", ollama_model="llama3")
    advisor = RemediationAdvisor(settings)

    mock_plan_response = """
REMEDIATION_TITLE: Secure SSH Daemon Configuration
DESCRIPTION: Enforce key-based authentication and disable password login.
STEPS:
1. Edit /etc/ssh/sshd_config
2. Set PasswordAuthentication to no
3. Restart ssh service
PATCH_APPLICABLE: YES
PATCH_DIFF:
--- /etc/ssh/sshd_config
+++ /etc/ssh/sshd_config
@@ -50,1 +50,1 @@
-PasswordAuthentication yes
+PasswordAuthentication no
REFERENCES: https://infosec.mozilla.org/guidelines/openssh
"""

    with patch("app.ai.ollama_client.OllamaClient.is_reachable", new_callable=AsyncMock) as mock_reach:
        mock_reach.return_value = True
        with patch("app.ai.ollama_client.OllamaClient.chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = mock_plan_response

            dummy_finding = Finding(
                id="f-123",
                scan_id="s-123",
                target_id="t-123",
                title="Exposed SSH with Password Auth",
                severity="MEDIUM",
                category="network_exposure",
                description="SSH allows password authentication",
                evidence="PasswordAuthentication yes",
                detected_by="nmap",
            )

            plan = await advisor.generate(dummy_finding)

            assert plan["title"] == "Secure SSH Daemon Configuration"
            assert len(plan["steps"]) == 3
            assert plan["action_type"] == "PATCH"
            assert "PasswordAuthentication" in (plan["patch_diff"] or "")
