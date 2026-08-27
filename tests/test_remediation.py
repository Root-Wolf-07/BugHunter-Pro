"""
Bug Hunter AI — Remediation & Patch Safety Tests
"""
import os
import tempfile
import pytest
from unittest.mock import MagicMock
from app.config import Settings
from app.database.models import RemediationAction, Finding
from app.remediation.patch_generator import PatchApplicator
from app.remediation.verifier import VerificationEngine, _check_security_headers


def test_check_security_headers():
    headers_missing = {
        "server": "nginx",
        "content-type": "text/html",
    }
    missing = _check_security_headers("Missing Content-Security-Policy Header", headers_missing)
    assert "content-security-policy" in missing

    headers_present = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
    }
    missing_after = _check_security_headers("Missing Content-Security-Policy Header", headers_present)
    assert len(missing_after) == 0


def test_patch_applicator_backup_and_validation():
    applicator = PatchApplicator()

    # 1. Validation error when missing target file
    action_invalid = RemediationAction(
        id="act-1",
        finding_id="f-1",
        action_type="patch",
        title="Test Patch",
        patch_diff="some diff",
        target_file=None,
    )
    with pytest.raises(ValueError):
        applicator.apply(action_invalid)

    # 2. Validation error when target file does not exist
    action_nonexistent = RemediationAction(
        id="act-2",
        finding_id="f-1",
        action_type="patch",
        title="Test Patch",
        patch_diff="some diff",
        target_file="/nonexistent/path/to/file.conf",
    )
    with pytest.raises(RuntimeError):
        applicator.apply(action_nonexistent)


@pytest.mark.asyncio
async def test_verification_engine_manual_fallback():
    settings = Settings()
    verifier = VerificationEngine(settings)

    finding = Finding(
        id="f-generic",
        scan_id="s-1",
        target_id="t-1",
        title="Generic Vulnerability",
        category="generic_cve",
        severity="MEDIUM",
        confidence="LIKELY",
        detected_by="nuclei",
    )

    result = await verifier.verify(finding)
    assert result["method"] == "manual"
    assert "manual" in result["notes"].lower()
