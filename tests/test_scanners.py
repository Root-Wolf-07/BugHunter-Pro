"""
Bug Hunter AI — Scanner, Parser & Deduplicator Unit Tests
"""
from app.scanners.registry import ScannerRegistry
from app.findings.parser import FindingParser
from app.findings.severity import normalize_severity, severity_score
from app.findings.deduplicator import Deduplicator


def test_scanner_registry():
    registry = ScannerRegistry()
    scanners = registry.all_scanners()
    names = [s.name for s in scanners]
    assert "nmap" in names
    assert "nuclei" in names
    assert "nikto" in names
    assert "ffuf" in names

    assert registry.get("nmap") is not None
    assert registry.get("nonexistent") is None


def test_severity_normalization():
    assert normalize_severity("CRITICAL") == "CRITICAL"
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity("high") == "HIGH"
    assert normalize_severity("medium") == "MEDIUM"
    assert normalize_severity("low") == "LOW"
    assert normalize_severity("informational") == "INFO"
    assert normalize_severity("info") == "INFO"
    assert normalize_severity("unknown_severity") == "LOW"

    assert severity_score("CRITICAL") > severity_score("HIGH")
    assert severity_score("HIGH") > severity_score("MEDIUM")
    assert severity_score("MEDIUM") > severity_score("LOW")
    assert severity_score("LOW") > severity_score("INFO")


def test_finding_parser_and_deduplication():
    parser = FindingParser()
    dedup = Deduplicator()

    mock_parsed_data = [
        {
            "title": "Open Port 22/tcp (ssh)",
            "category": "network_exposure",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "affected_component": "127.0.0.1:22",
            "description": "Port 22 is open running OpenSSH 8.9",
        },
        {
            "title": "Open Port 22/tcp (ssh)",
            "category": "network_exposure",
            "severity": "MEDIUM",
            "confidence": "CONFIRMED",
            "affected_component": "127.0.0.1:22",
            "description": "Port 22 open with older ssh protocol version",
        },
        {
            "title": "Open Port 80/tcp (http)",
            "category": "network_exposure",
            "severity": "INFO",
            "confidence": "CONFIRMED",
            "affected_component": "127.0.0.1:80",
            "description": "Port 80 is open running Apache",
        },
    ]

    findings = parser.parse("nmap", mock_parsed_data, "target-123", "scan-456")
    assert len(findings) == 3
    assert all("fingerprint" in f for f in findings)

    # Deduplicate: should merge the two port 22 findings and keep the higher severity (MEDIUM)
    deduped = dedup.deduplicate(findings)
    assert len(deduped) == 2

    port_22_finding = next(f for f in deduped if "22" in f["title"])
    assert port_22_finding["severity"] == "MEDIUM"
