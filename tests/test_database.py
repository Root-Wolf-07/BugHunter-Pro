"""
Bug Hunter AI — Database Models & Repositories Unit Tests
"""
from app.database.repository import (
    TargetRepository,
    ScanRepository,
    FindingRepository,
    RemediationRepository,
    ActivityRepository,
)


def test_target_crud(db_session):
    repo = TargetRepository(db_session)

    # Create
    target = repo.create(
        name="Local Host",
        target_type="ip_address",
        value="127.0.0.1",
        authorization_confirmed=True,
    )
    assert target.id is not None
    assert target.name == "Local Host"
    assert target.value == "127.0.0.1"

    # Read
    fetched = repo.get(target.id)
    assert fetched is not None
    assert fetched.value == "127.0.0.1"

    # List
    all_targets = repo.list()
    assert len(all_targets) == 1

    # Update
    updated = repo.update(target.id, name="Updated Localhost")
    assert updated.name == "Updated Localhost"

    # Delete
    deleted = repo.delete(target.id)
    assert deleted is True
    assert repo.get(target.id) is None


def test_scan_and_findings_relationship(db_session):
    target_repo = TargetRepository(db_session)
    scan_repo = ScanRepository(db_session)
    finding_repo = FindingRepository(db_session)

    target = target_repo.create(
        name="Web App",
        target_type="url",
        value="http://127.0.0.1:8080",
        authorization_confirmed=True,
    )

    scan = scan_repo.create(
        target_id=target.id,
        scan_type="full",
        tools_used=["nmap", "nikto"],
        authorization_confirmed=True,
    )
    assert scan.status == "pending"

    finding = finding_repo.create(
        scan_id=scan.id,
        target_id=target.id,
        title="Open Port 8080",
        category="network_exposure",
        severity="LOW",
        confidence="CONFIRMED",
        detected_by="nmap",
        fingerprint="fp_12345",
    )
    assert finding.id is not None
    assert finding.severity == "LOW"

    # Fetch by fingerprint
    fp_match = finding_repo.get_by_fingerprint("fp_12345")
    assert fp_match is not None
    assert fp_match.id == finding.id


def test_activity_logging(db_session):
    repo = ActivityRepository(db_session)
    log_entry = repo.log(
        event_type="TEST_EVENT",
        message="Running automated unit test",
        level="INFO",
        details={"test_key": "test_val"},
    )
    assert log_entry.id is not None
    logs = repo.list(limit=10)
    assert len(logs) == 1
    assert logs[0].event_type == "TEST_EVENT"
