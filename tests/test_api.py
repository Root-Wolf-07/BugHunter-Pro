"""
Bug Hunter AI — API Endpoints Integration Tests
"""


def test_health_endpoints(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "version" in data

    res2 = client.get("/api/dashboard")
    assert res2.status_code == 200
    d_data = res2.json()
    assert "targets" in d_data
    assert "scans" in d_data
    assert "findings" in d_data


def test_target_creation_and_authorization_gate(client):
    # Missing authorization should fail
    fail_res = client.post(
        "/api/targets/",
        json={
            "name": "Unauthorized Target",
            "target_type": "ip_address",
            "value": "192.168.1.50",
            "authorization_confirmed": False,
        },
    )
    assert fail_res.status_code == 400
    assert "Authorization confirmation is required" in fail_res.json()["detail"]

    # Authorized target creation succeeds
    ok_res = client.post(
        "/api/targets/",
        json={
            "name": "Authorized Lab Target",
            "target_type": "ip_address",
            "value": "127.0.0.1",
            "authorization_confirmed": True,
        },
    )
    assert ok_res.status_code == 201
    target = ok_res.json()
    assert target["name"] == "Authorized Lab Target"
    target_id = target["id"]

    # List targets
    list_res = client.get("/api/targets/")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1


def test_scan_creation_and_validation(client):
    # 1. Create target
    t_res = client.post(
        "/api/targets/",
        json={
            "name": "Scan Target",
            "target_type": "hostname",
            "value": "localhost",
            "authorization_confirmed": True,
        },
    )
    target_id = t_res.json()["id"]

    # 2. Try scan without auth confirmation -> 400
    fail_scan = client.post(
        "/api/scans/",
        json={
            "target_id": target_id,
            "tools": ["nmap"],
            "authorization_confirmed": False,
        },
    )
    assert fail_scan.status_code == 400

    # 3. Create authorized scan -> 201
    ok_scan = client.post(
        "/api/scans/",
        json={
            "target_id": target_id,
            "tools": ["nmap"],
            "authorization_confirmed": True,
        },
    )
    assert ok_scan.status_code == 201
    scan_id = ok_scan.json()["id"]

    # 4. List scans
    scans_list = client.get("/api/scans/")
    assert scans_list.status_code == 200
    assert any(s["id"] == scan_id for s in scans_list.json())


def test_tools_status_endpoint(client):
    res = client.get("/api/tools/")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    names = [t["name"] for t in data]
    assert "nmap" in names
    assert "nuclei" in names

    res_status = client.get("/api/tools/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert "nmap" in status_data
    assert "nuclei" in status_data


def test_activity_log_endpoint(client):
    res = client.get("/api/activity/")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
