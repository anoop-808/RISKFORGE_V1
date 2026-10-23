from unittest.mock import Mock

import app as app_module


def _scan_result(**overrides):
    result = {
        "target": "192.168.56.103",
        "scan_time": "2026-10-23T10:00:00+00:00",
        "ports": [{
            "host": "192.168.56.103", "port": 80, "protocol": "tcp",
            "service": "http", "product": "Apache", "version": "2.2.8",
            "state": "open",
        }],
        "findings": [{
            "cve_id": "CVE-2026-0001", "description": "Example finding",
            "cvss": 9.8, "severity": "CRITICAL", "risk_level": "CRITICAL",
            "risk_score": 9.8, "risk_rank": 1, "host": "192.168.56.103",
            "port": 80, "protocol": "tcp", "service": "http",
            "product": "Apache", "version": "2.2.8", "applicability": "MATCH",
            "applicability_evidence": {"matched_cpe_product": "http_server"},
        }],
        "indeterminate": [],
        "lookup_errors": [],
        "candidate_count": 1,
    }
    result.update(overrides)
    return result


def test_index_has_target_form_and_loading_behavior():
    response = app_module.app.test_client().get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'name="target_ip"' in body
    assert "Ready for scan" in body
    assert "Scanning…" in body
    assert "Start a focused" in body
    assert "Service discovery" in body
    assert "app.js" in body
    assert "Local network interfaces" in body
    assert 'id="refresh-discovery"' in body


def test_dashboard_destinations_render_real_pages():
    client = app_module.app.test_client()
    assert client.get("/discovery").status_code == 200
    assert "Authorized discovery" in client.get("/discovery").get_data(as_text=True)
    assert client.get("/findings").status_code == 200
    assert client.get("/history").status_code == 200


def test_results_route_renders_real_sections_and_saves_result(monkeypatch):
    result = _scan_result()
    save = Mock()
    monkeypatch.setattr(app_module, "run_vantage", lambda target: result)
    monkeypatch.setattr(app_module, "save_scan_results", save)

    response = app_module.app.test_client().post("/scan", data={"target_ip": result["target"]})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "CVE-2026-0001" in body
    assert "Confirmed CVE findings" in body
    assert "1 critical" in body
    assert "Apache" in body
    save.assert_called_once_with(result)


def test_results_keep_indeterminate_and_lookup_errors_separate(monkeypatch):
    result = _scan_result(
        findings=[],
        indeterminate=[{
            "cve_id": "CVE-2026-0002", "product": "Apache", "version": "2.2.8",
            "description": "Needs platform evidence",
            "applicability_evidence": {"reason": "platform_condition_not_evaluable"},
        }],
        lookup_errors=[{
            "host": "192.168.56.103", "port": 443, "service": "https",
            "error": "NVD unavailable",
        }],
    )
    monkeypatch.setattr(app_module, "run_vantage", lambda target: result)
    monkeypatch.setattr(app_module, "save_scan_results", Mock())

    body = app_module.app.test_client().post(
        "/scan", data={"target_ip": result["target"]}
    ).get_data(as_text=True)

    assert "Confirmed CVE findings" in body
    assert "CVE-2026-0002" in body
    assert "INDETERMINATE" in body
    assert "Lookup errors" in body
    assert "NVD unavailable" in body


def test_empty_scan_renders_empty_states(monkeypatch):
    result = _scan_result(ports=[], findings=[], indeterminate=[], lookup_errors=[])
    monkeypatch.setattr(app_module, "run_vantage", lambda target: result)
    monkeypatch.setattr(app_module, "save_scan_results", Mock())

    body = app_module.app.test_client().post(
        "/scan", data={"target_ip": result["target"]}
    ).get_data(as_text=True)

    assert "No open services found" in body
    assert "No confirmed findings" in body
    assert "No indeterminate candidates" in body


def test_failed_scan_is_not_rendered_as_success(monkeypatch):
    save = Mock()
    monkeypatch.setattr(app_module, "run_vantage", Mock(side_effect=RuntimeError("scanner unavailable")))
    monkeypatch.setattr(app_module, "save_scan_results", save)

    response = app_module.app.test_client().post(
        "/scan", data={"target_ip": "192.168.56.103"}
    )

    assert response.status_code == 400
    assert "scanner unavailable" in response.get_data(as_text=True)
    save.assert_not_called()


def _discovery():
    candidate = {
        "interface": "wlan0", "operational_state": "UP", "local_address": "192.168.1.23",
        "ipv4_cidr": "192.168.1.0/24", "gateway": "192.168.1.1", "eligible": True, "issues": [],
    }
    return {"version": 1, "discovered_at": "now", "interfaces": [{
        "name": "wlan0", "ipv4_addresses": [{"address": "192.168.1.23"}],
    }], "candidates": [candidate], "issues": []}


def test_discovery_endpoint_is_read_only(monkeypatch):
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value=_discovery()))
    nmap = Mock()
    monkeypatch.setattr(app_module, "run_vantage", nmap)
    response = app_module.app.test_client().get("/api/network/discovery")
    assert response.status_code == 200
    assert response.json["discovery"]["candidates"][0]["ipv4_cidr"] == "192.168.1.0/24"
    nmap.assert_not_called()


def test_discovery_failure_keeps_api_available_and_does_not_write_history(monkeypatch):
    monkeypatch.setattr(app_module, "discover_network", Mock(side_effect=app_module.DiscoveryError("ip unavailable")))
    nmap = Mock()
    save = Mock()
    monkeypatch.setattr(app_module, "run_vantage", nmap)
    monkeypatch.setattr(app_module, "save_scan_results", save)
    response = app_module.app.test_client().get("/api/network/discovery")
    assert response.status_code == 200
    assert response.json == {"ok": False, "error": "ip unavailable", "discovery": None}
    nmap.assert_not_called()
    save.assert_not_called()


def test_scope_preview_excludes_local_address_and_confirms_staleness(monkeypatch):
    discovery = _discovery()
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value=discovery))
    client = app_module.app.test_client()
    response = client.post("/scan/scope/preview", json={
        "interface": "wlan0", "local_address": "192.168.1.23", "ipv4_cidr": "192.168.1.0/24",
    })
    assert response.status_code == 200
    assert response.json["scope"]["host_count"] == 253
    assert response.json["scope"]["excluded_addresses"] == ["192.168.1.23"]
    token = response.json["scope_token"]
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value={**discovery, "candidates": []}))
    stale = client.post("/scan/scope/preview", json={"scope_token": token, "confirm": True})
    assert stale.status_code == 409


def test_host_discovery_requires_confirmation_and_never_runs_vantage(monkeypatch):
    discovery = _discovery()
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value=discovery))
    hosts = Mock(return_value={
        "network": "192.168.1.0/24", "discovered_at": "now", "hosts": ["192.168.1.104"],
        "local_addresses": ["192.168.1.23"], "warning": "A nonresponsive device is not confirmed offline.",
    })
    monkeypatch.setattr(app_module, "discover_hosts", hosts)
    vantage = Mock()
    save = Mock()
    monkeypatch.setattr(app_module, "run_vantage", vantage)
    monkeypatch.setattr(app_module, "save_scan_results", save)
    client = app_module.app.test_client()

    preview = client.post("/scan/scope/preview", json={
        "interface": "wlan0", "local_address": "192.168.1.23", "ipv4_cidr": "192.168.1.0/24",
    })
    unconfirmed = client.post("/scan/hosts/discover", json={"confirmation_token": preview.json["scope_token"]})
    assert unconfirmed.status_code == 400
    hosts.assert_not_called()

    confirmed = client.post("/scan/scope/preview", json={
        "scope_token": preview.json["scope_token"], "confirm": True,
    })
    assert confirmed.status_code == 200
    assert confirmed.json["confirmation_token"]
    discovered = client.post("/scan/hosts/discover", json={
        "confirmation_token": confirmed.json["confirmation_token"],
    })
    assert discovered.status_code == 200
    assert discovered.json["result"]["hosts"] == ["192.168.1.104"]
    hosts.assert_called_once_with("192.168.1.0/24", ["192.168.1.23"])
    vantage.assert_not_called()
    save.assert_not_called()


def test_host_discovery_rejects_forged_and_stale_confirmation(monkeypatch):
    discovery = _discovery()
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value=discovery))
    hosts = Mock()
    monkeypatch.setattr(app_module, "discover_hosts", hosts)
    client = app_module.app.test_client()
    assert client.post("/scan/hosts/discover", json={"confirmation_token": "forged"}).status_code == 400

    preview = client.post("/scan/scope/preview", json={
        "interface": "wlan0", "local_address": "192.168.1.23", "ipv4_cidr": "192.168.1.0/24",
    })
    confirmed = client.post("/scan/scope/preview", json={"scope_token": preview.json["scope_token"], "confirm": True})
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value={**discovery, "candidates": []}))
    stale = client.post("/scan/hosts/discover", json={"confirmation_token": confirmed.json["confirmation_token"]})
    assert stale.status_code == 409
    hosts.assert_not_called()


def test_scope_preview_rejects_oversized_network(monkeypatch):
    monkeypatch.setattr(app_module, "discover_network", Mock(return_value=_discovery()))
    response = app_module.app.test_client().post("/scan/scope/preview", json={
        "interface": "wlan0", "local_address": "192.168.1.23", "ipv4_cidr": "192.168.0.0/16",
    })
    assert response.status_code == 400
    assert "/24" in response.json["error"]
