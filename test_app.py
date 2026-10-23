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
    assert "Scanning…" in body
    assert "app.js" in body


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
