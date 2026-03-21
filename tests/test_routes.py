from __future__ import annotations

from api.gateway import SecurityConfig, create_security_api
from engines.auto_remediation import AutoRemediation

from conftest import DummyIR, DummyMesh, DummyVuln, _make_keys_json


def test_routes_registered(app_factory):
    app = app_factory(require_api_key=False)
    rules = {r.rule for r in app.url_map.iter_rules()}

    expected = {
        "/api/health",
        "/api/ready",
        "/healthz",
        "/readyz",
        "/api/mesh/status",
        "/api/threats/active",
        "/api/events/ingest",
        "/api/iocs",
        "/api/iocs/bulk",
        "/api/vulns/scan",
        "/api/vulns/scan/<scan_id>",
        "/api/vulns/status",
        "/api/vulns/remediation",
        "/api/vulns/webapp",
        "/api/incidents",
        "/api/incidents/<incident_id>",
        "/api/incidents/<incident_id>/approve/<action_id>",
        "/api/incidents/<incident_id>/deny/<action_id>",
        "/api/incidents/<incident_id>/rollback/<action_id>",
        "/api/ir/status",
        "/api/infra/spki-log",
        "/api/dashboard",
    }

    missing = expected - rules
    assert not missing, f"Missing route(s): {sorted(missing)}"


def test_remediation_route_prefers_latest_auto_remediation_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("QC_PRODUCTION", "0")
    monkeypatch.setenv("QC_LOG_FORMAT", "plain")
    monkeypatch.setenv("QC_API_KEY_PEPPER", "pepper-test")
    monkeypatch.setenv("QC_AUDIT_HMAC_KEY", "hmac-test")
    monkeypatch.setenv("QC_API_KEYS_JSON", _make_keys_json("test-api-key", "pepper-test"))

    remediator = AutoRemediation({"db_path": str(tmp_path / "queen.db"), "allow_execute": True})
    plan = remediator.generate_plan(
        [
            {
                "finding_id": "F-1",
                "title": "Missing Security Header: HSTS",
                "severity": "HIGH",
                "category": "web_security",
                "affected_component": "HTTPS",
                "remediation": "Add Strict-Transport-Security header",
            }
        ],
        target_host="127.0.0.1",
    )

    app = create_security_api(
        DummyMesh(),
        DummyVuln(),
        DummyIR(),
        remediator=remediator,
        config=SecurityConfig(require_api_key=True, rate_limit_requests_per_minute=120),
    )
    app.testing = True
    client = app.test_client()

    rv = client.get(
        "/api/vulns/remediation",
        headers={"Content-Type": "application/json", "X-QC-API-Key": "test-api-key"},
    )

    assert rv.status_code == 200
    payload = rv.get_json() or {}
    data = payload.get("data") or {}
    assert data.get("plan_id") == plan.plan_id
    assert data.get("total_actions", 0) >= 1
    assert len(data.get("actions", [])) >= 1


def test_remediation_route_prefers_nonempty_plan_over_newer_empty_plan(tmp_path, monkeypatch):
    """Regression: newest-by-timestamp empty plan must not hide an older plan that has actions."""
    monkeypatch.setenv("QC_PRODUCTION", "0")
    monkeypatch.setenv("QC_LOG_FORMAT", "plain")
    monkeypatch.setenv("QC_API_KEY_PEPPER", "pepper-test")
    monkeypatch.setenv("QC_AUDIT_HMAC_KEY", "hmac-test")
    monkeypatch.setenv("QC_API_KEYS_JSON", _make_keys_json("test-api-key", "pepper-test"))

    remediator = AutoRemediation({"db_path": str(tmp_path / "queen2.db"), "allow_execute": True})
    good = remediator.generate_plan(
        [
            {
                "finding_id": "F-1",
                "title": "Missing Security Header: HSTS",
                "severity": "HIGH",
                "category": "web_security",
                "affected_component": "HTTPS",
                "remediation": "Add Strict-Transport-Security header",
            }
        ],
        target_host="127.0.0.1",
    )
    remediator.generate_plan([], target_host="127.0.0.1")

    app = create_security_api(
        DummyMesh(),
        DummyVuln(),
        DummyIR(),
        remediator=remediator,
        config=SecurityConfig(require_api_key=True, rate_limit_requests_per_minute=120),
    )
    app.testing = True
    client = app.test_client()

    rv = client.get(
        "/api/vulns/remediation",
        headers={"Content-Type": "application/json", "X-QC-API-Key": "test-api-key"},
    )
    assert rv.status_code == 200
    data = (rv.get_json() or {}).get("data") or {}
    assert data.get("plan_id") == good.plan_id
    assert data.get("total_actions", 0) >= 1
    assert len(data.get("actions", [])) >= 1
