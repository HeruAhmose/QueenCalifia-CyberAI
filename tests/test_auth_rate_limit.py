from __future__ import annotations

import json


def test_health_is_public_even_when_auth_required(app_factory):
    app = app_factory(require_api_key=True)
    c = app.test_client()
    r = c.get("/api/health")
    assert r.status_code == 200


def test_auth_required_for_protected_endpoints(app_factory):
    app = app_factory(require_api_key=True)
    c = app.test_client()
    r = c.get("/api/mesh/status")
    assert r.status_code == 401


def test_auth_valid_allows_access(app_factory):
    app = app_factory(require_api_key=True)
    c = app.test_client()
    r = c.get("/api/mesh/status", headers={"X-QC-API-Key": "test-api-key"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] is True


def test_request_id_echo(app_factory):
    app = app_factory(require_api_key=True)
    c = app.test_client()
    rid = "req-123"
    r = c.get("/api/mesh/status", headers={"X-QC-API-Key": "test-api-key", "X-Request-ID": rid})
    assert r.headers.get("X-Request-Id") == rid


def test_global_rate_limit_enforced(app_factory, monkeypatch):
    # Force role to a tiny global budget
    monkeypatch.setenv("QC_ROLE_RATE_LIMITS_JSON", json.dumps({"admin": 2, "public": 30}))
    app = app_factory(require_api_key=True)
    c = app.test_client()
    headers = {"X-QC-API-Key": "test-api-key"}

    assert c.get("/api/mesh/status", headers=headers).status_code == 200
    assert c.get("/api/mesh/status", headers=headers).status_code == 200
    r3 = c.get("/api/mesh/status", headers=headers)
    assert r3.status_code == 429


def test_endpoint_rate_limit_enforced(app_factory, monkeypatch):
    # Big global, tight endpoint ceiling
    monkeypatch.setenv("QC_ROLE_RATE_LIMITS_JSON", json.dumps({"admin": 240, "public": 30}))
    monkeypatch.setenv("QC_RATE_LIMIT_ENDPOINTS_JSON", json.dumps({"GET /api/mesh/status": 1}))

    app = app_factory(require_api_key=True)
    c = app.test_client()
    headers = {"X-QC-API-Key": "test-api-key"}

    assert c.get("/api/mesh/status", headers=headers).status_code == 200
    r2 = c.get("/api/mesh/status", headers=headers)
    assert r2.status_code == 429
