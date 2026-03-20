from __future__ import annotations

import json
import sys
import types

from api.gateway import APIKeyStore


def _auth_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-QC-API-Key": "test-api-key",
    }


def test_v1_route_requires_auth_when_enabled(app_factory):
    app = app_factory(require_api_key=True)
    client = app.test_client()

    unauthorized = client.get("/api/v1/scanner/status")
    assert unauthorized.status_code == 401

    authorized = client.get("/api/v1/scanner/status", headers=_auth_headers())
    assert authorized.status_code == 200


def test_async_scan_queue_failure_returns_503_without_local_fallback(app_factory, monkeypatch):
    app = app_factory(require_api_key=True)
    client = app.test_client()

    monkeypatch.setenv("QC_USE_CELERY", "1")
    monkeypatch.setenv("QC_ALLOW_LOCAL_SCAN_FALLBACK", "0")

    fake_celery_module = types.SimpleNamespace(
        celery_app=types.SimpleNamespace(
            send_task=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("broker down"))
        )
    )
    monkeypatch.setitem(sys.modules, "celery_app", fake_celery_module)

    rv = client.post(
        "/api/vulns/scan",
        data=json.dumps(
            {
                "target": "127.0.0.1",
                "acknowledge_authorized": True,
            }
        ),
        headers=_auth_headers(),
    )

    body = rv.get_json() or {}
    assert rv.status_code == 503
    assert body.get("error") == "celery_unavailable"


def test_gateway_bootstraps_legacy_env_keys_in_production(tmp_path, monkeypatch):
    monkeypatch.setenv("QC_PRODUCTION", "1")
    monkeypatch.setenv("QC_API_KEY_PEPPER", "pepper-test")
    monkeypatch.setenv("QC_API_KEY", "legacy-api")
    monkeypatch.setenv("QC_ADMIN_KEY", "legacy-admin")
    monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("QC_API_KEYS_FILE", raising=False)

    store = APIKeyStore(str(tmp_path / "keys.json"), pepper="pepper-test")

    api_meta = store.validate("legacy-api")
    admin_meta = store.validate("legacy-admin")

    assert api_meta is not None
    assert admin_meta is not None
    assert "execute" in api_meta["permissions"]
    assert "admin" in admin_meta["permissions"]


def test_preflight_allows_admin_header(app_factory):
    app = app_factory(require_api_key=True)
    client = app.test_client()

    rv = client.open(
        "/api/v1/scanner/status",
        method="OPTIONS",
        headers={
            "Origin": "https://queencalifia-cyberai.web.app",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-QC-API-Key,X-QC-Admin-Key,Content-Type",
        },
    )

    assert rv.status_code in (200, 204)
    allow_headers = rv.headers.get("Access-Control-Allow-Headers", "")
    assert "X-QC-API-Key" in allow_headers
    assert "X-QC-Admin-Key" in allow_headers
