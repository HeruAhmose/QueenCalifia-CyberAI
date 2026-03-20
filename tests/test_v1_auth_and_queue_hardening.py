from __future__ import annotations

import json
import sys
import types


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
