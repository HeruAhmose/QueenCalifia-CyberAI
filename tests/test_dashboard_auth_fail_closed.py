from __future__ import annotations

from flask import Flask

from core.auth import require_admin, require_api_key


def _app() -> Flask:
    app = Flask(__name__)

    @app.get("/user")
    @require_api_key
    def user_route():
        return {"ok": True}

    @app.get("/admin")
    @require_admin
    def admin_route():
        return {"ok": True}

    return app


def test_missing_api_key_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("QC_API_KEY", raising=False)
    monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("QC_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("QC_NO_AUTH", raising=False)

    response = _app().test_client().get("/user")

    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}


def test_no_auth_is_honored_only_outside_production(monkeypatch):
    monkeypatch.setenv("QC_NO_AUTH", "1")
    monkeypatch.setenv("QC_PRODUCTION", "0")

    assert _app().test_client().get("/user").status_code == 200

    monkeypatch.setenv("QC_PRODUCTION", "1")
    assert _app().test_client().get("/user").status_code == 401


def test_admin_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("QC_ADMIN_KEY", raising=False)
    monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("QC_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("QC_NO_AUTH", raising=False)

    response = _app().test_client().get("/admin")

    assert response.status_code == 403
    assert response.get_json() == {"error": "admin access not configured"}
