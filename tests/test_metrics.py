from __future__ import annotations

from pathlib import Path

import pytest

from core.metrics import require_metrics_bearer_token


def test_metrics_requires_token_in_production(app_factory, monkeypatch):
    monkeypatch.setenv("QC_METRICS_TOKEN", "metrics-token")
    app = app_factory(require_api_key=True, production=True)
    c = app.test_client()

    # no bearer -> 401
    r = c.get("/metrics")
    assert r.status_code == 401

    # wrong token -> 401
    r = c.get("/metrics", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401

    # correct -> 200 or 204 if metrics disabled
    r = c.get("/metrics", headers={"Authorization": "Bearer metrics-token"})
    assert r.status_code in (200, 204)


def test_metrics_missing_token_fails_closed_in_production(monkeypatch):
    monkeypatch.delenv("QC_METRICS_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="QC_METRICS_TOKEN is required"):
        require_metrics_bearer_token(production=True)


def test_metrics_token_is_not_required_for_local_development(monkeypatch):
    monkeypatch.delenv("QC_METRICS_TOKEN", raising=False)

    assert require_metrics_bearer_token(production=False) is None


def test_public_helm_ingress_does_not_publish_metrics():
    ingress = Path("helm/queen-califia/templates/ingress.yaml").read_text(encoding="utf-8")

    assert "- path: /metrics" not in ingress
    assert "- path: /api" in ingress
