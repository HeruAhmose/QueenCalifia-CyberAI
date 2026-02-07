from __future__ import annotations

import os

def test_metrics_requires_token_in_production(app_factory):
    os.environ["QC_METRICS_TOKEN"] = "metrics-token"
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

