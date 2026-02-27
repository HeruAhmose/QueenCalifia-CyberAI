from __future__ import annotations

import json
import os

import pytest


def test_budget_enforced_with_redis(app_factory, monkeypatch):
    if not os.environ.get("QC_REDIS_URL", "").strip():
        pytest.skip("Redis not configured for this test run")

    monkeypatch.setenv("QC_BUDGET_ENABLED", "1")
    # Very small bucket to force denial: capacity 2 tokens, no refill.
    monkeypatch.setenv(
        "QC_BUDGET_ROLE_BUCKETS_JSON",
        json.dumps({"admin": {"capacity": 2, "refill_per_minute": 0}, "public": {"capacity": 2, "refill_per_minute": 0}}),
    )
    monkeypatch.setenv("QC_BUDGET_ENDPOINT_COSTS_JSON", json.dumps({"GET /api/mesh/status": 1}))

    app = app_factory(require_api_key=True)
    c = app.test_client()
    headers = {"X-QC-API-Key": "test-api-key"}

    assert c.get("/api/mesh/status", headers=headers).status_code == 200
    assert c.get("/api/mesh/status", headers=headers).status_code == 200
    r3 = c.get("/api/mesh/status", headers=headers)
    assert r3.status_code == 429
