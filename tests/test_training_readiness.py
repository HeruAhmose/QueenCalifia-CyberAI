"""Tests for advanced training readiness engine and catalog."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from backend.modules.training.readiness_engine import (
    build_capabilities_catalog,
    collect_route_hits,
    run_readiness_checks,
)


def _fake_rule(path: str):
    m = MagicMock()
    m.rule = path
    return m


def test_capabilities_catalog_nonempty():
    cat = build_capabilities_catalog()
    assert len(cat) >= 6
    ids = {c["id"] for c in cat}
    assert "cyber_chat" in ids
    assert "vulnerability_engine" in ids


def test_collect_route_hits_detects_core_routes():
    app = MagicMock()
    app.url_map.iter_rules.return_value = [
        _fake_rule("/api/chat/"),
        _fake_rule("/api/vulns/scan"),
        _fake_rule("/api/market/sources"),
        _fake_rule("/api/identity/state"),
        _fake_rule("/healthz"),
        _fake_rule("/readyz"),
        _fake_rule("/api/v1/telemetry/summary"),
        _fake_rule("/api/v1/predictor/status"),
        _fake_rule("/api/v1/evolution/status"),
    ]
    hits = collect_route_hits(app)
    assert hits["api_chat"] is True
    assert hits["api_vulns_scan"] is True
    assert hits["healthz"] is True


def test_run_readiness_with_mount_errors_not_ready():
    app = MagicMock()
    app.url_map.iter_rules.return_value = [_fake_rule("/api/chat/")]
    app.config = {"qc_mount_debug": {"errors": ["import failed"]}}
    out = run_readiness_checks(app, Path("data/qc_os.db"))
    assert out["ready_for_advanced_training"] is False
    assert any(c["id"] == "dashboard_blueprints" and not c["ok"] for c in out["checks"])


def test_run_readiness_structure():
    app = MagicMock()
    app.url_map.iter_rules.return_value = [
        _fake_rule("/api/chat/"),
        _fake_rule("/api/vulns/scan"),
        _fake_rule("/api/market/sources"),
        _fake_rule("/api/identity/state"),
        _fake_rule("/healthz"),
        _fake_rule("/readyz"),
        _fake_rule("/api/v1/telemetry/summary"),
        _fake_rule("/api/v1/predictor/status"),
        _fake_rule("/api/v1/evolution/status"),
    ]
    app.config = {"qc_mount_debug": {"errors": []}}
    out = run_readiness_checks(app, Path("data/qc_os.db"))
    assert "checks" in out
    assert "capabilities_catalog" in out
    assert out["schema_version"] == 1
