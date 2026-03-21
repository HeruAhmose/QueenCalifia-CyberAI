"""Tests for background autonomy / safe localhost learning loop."""
from __future__ import annotations

import core.autonomy_loop as autonomy


def test_autonomy_disabled_explicitly(monkeypatch):
    monkeypatch.setenv("QC_AUTONOMY_ENABLED", "0")
    monkeypatch.setenv("QC_PRODUCTION", "1")
    assert autonomy._autonomy_enabled() is False


def test_autonomy_enabled_explicitly(monkeypatch):
    monkeypatch.delenv("QC_PRODUCTION", raising=False)
    monkeypatch.setenv("QC_AUTONOMY_ENABLED", "1")
    assert autonomy._autonomy_enabled() is True


def test_autonomy_enabled_by_production_default(monkeypatch):
    monkeypatch.delenv("QC_AUTONOMY_ENABLED", raising=False)
    monkeypatch.setenv("QC_PRODUCTION", "1")
    assert autonomy._autonomy_enabled() is True


def test_localhost_scan_interval_respects_zero(monkeypatch):
    monkeypatch.setenv("QC_AUTONOMY_LOCALHOST_SCAN_SECONDS", "0")
    monkeypatch.setenv("QC_PRODUCTION", "1")
    assert autonomy._localhost_scan_interval_seconds() == 0


def test_localhost_scan_interval_explicit(monkeypatch):
    monkeypatch.setenv("QC_AUTONOMY_LOCALHOST_SCAN_SECONDS", "120")
    assert autonomy._localhost_scan_interval_seconds() == 120


def test_lease_prevents_concurrent_owners(tmp_path, monkeypatch):
    db_path = tmp_path / "queen.db"
    monkeypatch.setenv("QC_DB_PATH", str(db_path))
    o1 = "owner-a"
    o2 = "owner-b"
    assert autonomy._acquire_lease(db_path, o1, ttl_seconds=300) is True
    assert autonomy._acquire_lease(db_path, o2, ttl_seconds=300) is False
    assert autonomy._acquire_lease(db_path, o1, ttl_seconds=300) is True
