from __future__ import annotations

import os
from pathlib import Path

import pytest

from engines.externalized_scanners import (
    CeleryVulnerabilityEngine,
    PostgresLiveScanner,
    build_live_scanner,
    build_vulnerability_engine,
)
from engines.live_scanner import Finding, HostResult, ScanReport, ServiceInfo


def _postgres_url() -> str:
    return os.environ.get("QC_TEST_POSTGRES_URL", "").strip()


def _clean_live_tables(url: str) -> None:
    import psycopg

    with psycopg.connect(url) as conn:
        for table in ("qc_live_findings", "qc_live_baselines", "qc_live_scans"):
            if conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0]:
                conn.execute(f'DELETE FROM "{table}"')


def test_celery_vulnerability_engine_never_initializes_sqlite(monkeypatch, tmp_path: Path):
    requested = tmp_path / "must-not-exist.db"
    monkeypatch.setenv("QC_USE_CELERY", "1")
    monkeypatch.setenv("QC_PRODUCTION", "1")
    monkeypatch.delenv("QC_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    engine = build_vulnerability_engine(
        {
            "db_path": str(requested),
            "target_allowlist": "127.0.0.0/8",
            "deny_public_targets": True,
        }
    )

    assert isinstance(engine, CeleryVulnerabilityEngine)
    assert not requested.exists()
    assert engine.probe_health()["metrics"]["job_store_backend"] == "celery-redis"
    with pytest.raises(RuntimeError, match="Celery/Redis"):
        engine.submit_scan("127.0.0.1", "quick")
    assert not requested.exists()


def test_production_vulnerability_engine_refuses_non_celery(monkeypatch):
    monkeypatch.setenv("QC_PRODUCTION", "1")
    monkeypatch.setenv("QC_USE_CELERY", "0")
    with pytest.raises(RuntimeError, match="requires QC_USE_CELERY=1"):
        build_vulnerability_engine({})


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_postgres_live_scanner_state_is_shared_across_instances(monkeypatch):
    url = _postgres_url()
    _clean_live_tables(url)
    monkeypatch.setenv("QC_DATABASE_URL", url)
    monkeypatch.setenv("QC_PRODUCTION", "1")
    try:
        first = build_live_scanner(
            {
                "scan_allowlist": "127.0.0.0/8",
                "deny_public": True,
                "max_threads": 1,
            }
        )
        second = build_live_scanner(
            {
                "scan_allowlist": "127.0.0.0/8",
                "deny_public": True,
                "max_threads": 1,
            }
        )
        assert isinstance(first, PostgresLiveScanner)
        assert isinstance(second, PostgresLiveScanner)

        finding = Finding(
            finding_id="QC-MIGRATION-LIVE",
            title="Shared state test",
            severity="HIGH",
            cvss_score=8.0,
            cve_id="CVE-TEST-0001",
            affected_asset="127.0.0.1",
            created_at="2026-08-17T00:00:00+00:00" if False else None,
        )
        # Finding.timestamp is the persisted timestamp field; assign an explicit
        # deterministic value without relying on wall-clock time.
        finding.timestamp = "2026-08-17T00:00:00+00:00"
        host = HostResult(
            ip="127.0.0.1",
            open_ports=[443],
            services={443: ServiceInfo(port=443, service="https")},
            findings=[finding],
            risk_score=8.0,
        )
        report = ScanReport(
            scan_id="live-shared-1",
            target="127.0.0.1",
            scan_type="quick",
            start_time="2026-08-17T00:00:00+00:00",
            end_time="2026-08-17T00:01:00+00:00",
            hosts=[host],
            total_hosts_scanned=1,
            total_hosts_alive=1,
            total_open_ports=1,
            total_findings=1,
            high_findings=1,
            overall_risk=8.0,
        )

        first._persist_scan(report)
        first._update_baselines(report)

        fetched = second.get_scan("live-shared-1")
        assert fetched is not None
        assert fetched["scan_id"] == "live-shared-1"
        findings = second.get_all_findings(severity="HIGH")
        assert [item["finding_id"] for item in findings] == ["QC-MIGRATION-LIVE"]
        baselines = second.get_baselines()
        assert baselines[0]["host_ip"] == "127.0.0.1"
        assert baselines[0]["open_ports"] == [443]
        assert second.mark_remediated("QC-MIGRATION-LIVE") is True
        assert second.get_all_findings(severity="HIGH", status="open") == []
        status = second.get_status()
        assert status["storage_backend"] == "postgresql"
        assert status["scans_completed"] == 1
    finally:
        _clean_live_tables(url)
