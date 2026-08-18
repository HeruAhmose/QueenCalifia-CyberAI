from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import sqlite3

import pytest

from core.api_key_crypto import API_KEY_HASH_SCHEME, API_KEY_STORE_VERSION
from scripts.disposition_legacy_runtime_state import (
    LIVE_SCANNER_STAGE,
    VULNERABILITY_STAGE,
    dispose_api_keys,
    dispose_audit_log,
    dispose_live_scanner_sqlite,
    dispose_spki,
    dispose_vulnerability_sqlite,
)


def _postgres_url() -> str:
    return os.environ.get("QC_TEST_POSTGRES_URL", "").strip()


def _clean_target(url: str) -> None:
    import psycopg
    from psycopg import sql

    tables = (
        "qc_spki_evidence",
        "qc_request_audit",
        "qc_api_keys",
        "qc_legacy_vuln_scan_jobs",
        "qc_live_findings",
        "qc_live_baselines",
        "qc_live_scans",
    )
    with psycopg.connect(url) as conn:
        for table in tables:
            if conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0]:
                conn.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))


def _reset_stages() -> None:
    VULNERABILITY_STAGE.parent.mkdir(parents=True, exist_ok=True)
    for path in (VULNERABILITY_STAGE, LIVE_SCANNER_STAGE):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _audit_line(
    *,
    previous_hash: str,
    key: str,
    ts: str,
    request_id: str,
    action: str,
    source_ip: str,
    role: str,
    status: int,
    details: dict,
) -> tuple[str, str]:
    entry = {
        "ts": ts,
        "request_id": request_id,
        "action": action,
        "source_ip": source_ip,
        "user_role": role,
        "status_code": status,
        "details": details,
        "previous_hash": previous_hash,
    }
    canonical = json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    record_hash = hashlib.sha256(canonical.encode()).hexdigest()
    signature = hmac.new(
        key.encode(), (record_hash + previous_hash).encode(), hashlib.sha256
    ).hexdigest()
    record = {**entry, "hash": record_hash, "hmac": signature}
    return json.dumps(record, sort_keys=True, separators=(",", ":")), record_hash


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_file_artifacts_are_verified_and_targets_refuse_merge(monkeypatch):
    url = _postgres_url()
    _clean_target(url)
    try:
        keys = {
            "version": API_KEY_STORE_VERSION,
            "hash_scheme": API_KEY_HASH_SCHEME,
            "keys": [
                {
                    "key_hash": "a" * 64,
                    "role": "admin",
                    "permissions": ["read", "admin"],
                    "rate_limit": 240,
                    "created_at": "2026-08-17T00:00:00Z",
                    "description": "historical key",
                    "revoked": False,
                }
            ],
        }
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(keys)))
        result = dispose_api_keys(url)
        assert result["target"]["rows"] == 1

        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(keys)))
        with pytest.raises(RuntimeError, match="not empty"):
            dispose_api_keys(url)

        _clean_target(url)
        audit_key = "historical-audit-key"
        monkeypatch.setenv("QC_AUDIT_HMAC_KEY", audit_key)
        first, first_hash = _audit_line(
            previous_hash="0" * 64,
            key=audit_key,
            ts="2026-08-17T00:00:00Z",
            request_id="req-1",
            action="first",
            source_ip="127.0.0.1",
            role="admin",
            status=200,
            details={"order": 1},
        )
        second, _ = _audit_line(
            previous_hash=first_hash,
            key=audit_key,
            ts="2026-08-17T00:01:00Z",
            request_id="req-2",
            action="second",
            source_ip="127.0.0.2",
            role="analyst",
            status=202,
            details={"order": 2},
        )
        monkeypatch.setattr("sys.stdin", io.StringIO(first + "\n" + second + "\n"))
        audit_result = dispose_audit_log(url)
        assert audit_result["target"]["rows"] == 2

        _clean_target(url)
        spki_lines = "\n".join(
            [
                json.dumps(
                    {
                        "event_type": "qc.redis.spki_pin_bootstrap",
                        "timestamp": "2026-08-17T00:00:00Z",
                        "sha256": "b" * 64,
                    }
                ),
                json.dumps(
                    {
                        "event_type": "qc.redis.spki_pin_verified",
                        "timestamp": "2026-08-17T00:01:00Z",
                        "sha256": "b" * 64,
                    }
                ),
            ]
        ) + "\n"
        monkeypatch.setattr("sys.stdin", io.StringIO(spki_lines))
        spki_result = dispose_spki(url)
        assert spki_result["target"]["rows"] == 2
    finally:
        _clean_target(url)


@pytest.mark.skipif(not _postgres_url(), reason="QC_TEST_POSTGRES_URL not configured")
def test_scanner_sqlite_disposition_preserves_state():
    url = _postgres_url()
    _clean_target(url)
    _reset_stages()
    try:
        with sqlite3.connect(VULNERABILITY_STAGE) as conn:
            conn.execute(
                """
                CREATE TABLE qc_vuln_scan_jobs (
                    scan_id TEXT PRIMARY KEY,target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,status TEXT NOT NULL,
                    created_at TEXT,started_at TEXT,completed_at TEXT,
                    error TEXT,result_json TEXT
                )
                """
            )
            conn.execute(
                "INSERT INTO qc_vuln_scan_jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "legacy-vuln-1",
                    "127.0.0.1",
                    "quick",
                    "completed",
                    "2026-08-17T00:00:00Z",
                    "2026-08-17T00:00:01Z",
                    "2026-08-17T00:00:02Z",
                    None,
                    '{"findings":[]}',
                ),
            )

        vulnerability = dispose_vulnerability_sqlite(url)
        assert vulnerability["target"]["rows"] == 1
        assert len(vulnerability["source_sha256"]) == 64

        with sqlite3.connect(LIVE_SCANNER_STAGE) as conn:
            conn.executescript(
                """
                CREATE TABLE scans (
                    scan_id TEXT PRIMARY KEY,target TEXT,scan_type TEXT,
                    start_time TEXT,end_time TEXT,total_hosts INTEGER,
                    total_findings INTEGER,critical INTEGER,high INTEGER,
                    risk_score REAL,report_json TEXT
                );
                CREATE TABLE baselines (
                    host_ip TEXT PRIMARY KEY,open_ports TEXT,services TEXT,
                    os_guess TEXT,first_seen TEXT,last_seen TEXT,
                    scan_count INTEGER DEFAULT 1
                );
                CREATE TABLE findings_log (
                    finding_id TEXT PRIMARY KEY,scan_id TEXT,host_ip TEXT,
                    title TEXT,severity TEXT,cve_id TEXT,cvss_score REAL,
                    status TEXT DEFAULT 'open',remediated_at TEXT,created_at TEXT
                );
                """
            )
            conn.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "legacy-live-1", "127.0.0.1", "quick",
                    "2026-08-17T00:00:00Z", "2026-08-17T00:01:00Z",
                    1, 1, 0, 1, 8.0, '{"scan_id":"legacy-live-1"}',
                ),
            )
            conn.execute(
                "INSERT INTO baselines VALUES (?,?,?,?,?,?,?)",
                (
                    "127.0.0.1", "[443]", '{"443":"https"}', "linux",
                    "2026-08-17T00:00:00Z", "2026-08-17T00:01:00Z", 3,
                ),
            )
            conn.execute(
                "INSERT INTO findings_log VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    "legacy-finding-1", "legacy-live-1", "127.0.0.1",
                    "Legacy finding", "HIGH", "CVE-TEST-1", 8.0, "open",
                    None, "2026-08-17T00:00:30Z",
                ),
            )

        live = dispose_live_scanner_sqlite(url)
        assert live["target"]["qc_live_scans"]["rows"] == 1
        assert live["target"]["qc_live_baselines"]["rows"] == 1
        assert live["target"]["qc_live_findings"]["rows"] == 1

        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(url, row_factory=dict_row) as conn:
            archived = conn.execute(
                "SELECT scan_id,status FROM qc_legacy_vuln_scan_jobs"
            ).fetchone()
            live_row = conn.execute(
                "SELECT scan_id,report_json FROM qc_live_scans"
            ).fetchone()
        assert archived["scan_id"] == "legacy-vuln-1"
        assert archived["status"] == "completed"
        assert live_row["scan_id"] == "legacy-live-1"
    finally:
        _clean_target(url)
        _reset_stages()
