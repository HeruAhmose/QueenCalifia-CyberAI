#!/usr/bin/env python3
"""Preserve legacy scanner and file-backed state before PostgreSQL cutover.

This tool is deliberately narrow and fail-closed:

stdin modes (no caller-controlled path):
  api-keys   < keys.json
  audit-log  < audit.log.jsonl
  spki       < spki.jsonl

SQLite modes use fixed staging paths only. An operator must copy production
sources into these exact paths before execution:
  vulnerability  -> /tmp/qc-vulnerability-legacy.db
  live-scanner   -> /tmp/qc-live-scanner-legacy.db

All targets must be empty. Source SQLite is read-only. Every mode verifies row
counts and deterministic SHA-256 content digests before committing. This script
does not delete source state, change deployment configuration, or authorize HA.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.api_key_crypto import API_KEY_HASH_SCHEME, API_KEY_STORE_VERSION  # noqa: E402

VULNERABILITY_STAGE = Path("/tmp/qc-vulnerability-legacy.db")
LIVE_SCANNER_STAGE = Path("/tmp/qc-live-scanner-legacy.db")
ZERO_HASH = "0" * 64


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest_rows(rows: Iterable[Sequence[Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(_canonical(list(row)).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _connect_pg(url: str):
    if not url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("database URL must use postgresql:// or postgres://")
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("psycopg is required; install backend/requirements.txt") from exc
    return psycopg.connect(url, row_factory=dict_row)


def _database_url() -> str:
    url = (os.getenv("QC_DATABASE_URL") or os.getenv("DATABASE_URL") or "").strip()
    if not url:
        raise RuntimeError("QC_DATABASE_URL/DATABASE_URL is required")
    return url


def _connect_sqlite_readonly(path: Path) -> sqlite3.Connection:
    if path not in {VULNERABILITY_STAGE, LIVE_SCANNER_STAGE}:
        raise RuntimeError("legacy SQLite source path is not an approved staging path")
    if not path.is_file():
        raise RuntimeError(f"staged legacy SQLite source does not exist: {path}")
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _source_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows if not str(row[0]).startswith("sqlite_")}


def _require_empty_pg(target, table: str) -> None:
    from psycopg import sql

    count = int(
        target.execute(
            sql.SQL("SELECT COUNT(*) AS n FROM {}").format(sql.Identifier(table))
        ).fetchone()["n"]
    )
    if count:
        raise RuntimeError(f"target table {table} is not empty ({count} rows); refusing authority merge")


def _pg_rows(target, table: str, columns: Sequence[str], keys: Sequence[str]) -> list[tuple[Any, ...]]:
    from psycopg import sql

    query = sql.SQL("SELECT {} FROM {} ORDER BY {}").format(
        sql.SQL(", ").join(sql.Identifier(c) for c in columns),
        sql.Identifier(table),
        sql.SQL(", ").join(sql.Identifier(k) for k in keys),
    )
    rows = target.execute(query).fetchall()
    return [tuple(row[c] for c in columns) for row in rows]


def _verify(target, table: str, columns: Sequence[str], keys: Sequence[str], expected: Sequence[Sequence[Any]]) -> dict[str, Any]:
    actual = _pg_rows(target, table, columns, keys)
    expected_digest = _digest_rows(expected)
    actual_digest = _digest_rows(actual)
    if len(actual) != len(expected):
        raise RuntimeError(f"verification failed for {table}: source={len(expected)} target={len(actual)}")
    if actual_digest != expected_digest:
        raise RuntimeError(
            f"verification failed for {table}: source_sha256={expected_digest} target_sha256={actual_digest}"
        )
    return {"rows": len(actual), "sha256": actual_digest}


def _reset_sequence(target, table: str, column: str) -> None:
    from psycopg import sql

    row = target.execute("SELECT pg_get_serial_sequence(%s, %s) AS seq", (table, column)).fetchone()
    sequence = row["seq"] if row else None
    if not sequence:
        return
    maximum = int(
        target.execute(
            sql.SQL("SELECT COALESCE(MAX({}), 0) AS n FROM {}").format(
                sql.Identifier(column), sql.Identifier(table)
            )
        ).fetchone()["n"]
    )
    if maximum:
        target.execute("SELECT setval(%s::regclass, %s, true)", (sequence, maximum))
    else:
        target.execute("SELECT setval(%s::regclass, 1, false)", (sequence,))


def _read_stdin_text() -> tuple[str, str]:
    raw = sys.stdin.read()
    if not raw.strip():
        raise RuntimeError("stdin is empty; refusing empty disposition")
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dispose_api_keys(url: str) -> dict[str, Any]:
    raw, source_digest = _read_stdin_text()
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("version") != API_KEY_STORE_VERSION or data.get("hash_scheme") != API_KEY_HASH_SCHEME:
        raise RuntimeError(f"API-key JSON must use {API_KEY_HASH_SCHEME} version {API_KEY_STORE_VERSION}")
    keys = data.get("keys")
    if not isinstance(keys, list):
        raise RuntimeError("API-key JSON must contain a keys list")

    columns = (
        "key_hash", "role", "permissions_json", "rate_limit", "created_at",
        "description", "budget_capacity", "budget_refill_per_minute", "revoked",
    )
    rows: list[tuple[Any, ...]] = []
    seen: set[str] = set()
    for item in keys:
        if not isinstance(item, dict) or not item.get("key_hash"):
            raise RuntimeError("API-key entry missing key_hash")
        key_hash = str(item["key_hash"])
        if key_hash in seen:
            raise RuntimeError(f"duplicate API-key fingerprint: {key_hash}")
        seen.add(key_hash)
        permissions = list(item.get("permissions", ["read"]))
        rows.append(
            (
                key_hash,
                str(item.get("role", "reader")),
                json.dumps(permissions),
                int(item.get("rate_limit", 60)),
                str(item.get("created_at") or _utcnow()),
                str(item.get("description", "")),
                item.get("budget_capacity"),
                item.get("budget_refill_per_minute"),
                1 if bool(item.get("revoked", False)) else 0,
            )
        )
    rows.sort(key=lambda row: row[0])

    target = _connect_pg(url)
    try:
        with target.transaction():
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_api_keys (
                    key_hash TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    permissions_json TEXT NOT NULL,
                    rate_limit INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    budget_capacity INTEGER,
                    budget_refill_per_minute INTEGER,
                    revoked INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            _require_empty_pg(target, "qc_api_keys")
            if rows:
                target.executemany(
                    """
                    INSERT INTO qc_api_keys (
                        key_hash, role, permissions_json, rate_limit, created_at,
                        description, budget_capacity, budget_refill_per_minute, revoked
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    rows,
                )
            verified = _verify(target, "qc_api_keys", columns, ("key_hash",), rows)
        return {"kind": "api-keys", "source_sha256": source_digest, "target": verified}
    finally:
        target.close()


def _validate_audit_records(raw: str, hmac_key: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    previous = ZERO_HASH
    key = hmac_key.encode("utf-8")
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise RuntimeError(f"audit line {line_number} is not an object")
        entry = {k: v for k, v in record.items() if k not in {"hash", "hmac"}}
        expected_hash = hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()
        expected_hmac = hmac.new(
            key, (expected_hash + previous).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if record.get("previous_hash") != previous:
            raise RuntimeError(f"audit chain predecessor mismatch at line {line_number}")
        if record.get("hash") != expected_hash:
            raise RuntimeError(f"audit hash mismatch at line {line_number}")
        if record.get("hmac") != expected_hmac:
            raise RuntimeError(f"audit HMAC mismatch at line {line_number}")
        previous = expected_hash
        records.append(record)
    if not records:
        raise RuntimeError("audit log has no records")
    return records


def dispose_audit_log(url: str) -> dict[str, Any]:
    raw, source_digest = _read_stdin_text()
    hmac_key = (os.getenv("QC_AUDIT_HMAC_KEY") or "").strip()
    if not hmac_key:
        raise RuntimeError("QC_AUDIT_HMAC_KEY is required to validate historical audit evidence")
    records = _validate_audit_records(raw, hmac_key)
    columns = (
        "sequence", "ts", "request_id", "action", "source_ip", "user_role",
        "status_code", "details_json", "previous_hash", "record_hash", "record_hmac",
    )
    rows = [
        (
            index,
            record.get("ts"),
            record.get("request_id"),
            record.get("action"),
            record.get("source_ip"),
            record.get("user_role"),
            int(record.get("status_code", 0)),
            json.dumps(record.get("details") or {}, sort_keys=True),
            record.get("previous_hash"),
            record.get("hash"),
            record.get("hmac"),
        )
        for index, record in enumerate(records, start=1)
    ]

    target = _connect_pg(url)
    try:
        with target.transaction():
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_request_audit (
                    sequence BIGSERIAL PRIMARY KEY,
                    ts TEXT NOT NULL,
                    request_id TEXT,
                    action TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    record_hmac TEXT NOT NULL
                )
                """
            )
            _require_empty_pg(target, "qc_request_audit")
            target.executemany(
                """
                INSERT INTO qc_request_audit (
                    sequence, ts, request_id, action, source_ip, user_role,
                    status_code, details_json, previous_hash, record_hash, record_hmac
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                rows,
            )
            _reset_sequence(target, "qc_request_audit", "sequence")
            verified = _verify(target, "qc_request_audit", columns, ("sequence",), rows)
        return {"kind": "audit-log", "source_sha256": source_digest, "target": verified}
    finally:
        target.close()


def dispose_spki(url: str) -> dict[str, Any]:
    raw, source_digest = _read_stdin_text()
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise RuntimeError(f"SPKI line {line_number} is not an object")
        event_type = str(record.get("event_type") or "")
        if not event_type.startswith("qc.redis.spki_pin"):
            raise RuntimeError(f"SPKI line {line_number} has unsupported event_type {event_type!r}")
        records.append(record)
    if not records:
        raise RuntimeError("SPKI evidence has no records")

    rows: list[tuple[Any, ...]] = []
    seen: set[str] = set()
    for index, record in enumerate(records, start=1):
        canonical = _canonical(record)
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if event_hash in seen:
            continue
        seen.add(event_hash)
        rows.append(
            (
                index,
                str(record.get("event_type")),
                canonical,
                event_hash,
                str(record.get("timestamp") or _utcnow()),
            )
        )

    columns = ("sequence", "event_type", "event_json", "event_hash", "recorded_at")
    target = _connect_pg(url)
    try:
        with target.transaction():
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_spki_evidence (
                    sequence BIGSERIAL PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    recorded_at TEXT NOT NULL
                )
                """
            )
            _require_empty_pg(target, "qc_spki_evidence")
            target.executemany(
                """
                INSERT INTO qc_spki_evidence (
                    sequence, event_type, event_json, event_hash, recorded_at
                ) VALUES (%s,%s,%s,%s,%s)
                """,
                rows,
            )
            _reset_sequence(target, "qc_spki_evidence", "sequence")
            verified = _verify(target, "qc_spki_evidence", columns, ("sequence",), rows)
        return {"kind": "spki", "source_sha256": source_digest, "target": verified}
    finally:
        target.close()


def dispose_vulnerability_sqlite(url: str, source_path: Path = VULNERABILITY_STAGE) -> dict[str, Any]:
    source = _connect_sqlite_readonly(source_path)
    target = _connect_pg(url)
    columns = (
        "scan_id", "target", "scan_type", "status", "created_at", "started_at",
        "completed_at", "error", "result_json",
    )
    try:
        tables = _source_tables(source)
        if "qc_vuln_scan_jobs" not in tables:
            raise RuntimeError("staged vulnerability SQLite has no qc_vuln_scan_jobs table")
        rows = [
            tuple(row[column] for column in columns)
            for row in source.execute(
                "SELECT scan_id, target, scan_type, status, created_at, started_at, completed_at, error, result_json "
                "FROM qc_vuln_scan_jobs ORDER BY scan_id"
            ).fetchall()
        ]
        with target.transaction():
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_legacy_vuln_scan_jobs (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    result_json TEXT
                )
                """
            )
            _require_empty_pg(target, "qc_legacy_vuln_scan_jobs")
            if rows:
                target.executemany(
                    """
                    INSERT INTO qc_legacy_vuln_scan_jobs (
                        scan_id, target, scan_type, status, created_at, started_at,
                        completed_at, error, result_json
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    rows,
                )
            verified = _verify(
                target, "qc_legacy_vuln_scan_jobs", columns, ("scan_id",), rows
            )
        return {
            "kind": "vulnerability",
            "source_path": str(source_path),
            "source_sha256": _sha256_file(source_path),
            "target": verified,
        }
    finally:
        source.close()
        target.close()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dispose_live_scanner_sqlite(url: str, source_path: Path = LIVE_SCANNER_STAGE) -> dict[str, Any]:
    source = _connect_sqlite_readonly(source_path)
    target = _connect_pg(url)
    expected_tables = {"scans", "baselines", "findings_log"}
    try:
        tables = _source_tables(source)
        missing = sorted(expected_tables - tables)
        if missing:
            raise RuntimeError("staged live-scanner SQLite missing tables: " + ", ".join(missing))

        specs = {
            "scans": (
                "qc_live_scans",
                ("scan_id", "target", "scan_type", "start_time", "end_time", "total_hosts", "total_findings", "critical", "high", "risk_score", "report_json"),
                ("scan_id",),
            ),
            "baselines": (
                "qc_live_baselines",
                ("host_ip", "open_ports", "services", "os_guess", "first_seen", "last_seen", "scan_count"),
                ("host_ip",),
            ),
            "findings_log": (
                "qc_live_findings",
                ("finding_id", "scan_id", "host_ip", "title", "severity", "cve_id", "cvss_score", "status", "remediated_at", "created_at"),
                ("finding_id",),
            ),
        }
        source_rows: dict[str, list[tuple[Any, ...]]] = {}
        for source_table, (_, columns, keys) in specs.items():
            order = ", ".join(keys)
            selected = ", ".join(columns)
            source_rows[source_table] = [
                tuple(row[column] for column in columns)
                for row in source.execute(
                    f"SELECT {selected} FROM {source_table} ORDER BY {order}"
                ).fetchall()
            ]

        with target.transaction():
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_live_scans (
                    scan_id TEXT PRIMARY KEY, target TEXT, scan_type TEXT,
                    start_time TEXT, end_time TEXT, total_hosts INTEGER,
                    total_findings INTEGER, critical INTEGER, high INTEGER,
                    risk_score DOUBLE PRECISION, report_json TEXT NOT NULL
                )
                """
            )
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_live_baselines (
                    host_ip TEXT PRIMARY KEY, open_ports TEXT NOT NULL,
                    services TEXT NOT NULL, os_guess TEXT, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, scan_count INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            target.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_live_findings (
                    finding_id TEXT PRIMARY KEY, scan_id TEXT, host_ip TEXT,
                    title TEXT, severity TEXT, cve_id TEXT,
                    cvss_score DOUBLE PRECISION, status TEXT NOT NULL DEFAULT 'open',
                    remediated_at TEXT, created_at TEXT
                )
                """
            )

            for _, (target_table, _, _) in specs.items():
                _require_empty_pg(target, target_table)

            target.executemany(
                """
                INSERT INTO qc_live_scans (
                    scan_id,target,scan_type,start_time,end_time,total_hosts,
                    total_findings,critical,high,risk_score,report_json
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                source_rows["scans"],
            )
            target.executemany(
                """
                INSERT INTO qc_live_baselines (
                    host_ip,open_ports,services,os_guess,first_seen,last_seen,scan_count
                ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                source_rows["baselines"],
            )
            target.executemany(
                """
                INSERT INTO qc_live_findings (
                    finding_id,scan_id,host_ip,title,severity,cve_id,cvss_score,
                    status,remediated_at,created_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                source_rows["findings_log"],
            )

            verified: dict[str, Any] = {}
            for source_table, (target_table, columns, keys) in specs.items():
                verified[target_table] = _verify(
                    target, target_table, columns, keys, source_rows[source_table]
                )

        return {
            "kind": "live-scanner",
            "source_path": str(source_path),
            "source_sha256": _sha256_file(source_path),
            "target": verified,
        }
    finally:
        source.close()
        target.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "kind",
        choices=("api-keys", "audit-log", "spki", "vulnerability", "live-scanner"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    url = _database_url()
    if args.kind == "api-keys":
        result = dispose_api_keys(url)
    elif args.kind == "audit-log":
        result = dispose_audit_log(url)
    elif args.kind == "spki":
        result = dispose_spki(url)
    elif args.kind == "vulnerability":
        result = dispose_vulnerability_sqlite(url)
    else:
        result = dispose_live_scanner_sqlite(url)
    print(json.dumps({"verified": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
