#!/usr/bin/env python3
"""Preserve legacy scanner and file-backed state before PostgreSQL cutover.

stdin modes (no caller-controlled path):
  api-keys   < keys.json
  audit-log  < audit.log.jsonl
  spki       < spki.jsonl

SQLite modes use repository-local, git-ignored staging only:
  vulnerability -> .cutover-staging/qc-vulnerability-legacy.db
  live-scanner  -> .cutover-staging/qc-live-scanner-legacy.db

Every SQLite source is a non-symlink regular file opened read-only. Every
PostgreSQL target must be empty. Every copy is verified by row count and
SHA-256 before commit. This script never deletes a source, changes deployment
configuration, or authorizes HA/read-only-rootfs.
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

STAGING_ROOT = ROOT / ".cutover-staging"
VULNERABILITY_STAGE = STAGING_ROOT / "qc-vulnerability-legacy.db"
LIVE_SCANNER_STAGE = STAGING_ROOT / "qc-live-scanner-legacy.db"
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


def _approved_stage(path: Path) -> Path:
    if path not in {VULNERABILITY_STAGE, LIVE_SCANNER_STAGE}:
        raise RuntimeError("legacy SQLite source is not an approved staging file")
    if path.is_symlink():
        raise RuntimeError(f"refusing symlinked staged SQLite source: {path}")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"staged legacy SQLite source does not exist: {path}") from exc
    if resolved.parent != STAGING_ROOT.resolve():
        raise RuntimeError("staged SQLite source escaped the repository cutover directory")
    if not resolved.is_file():
        raise RuntimeError(f"staged legacy SQLite source is not a regular file: {path}")
    return resolved


def _connect_sqlite_readonly(path: Path) -> sqlite3.Connection:
    resolved = _approved_stage(path)
    conn = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _source_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows if not str(row[0]).startswith("sqlite_")}


def _executemany(target, statement: str, rows: Sequence[Sequence[Any]]) -> None:
    if not rows:
        return
    with target.cursor() as cursor:
        cursor.executemany(statement, rows)


def _require_empty_pg(target, table: str) -> None:
    from psycopg import sql

    count = int(
        target.execute(
            sql.SQL("SELECT COUNT(*) AS n FROM {}").format(sql.Identifier(table))
        ).fetchone()["n"]
    )
    if count:
        raise RuntimeError(
            f"target table {table} is not empty ({count} rows); refusing authority merge"
        )


def _pg_rows(
    target, table: str, columns: Sequence[str], keys: Sequence[str]
) -> list[tuple[Any, ...]]:
    from psycopg import sql

    query = sql.SQL("SELECT {} FROM {} ORDER BY {}").format(
        sql.SQL(", ").join(sql.Identifier(column) for column in columns),
        sql.Identifier(table),
        sql.SQL(", ").join(sql.Identifier(key) for key in keys),
    )
    rows = target.execute(query).fetchall()
    return [tuple(row[column] for column in columns) for row in rows]


def _verify(
    target,
    table: str,
    columns: Sequence[str],
    keys: Sequence[str],
    expected: Sequence[Sequence[Any]],
) -> dict[str, Any]:
    actual = _pg_rows(target, table, columns, keys)
    expected_digest = _digest_rows(expected)
    actual_digest = _digest_rows(actual)
    if len(actual) != len(expected):
        raise RuntimeError(
            f"verification failed for {table}: source={len(expected)} target={len(actual)}"
        )
    if actual_digest != expected_digest:
        raise RuntimeError(
            f"verification failed for {table}: "
            f"source_sha256={expected_digest} target_sha256={actual_digest}"
        )
    return {"rows": len(actual), "sha256": actual_digest}


def _reset_sequence(target, table: str, column: str) -> None:
    from psycopg import sql

    row = target.execute(
        "SELECT pg_get_serial_sequence(%s, %s) AS seq", (table, column)
    ).fetchone()
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


def _sha256_stage(path: Path) -> str:
    resolved = _approved_stage(path)
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dispose_api_keys(url: str) -> dict[str, Any]:
    raw, source_digest = _read_stdin_text()
    data = json.loads(raw)
    if (
        not isinstance(data, dict)
        or data.get("version") != API_KEY_STORE_VERSION
        or data.get("hash_scheme") != API_KEY_HASH_SCHEME
    ):
        raise RuntimeError(
            f"API-key JSON must use {API_KEY_HASH_SCHEME} version {API_KEY_STORE_VERSION}"
        )
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
        rows.append(
            (
                key_hash,
                str(item.get("role", "reader")),
                json.dumps(list(item.get("permissions", ["read"]))),
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
            _executemany(
                target,
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
    secret = hmac_key.encode("utf-8")
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise RuntimeError(f"audit line {line_number} is not an object")
        entry = {
            key: value for key, value in record.items() if key not in {"hash", "hmac"}
        }
        expected_hash = hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()
        expected_hmac = hmac.new(
            secret, (expected_hash + previous).encode("utf-8"), hashlib.sha256
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
        raise RuntimeError(
            "QC_AUDIT_HMAC_KEY is required to validate historical audit evidence"
        )
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
            _executemany(
                target,
                """
                INSERT INTO qc_request_audit (
                    sequence, ts, request_id, action, source_ip, user_role,
                    status_code, details_json, previous_hash, record_hash, record_hmac
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                rows,
            )
            _reset_sequence(target, "qc_request_audit", "sequence")
            verified = _verify(
                target, "qc_request_audit", columns, ("sequence",), rows
            )
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
            raise RuntimeError(
                f"SPKI line {line_number} has unsupported event_type {event_type!r}"
            )
        records.append(record)
    if not records:
        raise RuntimeError("SPKI evidence has no records")

    rows: list[tuple[Any, ...]] = []
    seen: set[str] = set()
    sequence = 0
    for record in records:
        canonical = _canonical(record)
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if event_hash in seen:
            continue
        seen.add(event_hash)
        sequence += 1
        rows.append(
            (
                sequence,
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
            _executemany(
                target,
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


def dispose_vulnerability_sqlite(url: str) -> dict[str, Any]:
    source = _connect_sqlite_readonly(VULNERABILITY_STAGE)
    target = _connect_pg(url)
    columns = (
        "scan_id", "target", "scan_type", "status", "created_at", "started_at",
        "completed_at", "error", "result_json",
    )
    try:
        if "qc_vuln_scan_jobs" not in _source_tables(source):
            raise RuntimeError(
                "staged vulnerability SQLite has no qc_vuln_scan_jobs table"
            )
        rows = [
            tuple(row[column] for column in columns)
            for row in source.execute(
                "SELECT scan_id, target, scan_type, status, created_at, started_at, "
                "completed_at, error, result_json FROM qc_vuln_scan_jobs ORDER BY scan_id"
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
            _executemany(
                target,
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
            "source_path": str(VULNERABILITY_STAGE.relative_to(ROOT)),
            "source_sha256": _sha256_stage(VULNERABILITY_STAGE),
            "target": verified,
        }
    finally:
        source.close()
        target.close()


def dispose_live_scanner_sqlite(url: str) -> dict[str, Any]:
    source = _connect_sqlite_readonly(LIVE_SCANNER_STAGE)
    target = _connect_pg(url)
    try:
        missing = sorted(
            {"scans", "baselines", "findings_log"} - _source_tables(source)
        )
        if missing:
            raise RuntimeError(
                "staged live-scanner SQLite missing tables: " + ", ".join(missing)
            )

        scans_columns = (
            "scan_id", "target", "scan_type", "start_time", "end_time",
            "total_hosts", "total_findings", "critical", "high", "risk_score",
            "report_json",
        )
        baseline_columns = (
            "host_ip", "open_ports", "services", "os_guess", "first_seen",
            "last_seen", "scan_count",
        )
        finding_columns = (
            "finding_id", "scan_id", "host_ip", "title", "severity", "cve_id",
            "cvss_score", "status", "remediated_at", "created_at",
        )
        scans = [
            tuple(row[column] for column in scans_columns)
            for row in source.execute(
                "SELECT scan_id,target,scan_type,start_time,end_time,total_hosts,"
                "total_findings,critical,high,risk_score,report_json "
                "FROM scans ORDER BY scan_id"
            ).fetchall()
        ]
        baselines = [
            tuple(row[column] for column in baseline_columns)
            for row in source.execute(
                "SELECT host_ip,open_ports,services,os_guess,first_seen,last_seen,scan_count "
                "FROM baselines ORDER BY host_ip"
            ).fetchall()
        ]
        findings = [
            tuple(row[column] for column in finding_columns)
            for row in source.execute(
                "SELECT finding_id,scan_id,host_ip,title,severity,cve_id,cvss_score,"
                "status,remediated_at,created_at FROM findings_log ORDER BY finding_id"
            ).fetchall()
        ]
        if any(row[-1] is None for row in scans):
            raise RuntimeError("legacy live-scanner scan has null report_json")

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
            for table in ("qc_live_scans", "qc_live_baselines", "qc_live_findings"):
                _require_empty_pg(target, table)

            _executemany(
                target,
                """
                INSERT INTO qc_live_scans (
                    scan_id,target,scan_type,start_time,end_time,total_hosts,
                    total_findings,critical,high,risk_score,report_json
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                scans,
            )
            _executemany(
                target,
                """
                INSERT INTO qc_live_baselines (
                    host_ip,open_ports,services,os_guess,first_seen,last_seen,scan_count
                ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                baselines,
            )
            _executemany(
                target,
                """
                INSERT INTO qc_live_findings (
                    finding_id,scan_id,host_ip,title,severity,cve_id,cvss_score,
                    status,remediated_at,created_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                findings,
            )

            verified = {
                "qc_live_scans": _verify(
                    target, "qc_live_scans", scans_columns, ("scan_id",), scans
                ),
                "qc_live_baselines": _verify(
                    target,
                    "qc_live_baselines",
                    baseline_columns,
                    ("host_ip",),
                    baselines,
                ),
                "qc_live_findings": _verify(
                    target,
                    "qc_live_findings",
                    finding_columns,
                    ("finding_id",),
                    findings,
                ),
            }
        return {
            "kind": "live-scanner",
            "source_path": str(LIVE_SCANNER_STAGE.relative_to(ROOT)),
            "source_sha256": _sha256_stage(LIVE_SCANNER_STAGE),
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
