#!/usr/bin/env python3
"""Bootstrap Queen Califia's PostgreSQL runtime schema on a verified-empty PG18 target.

This is a schema-only cutover primitive. It never imports historical data, never
creates an authorization marker, never starts application services, and never
prints a connection URL or row values.

The target must be the direct TLS PostgreSQL endpoint supplied through
QC_DATABASE_DIRECT_URL. Any existing public table or sequence causes a
fail-closed refusal.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.database import POSTGRES_SCHEMA  # noqa: E402
from scripts.migrate_runtime_state_to_postgres import TARGET_SCHEMA  # noqa: E402
from scripts.postgres_database_manifest import build_database_manifest  # noqa: E402

EXTERNALIZED_ARTIFACT_SCHEMA = """
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
);
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
);
CREATE TABLE IF NOT EXISTS qc_spki_evidence (
    sequence BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_json TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL
);
"""

LIVE_SCANNER_SCHEMA = """
CREATE TABLE IF NOT EXISTS qc_live_scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT,
    scan_type TEXT,
    start_time TEXT,
    end_time TEXT,
    total_hosts INTEGER,
    total_findings INTEGER,
    critical INTEGER,
    high INTEGER,
    risk_score DOUBLE PRECISION,
    report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_live_baselines (
    host_ip TEXT PRIMARY KEY,
    open_ports TEXT NOT NULL,
    services TEXT NOT NULL,
    os_guess TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS qc_live_findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT,
    host_ip TEXT,
    title TEXT,
    severity TEXT,
    cve_id TEXT,
    cvss_score DOUBLE PRECISION,
    status TEXT NOT NULL DEFAULT 'open',
    remediated_at TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_qc_live_findings_host ON qc_live_findings(host_ip);
CREATE INDEX IF NOT EXISTS idx_qc_live_findings_severity ON qc_live_findings(severity);
CREATE INDEX IF NOT EXISTS idx_qc_live_scans_target ON qc_live_scans(target);
"""

REQUIRED_TABLES = frozenset(
    {
        "sessions",
        "turns",
        "memories",
        "trusted_sources",
        "source_cache",
        "market_snapshots",
        "features",
        "forecast_runs",
        "portfolio_scenarios",
        "telemetry_events",
        "audit_log",
        "identity_proposals",
        "identity_reflections",
        "identity_persona_rules",
        "identity_self_notes",
        "identity_provider",
        "identity_missions",
        "identity_findings",
        "identity_remediation",
        "qc_approval_records",
        "qc_used_nonces",
        "qc_audit_chain",
        "qc_ir_incidents",
        "qc_ir_runtime_state",
        "qc_remediation_plans",
        "qc_remediation_action_log",
        "health_log",
        "learned_patterns",
        "evolutions",
        "scan_intelligence",
        "false_positives",
        "network_baselines",
        "processed_scan_learning",
        "threat_feeds",
        "threat_indicators",
        "threat_cves",
        "threat_actors",
        "threat_sync_log",
        "threat_scheduler_lease",
        "qc_api_keys",
        "qc_request_audit",
        "qc_spki_evidence",
        "qc_live_scans",
        "qc_live_baselines",
        "qc_live_findings",
    }
)

_ADVISORY_LOCK = 72427218


def _schema_statements(schema: str) -> list[str]:
    return [statement.strip() for statement in schema.split(";") if statement.strip()]


def schema_statements() -> list[str]:
    statements: list[str] = []
    for schema in (
        POSTGRES_SCHEMA,
        TARGET_SCHEMA,
        EXTERNALIZED_ARTIFACT_SCHEMA,
        LIVE_SCANNER_SCHEMA,
    ):
        statements.extend(_schema_statements(schema))
    return statements


def validate_direct_database_url(url: str) -> str:
    value = (url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise RuntimeError(
            "QC_DATABASE_DIRECT_URL must use postgresql:// or postgres://"
        )
    if not parsed.hostname:
        raise RuntimeError("QC_DATABASE_DIRECT_URL is missing a hostname")
    if "-pooler." in parsed.hostname:
        raise RuntimeError("QC_DATABASE_DIRECT_URL must use the direct Neon endpoint")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if query.get("sslmode") != ["require"]:
        raise RuntimeError(
            "QC_DATABASE_DIRECT_URL must require TLS with sslmode=require"
        )
    return value


def _inventory(conn) -> tuple[list[str], list[str]]:
    tables = [
        str(row[0])
        for row in conn.execute(
            """
            SELECT tablename
            FROM pg_tables
            WHERE schemaname='public'
            ORDER BY tablename
            """
        ).fetchall()
    ]
    sequences = [
        str(row[0])
        for row in conn.execute(
            """
            SELECT sequencename
            FROM pg_sequences
            WHERE schemaname='public'
            ORDER BY sequencename
            """
        ).fetchall()
    ]
    return tables, sequences


def bootstrap(database_url: str) -> dict[str, object]:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - packaging contract
        raise RuntimeError(
            "psycopg is required; install backend/requirements.txt"
        ) from exc

    url = validate_direct_database_url(database_url)
    with psycopg.connect(url) as conn:
        server_version_num = int(conn.execute("SHOW server_version_num").fetchone()[0])
        major = server_version_num // 10000
        if major != 18:
            raise RuntimeError(f"expected PostgreSQL 18, got major {major}")

        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK,))
        before_tables, before_sequences = _inventory(conn)
        if before_tables or before_sequences:
            raise RuntimeError(
                "refusing schema bootstrap: public schema is not empty "
                f"(tables={len(before_tables)} sequences={len(before_sequences)})"
            )

        for statement in schema_statements():
            conn.execute(statement)

        after_tables, after_sequences = _inventory(conn)
        missing = sorted(REQUIRED_TABLES - set(after_tables))
        if missing:
            raise RuntimeError(
                "schema bootstrap incomplete; missing required tables: "
                + ", ".join(missing)
            )

    manifest = build_database_manifest(url)
    if manifest.get("postgresql_major") != 18:
        raise RuntimeError("post-bootstrap manifest did not report PostgreSQL 18")
    if set(manifest.get("tables", {})) != set(after_tables):
        raise RuntimeError("post-bootstrap manifest table inventory mismatch")

    return {
        "kind": "queen-califia-postgres-schema-bootstrap",
        "version": 1,
        "postgresql_major": 18,
        "schema_only": True,
        "historical_data_migrated": False,
        "target_was_empty": True,
        "tables": len(after_tables),
        "sequences": len(after_sequences),
        "database_sha256": manifest["database_sha256"],
    }


def main() -> int:
    url = validate_direct_database_url(os.getenv("QC_DATABASE_DIRECT_URL", ""))
    print(json.dumps(bootstrap(url), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
