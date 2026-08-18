#!/usr/bin/env python3
"""Migrate Queen Califia runtime SQLite authorities into PostgreSQL.

This is a staging/cutover-preparation tool. It deliberately does not switch the
application to PostgreSQL, delete SQLite files, enable multiple replicas, or
mark any topology completion gate true.

Safety properties:
- every SQLite source is opened read-only;
- source tables are classified against an explicit ownership inventory;
- unknown tables fail closed;
- known unresolved writable stores (vulnerability/live-scanner) are reported as
  cutover blockers rather than copied or ignored;
- all recognized authoritative tables are copied in one PostgreSQL transaction;
- the PostgreSQL target must be empty for every table being migrated;
- incident attack-chain identity is materialized from the persisted JSON and
  protected by the PostgreSQL uniqueness contract;
- audit-chain cryptographic continuity is verified before copy;
- row counts AND deterministic per-table content digests are verified before
  commit;
- serial sequences are reset after explicit IDs are copied;
- an optional migration manifest records source file hashes and verified table
  digests; the same manifest can later verify a restored PostgreSQL database;
- control-plane topology is read only from the repository-owned canonical path;
- manifest transport uses stdout/stdin rather than user-controlled file writes;
- --require-cutover-ready fails while runtime-state-topology still reports any
  unresolved SQLite/file authority or incomplete production cutover.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_TOPOLOGY_PATH = ROOT / "config" / "runtime-state-topology.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.database import POSTGRES_SCHEMA  # noqa: E402
from scripts.migrate_primary_sqlite_to_postgres import (  # noqa: E402
    DYNAMIC_TABLES,
    PRIMARY_TABLES,
    SERIAL_TABLES as PRIMARY_SERIAL_TABLES,
)
from sovereignty.audit_chain import (  # noqa: E402
    GENESIS_HASH,
    compute_chain_hash,
    compute_record_hash,
)
from sovereignty.schemas import ApprovalRecord  # noqa: E402


SOVEREIGNTY_TABLES = (
    "qc_approval_records",
    "qc_used_nonces",
    "qc_audit_chain",
)
INCIDENT_TABLES = (
    "qc_ir_incidents",
    "qc_ir_runtime_state",
)
REMEDIATION_TABLES = (
    "qc_remediation_plans",
    "qc_remediation_action_log",
)
EVOLUTION_TABLES = (
    "health_log",
    "learned_patterns",
    "evolutions",
    "scan_intelligence",
    "false_positives",
    "network_baselines",
    "processed_scan_learning",
)
THREAT_TABLES = (
    "threat_feeds",
    "threat_indicators",
    "threat_cves",
    "threat_actors",
    "threat_sync_log",
    "threat_scheduler_lease",
)

UNRESOLVED_WRITER_TABLES = {
    "qc_vuln_scan_jobs": "vulnerability-scan-job-db",
    "scans": "live-scanner-db",
    "baselines": "live-scanner-db",
    "findings_log": "live-scanner-db",
}

AUTHORITATIVE_TABLES = (
    set(PRIMARY_TABLES)
    | set(DYNAMIC_TABLES)
    | set(SOVEREIGNTY_TABLES)
    | set(INCIDENT_TABLES)
    | set(REMEDIATION_TABLES)
    | set(EVOLUTION_TABLES)
    | set(THREAT_TABLES)
)
KNOWN_SOURCE_TABLES = AUTHORITATIVE_TABLES | set(UNRESOLVED_WRITER_TABLES)

TARGET_SCHEMA = """
CREATE TABLE IF NOT EXISTS qc_approval_records (
    approval_id TEXT PRIMARY KEY,
    approval_json TEXT NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_used_nonces (
    nonce TEXT PRIMARY KEY,
    used_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_audit_chain (
    sequence BIGINT PRIMARY KEY,
    timestamp DOUBLE PRECISION NOT NULL,
    record_json TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    prev_chain_hash TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    hash_alg TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_ir_incidents (
    incident_id TEXT PRIMARY KEY,
    attack_chain_id TEXT,
    incident_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
ALTER TABLE qc_ir_incidents ADD COLUMN IF NOT EXISTS attack_chain_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_qc_ir_attack_chain
    ON qc_ir_incidents(attack_chain_id) WHERE attack_chain_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS qc_ir_runtime_state (
    state_key TEXT PRIMARY KEY,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_remediation_plans (
    plan_id TEXT PRIMARY KEY,
    plan_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_remediation_action_log (
    log_id BIGSERIAL PRIMARY KEY,
    action_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS health_log (
    id BIGSERIAL PRIMARY KEY,
    component_id TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    healed INTEGER DEFAULT 0,
    timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS learned_patterns (
    pattern_id TEXT PRIMARY KEY,
    learning_type TEXT NOT NULL,
    source_engine TEXT NOT NULL,
    pattern_json TEXT NOT NULL,
    confidence DOUBLE PRECISION DEFAULT 0,
    observations INTEGER DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    applied INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS evolutions (
    evolution_id TEXT PRIMARY KEY,
    evolution_type TEXT NOT NULL,
    description TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    source_patterns TEXT,
    created_at TEXT NOT NULL,
    applied INTEGER DEFAULT 0,
    success INTEGER,
    impact_score DOUBLE PRECISION DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_intelligence (
    id BIGSERIAL PRIMARY KEY,
    host_ip TEXT NOT NULL,
    port INTEGER,
    service TEXT,
    version TEXT,
    finding_type TEXT,
    severity TEXT,
    scan_time TEXT NOT NULL,
    remediated INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS false_positives (
    id BIGSERIAL PRIMARY KEY,
    rule_id TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    marked_by TEXT DEFAULT 'operator',
    timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS network_baselines (
    baseline_key TEXT PRIMARY KEY,
    baseline_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS processed_scan_learning (
    scan_id TEXT PRIMARY KEY,
    learned_at TEXT NOT NULL,
    source TEXT,
    learning_json TEXT,
    evolution_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_component ON health_log(component_id);
CREATE INDEX IF NOT EXISTS idx_patterns_type ON learned_patterns(learning_type);
CREATE INDEX IF NOT EXISTS idx_scan_intel_host ON scan_intelligence(host_ip);
CREATE INDEX IF NOT EXISTS idx_evolutions_type ON evolutions(evolution_type);
CREATE TABLE IF NOT EXISTS threat_feeds (
    feed_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    feed_format TEXT NOT NULL,
    status TEXT NOT NULL,
    update_interval_sec INTEGER NOT NULL,
    last_sync DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_success DOUBLE PRECISION NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    ioc_count INTEGER NOT NULL DEFAULT 0,
    confidence_weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    tags_json TEXT NOT NULL,
    auth_required INTEGER NOT NULL DEFAULT 0,
    created_at DOUBLE PRECISION NOT NULL,
    parser_config_json TEXT NOT NULL,
    headers_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator_id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    severity TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    first_seen DOUBLE PRECISION NOT NULL,
    last_seen DOUBLE PRECISION NOT NULL,
    last_updated DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    tags_json TEXT NOT NULL,
    mitre_techniques_json TEXT NOT NULL,
    threat_actor TEXT,
    campaign TEXT,
    context_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    decay_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01
);
CREATE TABLE IF NOT EXISTS threat_cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    severity TEXT NOT NULL,
    affected_products_json TEXT NOT NULL,
    exploit_available INTEGER NOT NULL DEFAULT 0,
    in_the_wild INTEGER NOT NULL DEFAULT 0,
    patch_available INTEGER NOT NULL DEFAULT 0,
    first_published DOUBLE PRECISION NOT NULL,
    last_modified DOUBLE PRECISION NOT NULL,
    references_json TEXT NOT NULL,
    mitre_techniques_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_actors (
    actor_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    aliases_json TEXT NOT NULL,
    nation_state TEXT,
    motivation TEXT,
    sophistication TEXT,
    target_industries_json TEXT NOT NULL,
    target_regions_json TEXT NOT NULL,
    known_techniques_json TEXT NOT NULL,
    known_tools_json TEXT NOT NULL,
    campaigns_json TEXT NOT NULL,
    ioc_count INTEGER NOT NULL DEFAULT 0,
    last_activity DOUBLE PRECISION NOT NULL DEFAULT 0,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS threat_sync_log (
    id BIGSERIAL PRIMARY KEY,
    feed_id TEXT NOT NULL,
    success INTEGER NOT NULL,
    iocs_ingested INTEGER NOT NULL DEFAULT 0,
    cves_ingested INTEGER NOT NULL DEFAULT 0,
    actors_ingested INTEGER NOT NULL DEFAULT 0,
    detail_json TEXT,
    timestamp DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_scheduler_lease (
    lease_name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    acquired_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL
);
"""


@dataclass(frozen=True)
class SourceSpec:
    role: str
    path: Path


@dataclass(frozen=True)
class TableSpec:
    columns: tuple[str, ...]
    key_columns: tuple[str, ...]
    transform: Callable[[Mapping[str, Any]], tuple[Any, ...]] | None = None


def _identity(columns: Sequence[str]) -> Callable[[Mapping[str, Any]], tuple[Any, ...]]:
    return lambda row: tuple(row[column] for column in columns)


def _incident_row(row: Mapping[str, Any]) -> tuple[Any, ...]:
    payload = json.loads(row["incident_json"])
    incident_id = str(row["incident_id"])
    payload_id = str(payload.get("incident_id") or incident_id)
    if payload_id != incident_id:
        raise RuntimeError(
            f"qc_ir_incidents identity mismatch: row={incident_id!r}, json={payload_id!r}"
        )
    attack_chain_id = payload.get("attack_chain_id") or None
    return (incident_id, attack_chain_id, row["incident_json"], row["updated_at"])


def _build_specs() -> dict[str, TableSpec]:
    specs: dict[str, TableSpec] = {}
    for table in set(PRIMARY_TABLES) | set(DYNAMIC_TABLES):
        specs[table] = TableSpec((), ())

    explicit: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
        "qc_approval_records": (("approval_id", "approval_json", "updated_at"), ("approval_id",)),
        "qc_used_nonces": (("nonce", "used_at"), ("nonce",)),
        "qc_audit_chain": (("sequence", "timestamp", "record_json", "record_hash", "prev_chain_hash", "chain_hash", "hash_alg"), ("sequence",)),
        "qc_ir_incidents": (("incident_id", "attack_chain_id", "incident_json", "updated_at"), ("incident_id",)),
        "qc_ir_runtime_state": (("state_key", "state_json", "updated_at"), ("state_key",)),
        "qc_remediation_plans": (("plan_id", "plan_json", "updated_at"), ("plan_id",)),
        "qc_remediation_action_log": (("log_id", "action_json", "created_at"), ("log_id",)),
        "health_log": (("id", "component_id", "status", "error", "healed", "timestamp"), ("id",)),
        "learned_patterns": (("pattern_id", "learning_type", "source_engine", "pattern_json", "confidence", "observations", "first_seen", "last_seen", "applied"), ("pattern_id",)),
        "evolutions": (("evolution_id", "evolution_type", "description", "payload_json", "source_patterns", "created_at", "applied", "success", "impact_score"), ("evolution_id",)),
        "scan_intelligence": (("id", "host_ip", "port", "service", "version", "finding_type", "severity", "scan_time", "remediated"), ("id",)),
        "false_positives": (("id", "rule_id", "finding_hash", "marked_by", "timestamp"), ("id",)),
        "network_baselines": (("baseline_key", "baseline_json", "updated_at"), ("baseline_key",)),
        "processed_scan_learning": (("scan_id", "learned_at", "source", "learning_json", "evolution_json"), ("scan_id",)),
        "threat_feeds": (("feed_id", "name", "source_url", "feed_format", "status", "update_interval_sec", "last_sync", "last_success", "error_count", "ioc_count", "confidence_weight", "tags_json", "auth_required", "created_at", "parser_config_json", "headers_json"), ("feed_id",)),
        "threat_indicators": (("indicator_id", "value", "indicator_type", "confidence", "severity", "sources_json", "first_seen", "last_seen", "last_updated", "expires_at", "tags_json", "mitre_techniques_json", "threat_actor", "campaign", "context_json", "active", "decay_rate"), ("indicator_id",)),
        "threat_cves": (("cve_id", "description", "cvss_score", "severity", "affected_products_json", "exploit_available", "in_the_wild", "patch_available", "first_published", "last_modified", "references_json", "mitre_techniques_json"), ("cve_id",)),
        "threat_actors": (("actor_id", "name", "aliases_json", "nation_state", "motivation", "sophistication", "target_industries_json", "target_regions_json", "known_techniques_json", "known_tools_json", "campaigns_json", "ioc_count", "last_activity", "confidence"), ("actor_id",)),
        "threat_sync_log": (("id", "feed_id", "success", "iocs_ingested", "cves_ingested", "actors_ingested", "detail_json", "timestamp"), ("id",)),
        "threat_scheduler_lease": (("lease_name", "owner_id", "acquired_at", "expires_at"), ("lease_name",)),
    }
    for table, (columns, keys) in explicit.items():
        transform = _incident_row if table == "qc_ir_incidents" else _identity(columns)
        specs[table] = TableSpec(columns, keys, transform)
    return specs


TABLE_SPECS = _build_specs()

SERIAL_COLUMNS = {table: "id" for table in PRIMARY_SERIAL_TABLES}
SERIAL_COLUMNS.update(
    {
        "qc_remediation_action_log": "log_id",
        "health_log": "id",
        "scan_intelligence": "id",
        "false_positives": "id",
        "threat_sync_log": "id",
    }
)

JSON_COLUMNS: dict[str, tuple[str, ...]] = {
    "qc_ir_runtime_state": ("state_json",),
    "qc_remediation_action_log": ("action_json",),
    "learned_patterns": ("pattern_json",),
    "evolutions": ("payload_json", "source_patterns"),
    "network_baselines": ("baseline_json",),
    "processed_scan_learning": ("learning_json", "evolution_json"),
    "threat_feeds": ("tags_json", "parser_config_json", "headers_json"),
    "threat_indicators": ("sources_json", "tags_json", "mitre_techniques_json", "context_json"),
    "threat_cves": ("affected_products_json", "references_json", "mitre_techniques_json"),
    "threat_actors": ("aliases_json", "target_industries_json", "target_regions_json", "known_techniques_json", "known_tools_json", "campaigns_json"),
    "threat_sync_log": ("detail_json",),
}


def _schema_statements(schema: str) -> list[str]:
    return [statement.strip() for statement in schema.split(";") if statement.strip()]


def _quote_identifier(name: str) -> str:
    if name not in KNOWN_SOURCE_TABLES and name not in AUTHORITATIVE_TABLES:
        raise ValueError(f"unexpected table name: {name}")
    return '"' + name.replace('"', '""') + '"'


def _connect_source(path: Path) -> sqlite3.Connection:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise RuntimeError(f"SQLite source does not exist: {resolved}")
    conn = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _connect_postgres(url: str):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("psycopg is required; install backend/requirements.txt") from exc
    return psycopg.connect(url, row_factory=dict_row)


def _source_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows if not str(row[0]).startswith("sqlite_")}


def _source_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    quoted = _quote_identifier(table)
    return [str(row[1]) for row in conn.execute(f"PRAGMA table_info({quoted})").fetchall()]


def _primary_spec(conn: sqlite3.Connection, table: str) -> TableSpec:
    columns = tuple(_source_columns(conn, table))
    if not columns:
        raise RuntimeError(f"source table {table} has no columns")
    info = conn.execute(f"PRAGMA table_info({_quote_identifier(table)})").fetchall()
    pk_rows = sorted((row for row in info if int(row[5] or 0) > 0), key=lambda row: int(row[5]))
    keys = tuple(str(row[1]) for row in pk_rows)
    if not keys:
        raise RuntimeError(f"source table {table} has no declared primary key; update migration contract")
    return TableSpec(columns, keys, _identity(columns))


def _table_spec(conn: sqlite3.Connection, table: str) -> TableSpec:
    if table in set(PRIMARY_TABLES) | set(DYNAMIC_TABLES):
        return _primary_spec(conn, table)
    spec = TABLE_SPECS[table]
    source_columns = set(_source_columns(conn, table))
    required = set(spec.columns)
    if table == "qc_ir_incidents":
        required.discard("attack_chain_id")
    missing = sorted(required - source_columns)
    if missing:
        raise RuntimeError(f"source table {table} missing expected columns: {', '.join(missing)}")
    return spec


def _normalize(value: Any) -> Any:
    if isinstance(value, memoryview):
        return bytes(value).hex()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, float):
        return {"__float__": repr(value)}
    return value


def _digest_rows(rows: Iterable[Sequence[Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        payload = json.dumps([_normalize(v) for v in row], sort_keys=True, separators=(",", ":"), default=str)
        digest.update(payload.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _source_rows(conn: sqlite3.Connection, table: str, spec: TableSpec) -> list[tuple[Any, ...]]:
    source_columns = _source_columns(conn, table)
    quoted = _quote_identifier(table)
    key_sql = ", ".join(f'"{key}"' for key in spec.key_columns)
    sql = f"SELECT * FROM {quoted} ORDER BY {key_sql}"
    rows = conn.execute(sql).fetchall()
    transform = spec.transform or _identity(spec.columns or tuple(source_columns))
    return [transform(row) for row in rows]


def _validate_json_columns(conn: sqlite3.Connection, table: str) -> None:
    columns = set(_source_columns(conn, table))
    for column in JSON_COLUMNS.get(table, ()):
        if column not in columns:
            continue
        for row in conn.execute(
            f'SELECT "{column}" FROM {_quote_identifier(table)} WHERE "{column}" IS NOT NULL'
        ).fetchall():
            raw = row[0]
            if raw in (None, ""):
                continue
            try:
                json.loads(raw)
            except Exception as exc:
                raise RuntimeError(f"invalid JSON in {table}.{column}: {exc}") from exc


def _validate_semantic_invariants(conn: sqlite3.Connection, tables: set[str]) -> None:
    if "qc_approval_records" in tables:
        for row in conn.execute("SELECT approval_id, approval_json FROM qc_approval_records").fetchall():
            record = ApprovalRecord.model_validate_json(row["approval_json"])
            if record.approval_id != row["approval_id"]:
                raise RuntimeError(
                    f"qc_approval_records identity mismatch: row={row['approval_id']!r}, json={record.approval_id!r}"
                )

    if "qc_remediation_plans" in tables:
        for row in conn.execute("SELECT plan_id, plan_json FROM qc_remediation_plans").fetchall():
            payload = json.loads(row["plan_json"])
            if str(payload.get("plan_id") or "") != str(row["plan_id"]):
                raise RuntimeError(f"qc_remediation_plans identity mismatch for {row['plan_id']!r}")

    if "qc_audit_chain" in tables:
        rows = conn.execute(
            "SELECT sequence, record_json, record_hash, prev_chain_hash, chain_hash, hash_alg "
            "FROM qc_audit_chain ORDER BY sequence ASC"
        ).fetchall()
        prev = GENESIS_HASH
        for expected_sequence, row in enumerate(rows):
            sequence = int(row["sequence"])
            if sequence != expected_sequence:
                raise RuntimeError(
                    f"qc_audit_chain sequence discontinuity: expected={expected_sequence}, actual={sequence}"
                )
            record = json.loads(row["record_json"])
            alg = row["hash_alg"]
            expected_record_hash = compute_record_hash(record, alg)
            if row["record_hash"] != expected_record_hash:
                raise RuntimeError(f"qc_audit_chain record hash mismatch at sequence {sequence}")
            if row["prev_chain_hash"] != prev:
                raise RuntimeError(f"qc_audit_chain predecessor mismatch at sequence {sequence}")
            expected_chain_hash = compute_chain_hash(prev, expected_record_hash, alg)
            if row["chain_hash"] != expected_chain_hash:
                raise RuntimeError(f"qc_audit_chain chain hash mismatch at sequence {sequence}")
            prev = row["chain_hash"]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dedupe_sources(sources: Sequence[SourceSpec]) -> list[SourceSpec]:
    by_path: dict[Path, list[str]] = {}
    for source in sources:
        resolved = source.path.expanduser().resolve()
        by_path.setdefault(resolved, []).append(source.role)
    return [SourceSpec(role="+".join(sorted(roles)), path=path) for path, roles in by_path.items()]


def _inventory_sources(sources: Sequence[SourceSpec]) -> tuple[dict[str, tuple[SourceSpec, sqlite3.Connection, TableSpec]], list[dict[str, Any]], list[str]]:
    ownership: dict[str, tuple[SourceSpec, sqlite3.Connection, TableSpec]] = {}
    source_meta: list[dict[str, Any]] = []
    blockers: list[str] = []

    for source in _dedupe_sources(sources):
        conn = _connect_source(source.path)
        tables = _source_tables(conn)
        unknown = sorted(tables - KNOWN_SOURCE_TABLES)
        if unknown:
            conn.close()
            raise RuntimeError(
                f"{source.path} contains unrecognized application tables; update migration inventory before cutover: "
                + ", ".join(unknown)
            )

        unresolved = sorted(tables & set(UNRESOLVED_WRITER_TABLES))
        for table in unresolved:
            count = int(conn.execute(f"SELECT COUNT(*) FROM {_quote_identifier(table)}").fetchone()[0])
            blockers.append(
                f"{UNRESOLVED_WRITER_TABLES[table]} remains a SQLite runtime writer "
                f"({source.path}:{table}, rows={count})"
            )

        authoritative = sorted(tables & AUTHORITATIVE_TABLES)
        _validate_semantic_invariants(conn, set(authoritative))
        for table in authoritative:
            _validate_json_columns(conn, table)
            if table in ownership:
                prior = ownership[table][0]
                conn.close()
                raise RuntimeError(
                    f"authoritative table {table} appears in multiple SQLite sources: "
                    f"{prior.path} and {source.path}; refusing authority merge"
                )
            ownership[table] = (source, conn, _table_spec(conn, table))

        source_meta.append(
            {
                "role": source.role,
                "path": str(source.path),
                "sha256": _sha256_file(source.path),
                "tables": authoritative,
                "unresolved_writer_tables": unresolved,
            }
        )

    return ownership, source_meta, blockers


def _ensure_target_schema(target, source_tables: set[str]) -> None:
    for statement in _schema_statements(POSTGRES_SCHEMA):
        target.execute(statement)
    for table, ddl in DYNAMIC_TABLES.items():
        if table in source_tables:
            target.execute(ddl)
    for statement in _schema_statements(TARGET_SCHEMA):
        target.execute(statement)


def _assert_target_empty(target, tables: Iterable[str]) -> None:
    occupied: list[tuple[str, int]] = []
    for table in sorted(tables):
        count = int(target.execute(f'SELECT COUNT(*) AS n FROM "{table}"').fetchone()["n"])
        if count:
            occupied.append((table, count))
    if occupied:
        detail = ", ".join(f"{table}={count}" for table, count in occupied)
        raise RuntimeError(
            "PostgreSQL target is not empty; refusing to merge authorities. Occupied tables: " + detail
        )


def _copy_table(target, table: str, spec: TableSpec, rows: Sequence[Sequence[Any]]) -> None:
    if not rows:
        return
    columns = spec.columns
    column_sql = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    sql = f'INSERT INTO "{table}" ({column_sql}) VALUES ({placeholders})'
    with target.cursor() as cursor:
        cursor.executemany(sql, rows)


def _reset_sequence(target, table: str, column: str) -> None:
    row = target.execute("SELECT pg_get_serial_sequence(%s, %s) AS seq", (table, column)).fetchone()
    sequence = row["seq"] if row else None
    if not sequence:
        return
    maximum = int(
        target.execute(
            f'SELECT COALESCE(MAX("{column}"), 0) AS max_id FROM "{table}"'
        ).fetchone()["max_id"]
    )
    if maximum > 0:
        target.execute("SELECT setval(%s::regclass, %s, true)", (sequence, maximum))
    else:
        target.execute("SELECT setval(%s::regclass, 1, false)", (sequence,))


def _target_rows(target, table: str, spec: TableSpec) -> list[tuple[Any, ...]]:
    columns = spec.columns
    column_sql = ", ".join(f'"{column}"' for column in columns)
    key_sql = ", ".join(f'"{column}"' for column in spec.key_columns)
    rows = target.execute(f'SELECT {column_sql} FROM "{table}" ORDER BY {key_sql}').fetchall()
    return [tuple(row[column] for column in columns) for row in rows]


def _topology_cutover_blockers(topology_path: Path | None = None) -> list[str]:
    if topology_path is not None:
        requested = topology_path.expanduser().resolve()
        canonical = RUNTIME_TOPOLOGY_PATH.resolve()
        if requested != canonical:
            raise RuntimeError(
                "runtime topology path is fixed to the repository-owned control-plane file"
            )
    topology = json.loads(RUNTIME_TOPOLOGY_PATH.read_text(encoding="utf-8"))
    blockers: list[str] = []
    if topology.get("multi_replica_api_permitted") is not True:
        blockers.append("runtime topology does not permit multi-replica API")

    for connector in topology.get("sqlite_connectors", []):
        if not connector.get("migration_required"):
            continue
        if connector.get("production_cutover_complete") is not True:
            blockers.append(
                f"{connector.get('store', connector.get('path', 'sqlite-store'))} production cutover incomplete"
            )

    for item in topology.get("api_file_state", []):
        if item.get("production_cutover_complete") is not True:
            blockers.append(
                f"file state {item.get('environment', item.get('path', 'unknown'))} not externalized/validated"
            )

    return blockers


def migrate_runtime_state(
    *,
    sources: Sequence[SourceSpec],
    database_url: str,
    topology_path: Path | None = None,
    require_cutover_ready: bool = False,
) -> dict[str, Any]:
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("database_url must be a postgresql:// or postgres:// URL")
    if not sources:
        raise RuntimeError("at least one SQLite source is required")

    ownership: dict[str, tuple[SourceSpec, sqlite3.Connection, TableSpec]] = {}
    target = None
    try:
        ownership, source_meta, source_blockers = _inventory_sources(sources)
        topology_blockers = _topology_cutover_blockers(topology_path) if topology_path is not None else []
        blockers = source_blockers + topology_blockers
        if require_cutover_ready and blockers:
            raise RuntimeError(
                "Cutover is not ready; unresolved runtime-state blockers:\n- " + "\n- ".join(blockers)
            )

        target = _connect_postgres(database_url)
        table_manifest: dict[str, dict[str, Any]] = {}
        source_rows_by_table: dict[str, list[tuple[Any, ...]]] = {}

        for table, (_, conn, spec) in ownership.items():
            rows = _source_rows(conn, table, spec)
            source_rows_by_table[table] = rows
            table_manifest[table] = {
                "rows": len(rows),
                "sha256": _digest_rows(rows),
                "columns": list(spec.columns),
                "key_columns": list(spec.key_columns),
            }

        with target.transaction():
            _ensure_target_schema(target, set(ownership))
            _assert_target_empty(target, ownership)

            for table in sorted(ownership):
                _copy_table(target, table, ownership[table][2], source_rows_by_table[table])

            for table, column in SERIAL_COLUMNS.items():
                if table in ownership:
                    _reset_sequence(target, table, column)

            for table in sorted(ownership):
                spec = ownership[table][2]
                target_rows = _target_rows(target, table, spec)
                expected = table_manifest[table]
                actual_count = len(target_rows)
                actual_digest = _digest_rows(target_rows)
                if actual_count != expected["rows"]:
                    raise RuntimeError(
                        f"verification failed for {table}: source={expected['rows']}, target={actual_count}"
                    )
                if actual_digest != expected["sha256"]:
                    raise RuntimeError(
                        f"content verification failed for {table}: "
                        f"source_sha256={expected['sha256']}, target_sha256={actual_digest}"
                    )

        return {
            "version": 1,
            "kind": "queen-califia-runtime-state-migration",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sources": source_meta,
            "tables": table_manifest,
            "cutover_ready": not blockers,
            "cutover_blockers": blockers,
            "topology_path": str(RUNTIME_TOPOLOGY_PATH) if topology_path is not None else None,
        }
    finally:
        seen_connections: set[int] = set()
        for _, conn, _ in ownership.values():
            ident = id(conn)
            if ident not in seen_connections:
                seen_connections.add(ident)
                conn.close()
        if target is not None:
            target.close()


def verify_postgres_manifest(database_url: str, manifest: Mapping[str, Any]) -> dict[str, Any]:
    target = _connect_postgres(database_url)
    try:
        verified: dict[str, Any] = {}
        for table, expected in sorted(manifest.get("tables", {}).items()):
            if table not in AUTHORITATIVE_TABLES:
                raise RuntimeError(f"manifest contains unrecognized table: {table}")
            spec = TableSpec(tuple(expected["columns"]), tuple(expected["key_columns"]))
            rows = _target_rows(target, table, spec)
            actual = {"rows": len(rows), "sha256": _digest_rows(rows)}
            if actual["rows"] != int(expected["rows"]):
                raise RuntimeError(
                    f"restore verification failed for {table}: expected rows={expected['rows']}, actual={actual['rows']}"
                )
            if actual["sha256"] != expected["sha256"]:
                raise RuntimeError(
                    f"restore verification failed for {table}: expected sha256={expected['sha256']}, actual={actual['sha256']}"
                )
            verified[table] = actual
        return {"verified": True, "tables": verified}
    finally:
        target.close()


def _default_path(env_name: str, fallback: str) -> Path:
    return Path(os.environ.get(env_name, fallback))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary-sqlite", type=Path, help="Primary QC_DB_PATH SQLite source")
    parser.add_argument("--evolution-sqlite", type=Path, help="QC_EVOLUTION_DB SQLite source")
    parser.add_argument("--threat-intel-sqlite", type=Path, help="QC_THREAT_INTEL_DB SQLite source")
    parser.add_argument("--audit-chain-sqlite", type=Path, help="Optional separate QC_AUDIT_CHAIN_DB source")
    parser.add_argument("--approvals-sqlite", type=Path, help="Optional separate QC_APPROVALS_DB source")
    parser.add_argument("--live-scanner-sqlite", type=Path, help="Optional live-scanner SQLite source to inventory as a blocker")
    parser.add_argument(
        "--database-url",
        default=(os.getenv("QC_DATABASE_URL") or os.getenv("DATABASE_URL") or ""),
        help="PostgreSQL URL; defaults to QC_DATABASE_URL or DATABASE_URL",
    )
    parser.add_argument(
        "--require-cutover-ready",
        action="store_true",
        help="Refuse before migration unless topology and source inventory have no unresolved cutover blockers",
    )
    parser.add_argument(
        "--emit-manifest-json",
        action="store_true",
        help="Emit only the verified migration manifest as JSON on stdout for shell redirection or secure capture",
    )
    parser.add_argument(
        "--verify-manifest-stdin",
        action="store_true",
        help="Read a migration manifest as JSON from stdin and verify the PostgreSQL target/restore",
    )
    return parser.parse_args()


def _sources_from_args(args: argparse.Namespace) -> list[SourceSpec]:
    primary = args.primary_sqlite or _default_path("QC_DB_PATH", "data/queen.db")
    evolution = args.evolution_sqlite or _default_path("QC_EVOLUTION_DB", "qc_evolution.db")
    threat_default = os.environ.get("QC_THREAT_INTEL_DB", "").strip()
    if threat_default:
        threat = args.threat_intel_sqlite or Path(threat_default)
    else:
        threat = args.threat_intel_sqlite or (evolution.expanduser().resolve().parent / "qc_threat_intel.db")

    sources = [
        SourceSpec("primary+incident+remediation", primary),
        SourceSpec("evolution", evolution),
        SourceSpec("threat-intelligence", threat),
        SourceSpec("audit-chain", args.audit_chain_sqlite or primary),
        SourceSpec("approvals", args.approvals_sqlite or primary),
    ]
    if args.live_scanner_sqlite is not None:
        sources.append(SourceSpec("live-scanner", args.live_scanner_sqlite))
    return sources


def main() -> int:
    args = parse_args()
    if args.verify_manifest_stdin:
        manifest = json.load(sys.stdin)
        result = verify_postgres_manifest(args.database_url, manifest)
        print("PostgreSQL runtime-state restore verified against migration manifest.")
        for table, info in result["tables"].items():
            print(f"  {table}: rows={info['rows']} sha256={info['sha256']}")
        return 0

    manifest = migrate_runtime_state(
        sources=_sources_from_args(args),
        database_url=args.database_url,
        topology_path=RUNTIME_TOPOLOGY_PATH,
        require_cutover_ready=args.require_cutover_ready,
    )
    if args.emit_manifest_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    print("Runtime SQLite -> PostgreSQL staging migration verified.")
    for table, info in sorted(manifest["tables"].items()):
        print(f"  {table}: rows={info['rows']} sha256={info['sha256']}")
    if manifest["cutover_blockers"]:
        print("CUTOVER NOT READY. Remaining blockers:")
        for blocker in manifest["cutover_blockers"]:
            print(f"  - {blocker}")
    else:
        print("No migration/topology blockers detected by this tool.")
    print("SQLite sources were not modified. Deployment configuration was not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
