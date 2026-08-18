"""QC OS primary runtime database contract.

SQLite remains the default for local/dev operation. Setting QC_DATABASE_URL to a
postgresql:// or postgres:// URL moves this *primary* state contract to
PostgreSQL without changing the calling surface used by chat, market, forecast,
and identity modules.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_dumps(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, default=str)


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def database_url() -> str:
    return (os.getenv("QC_DATABASE_URL") or os.getenv("DATABASE_URL") or "").strip()


def database_backend() -> str:
    url = database_url()
    if not url:
        return "sqlite"
    if url.startswith(("postgresql://", "postgres://")):
        return "postgresql"
    raise RuntimeError("QC_DATABASE_URL/DATABASE_URL must use postgresql:// or postgres://")


class DatabaseCursor:
    def __init__(self, raw: Any, dialect: str):
        self.raw = raw
        self.dialect = dialect

    def __getattr__(self, name: str):
        return getattr(self.raw, name)

    @property
    def lastrowid(self):
        if self.dialect == "sqlite":
            return self.raw.lastrowid
        row = self.raw.connection.execute("SELECT LASTVAL() AS id").fetchone()
        return row["id"]


class DatabaseConnection:
    """Small DB-API compatibility facade shared by SQLite and Psycopg 3."""

    def __init__(self, raw: Any, dialect: str):
        self.raw = raw
        self.dialect = dialect

    def __enter__(self) -> "DatabaseConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self.raw.commit()
            else:
                self.raw.rollback()
        finally:
            self.raw.close()

    def __getattr__(self, name: str):
        # Preserve the existing sqlite3.Connection surface for callers that do
        # not need cross-database translation. Explicit facade methods below
        # handle operations whose behavior differs between engines.
        return getattr(self.raw, name)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()

    def execute(self, sql: str, params: tuple | list = ()):
        if self.dialect == "postgresql":
            sql = _postgres_sql(sql)
        return DatabaseCursor(self.raw.execute(sql, params), self.dialect)

    def executescript(self, script: str):
        if self.dialect == "sqlite":
            return self.raw.executescript(script)
        cursor = None
        for statement in _schema_statements(script):
            cursor = self.raw.execute(_postgres_sql(statement))
        return DatabaseCursor(cursor, self.dialect) if cursor is not None else None


def _postgres_sql(sql: str) -> str:
    """Translate the deliberately small SQLite query surface used by callers."""
    statement = sql.strip()
    if statement.upper() == "BEGIN IMMEDIATE":
        # Preserve the SQLite gate's single-writer semantics for the identity
        # auto-learning throttle without taking a database-wide table lock.
        return "SELECT pg_advisory_xact_lock(72427201)"

    statement = statement.replace("?", "%s")

    if re.match(r"(?is)^INSERT\s+OR\s+REPLACE\s+INTO\s+identity_cycle_gate\s*", statement):
        statement = re.sub(r"(?is)^INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", statement, count=1)
        return statement + " ON CONFLICT (id) DO UPDATE SET last_auto_at = EXCLUDED.last_auto_at"

    if re.match(r"(?is)^INSERT\s+OR\s+IGNORE\s+INTO\s+", statement):
        statement = re.sub(r"(?is)^INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", statement, count=1)
        if " ON CONFLICT " not in statement.upper():
            returning_match = re.search(r"(?is)\s+RETURNING\s+", statement)
            if returning_match:
                idx = returning_match.start()
                statement = statement[:idx] + " ON CONFLICT DO NOTHING" + statement[idx:]
            else:
                statement += " ON CONFLICT DO NOTHING"
    return statement


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_sqlite_path(db_path: Path | str) -> Path:
    """Resolve a SQLite path only inside explicitly trusted storage roots.

    Runtime state belongs in the configured QC_DB_PATH directory or the local
    application data directory. Pytest may additionally use its temporary root.
    This prevents request-controlled values from turning database creation into
    an arbitrary filesystem write primitive.
    """
    raw = os.fspath(db_path)
    if not raw or "\x00" in raw:
        raise ValueError("SQLite database path is empty or invalid")

    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = candidate.resolve(strict=False)

    trusted_roots: list[Path] = [(Path.cwd() / "data").resolve(strict=False)]
    configured = (os.getenv("QC_DB_PATH") or "").strip()
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_absolute():
            configured_path = Path.cwd() / configured_path
        trusted_roots.append(configured_path.resolve(strict=False).parent)

    # pytest exposes this variable only while a test is executing. Restricting
    # temp-root access to tests keeps production/runtime callers on durable,
    # explicitly configured storage while preserving isolated tmp_path tests.
    if os.getenv("PYTEST_CURRENT_TEST"):
        trusted_roots.append(Path(tempfile.gettempdir()).resolve(strict=False))

    if not any(_is_within(candidate, root) for root in trusted_roots):
        roots = ", ".join(str(root) for root in trusted_roots)
        raise ValueError(f"SQLite database path must stay within trusted storage roots: {roots}")
    return candidate


def get_db(db_path: Path | str) -> DatabaseConnection:
    if database_backend() == "postgresql":
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise RuntimeError("PostgreSQL configured but psycopg is not installed") from exc
        raw = psycopg.connect(database_url(), row_factory=dict_row)
        return DatabaseConnection(raw, "postgresql")

    path = _resolve_sqlite_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(str(path))
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA journal_mode=WAL")
    raw.execute("PRAGMA foreign_keys=ON")
    return DatabaseConnection(raw, "sqlite")


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'cyber', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS turns (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('user','assistant','system','tool')), content TEXT NOT NULL, tool_name TEXT, tokens_in INTEGER, tokens_out INTEGER, latency_ms INTEGER, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memories (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 0.8, source TEXT DEFAULT 'conversation', created_at TEXT NOT NULL, expires_at TEXT, UNIQUE(user_id, key, value));
CREATE TABLE IF NOT EXISTS trusted_sources (id TEXT PRIMARY KEY, name TEXT NOT NULL, base_url TEXT NOT NULL, source_type TEXT NOT NULL, confidence_score REAL NOT NULL DEFAULT 0.95, enabled INTEGER NOT NULL DEFAULT 1, last_fetched_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, query_key TEXT NOT NULL, data_json TEXT NOT NULL, fetched_at TEXT NOT NULL, expires_at TEXT NOT NULL, hash_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS market_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_type TEXT NOT NULL, symbol TEXT NOT NULL, source TEXT NOT NULL, price REAL, quote_ccy TEXT, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS features (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, feature_name TEXT NOT NULL, value REAL NOT NULL, confidence REAL NOT NULL DEFAULT 0.5, source_ids TEXT NOT NULL, computed_at TEXT NOT NULL, promoted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS forecast_runs (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, run_type TEXT NOT NULL, input_json TEXT NOT NULL, output_json TEXT, status TEXT NOT NULL DEFAULT 'pending', baseline_score REAL, new_score REAL, promoted INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, completed_at TEXT);
CREATE TABLE IF NOT EXISTS portfolio_scenarios (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, holdings_json TEXT NOT NULL, strategy_json TEXT, performance_json TEXT, is_paper INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS telemetry_events (id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, actor TEXT NOT NULL, target TEXT, detail_json TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_proposals (id INTEGER PRIMARY KEY AUTOINCREMENT, lane TEXT NOT NULL CHECK(lane IN ('personal','cyber','market','persona')), kind TEXT NOT NULL, content TEXT NOT NULL, score REAL NOT NULL DEFAULT 0.5, source TEXT, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_reflections (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL, source TEXT, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_persona_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_self_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, note_text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), period TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_provider (id INTEGER PRIMARY KEY CHECK(id=1), provider TEXT NOT NULL DEFAULT 'local_symbolic_core', model TEXT, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_missions (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','closed','archived')), created_at TEXT NOT NULL, closed_at TEXT);
CREATE TABLE IF NOT EXISTS identity_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL REFERENCES identity_missions(id), severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')), summary TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_remediation (id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL REFERENCES identity_missions(id), package_json TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, applied_at TEXT);
"""

POSTGRES_SCHEMA = (
    SQLITE_SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    .replace("mission_id INTEGER NOT NULL REFERENCES", "mission_id BIGINT NOT NULL REFERENCES")
    .replace(" REAL", " DOUBLE PRECISION")
)

TRUSTED_SOURCES = (
    ("sec_edgar", "SEC EDGAR", "https://data.sec.gov", "sec_edgar", 0.99),
    ("fred_api", "Federal Reserve FRED", "https://api.stlouisfed.org/fred", "fred", 0.98),
    ("ecb_data", "ECB Data Portal", "https://data-api.ecb.europa.eu", "ecb", 0.97),
    ("coinbase", "Coinbase Exchange", "https://api.exchange.coinbase.com", "crypto_exchange", 0.93),
    ("kraken", "Kraken Exchange", "https://api.kraken.com", "crypto_exchange", 0.92),
    ("nasdaq_data", "Nasdaq Data Link", "https://data.nasdaq.com/api/v3", "nasdaq", 0.96),
)


def _schema_statements(schema: str) -> list[str]:
    return [statement.strip() for statement in schema.split(";") if statement.strip()]


def init_db(db_path: Path | str) -> None:
    with get_db(db_path) as c:
        schema = POSTGRES_SCHEMA if c.dialect == "postgresql" else SQLITE_SCHEMA
        for statement in _schema_statements(schema):
            c.execute(statement)
        now = utc_now()
        for source_id, name, base_url, source_type, confidence in TRUSTED_SOURCES:
            c.execute(
                "INSERT OR IGNORE INTO trusted_sources "
                "(id,name,base_url,source_type,confidence_score,enabled,created_at) "
                "VALUES (?,?,?,?,?,1,?)",
                (source_id, name, base_url, source_type, confidence, now),
            )


def audit(db_path: Path | str, event_type: str, actor: str, target: str | None = None, detail: dict | None = None) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO audit_log (event_type,actor,target,detail_json,created_at) VALUES (?,?,?,?,?)",
            (event_type, actor, target, json_dumps(detail) if detail else None, utc_now()),
        )


def log_event(db_path: Path | str, category: str, kind: str, subject: str, payload: Any) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO telemetry_events (category,kind,subject,payload_json,created_at) VALUES (?,?,?,?,?)",
            (category, kind, subject, json_dumps(payload), utc_now()),
        )


def save_market_snapshot(db_path: Path | str, asset_type: str, symbol: str, source: str, price: float | None, quote_ccy: str | None, payload: dict) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO market_snapshots (asset_type,symbol,source,price,quote_ccy,payload_json,created_at) VALUES (?,?,?,?,?,?,?)",
            (asset_type, symbol, source, price, quote_ccy, json_dumps(payload), utc_now()),
        )


def get_market_history(db_path: Path | str, asset_type: str, symbol: str, limit: int = 24) -> list[dict]:
    with get_db(db_path) as c:
        rows = c.execute(
            "SELECT price,quote_ccy,source,created_at FROM market_snapshots "
            "WHERE asset_type=? AND symbol=? ORDER BY id DESC LIMIT ?",
            (asset_type, symbol, limit),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]
