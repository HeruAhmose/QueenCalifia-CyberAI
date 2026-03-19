"""QC OS — Database (merged)
=============================
Minimal database helpers used by dashboard route modules.

This file is intentionally copied from `backend/core/database.py` so that
imports like `from core.database import ...` work when the security gateway
root app is loaded.
"""

from __future__ import annotations

import hashlib, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_dumps(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, default=str)


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def get_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(db_path))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db(db_path: Path) -> None:
    with get_db(db_path) as c:
        c.executescript("""
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

            -- Identity Core: Memory Proposals (4 lanes: personal, cyber, market, persona)
            CREATE TABLE IF NOT EXISTS identity_proposals (id INTEGER PRIMARY KEY AUTOINCREMENT, lane TEXT NOT NULL CHECK(lane IN ('personal','cyber','market','persona')), kind TEXT NOT NULL, content TEXT NOT NULL, score REAL NOT NULL DEFAULT 0.5, source TEXT, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL);
            -- Identity Core: Reflections
            CREATE TABLE IF NOT EXISTS identity_reflections (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL, source TEXT, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL);
            -- Identity Core: Persona Rules
            CREATE TABLE IF NOT EXISTS identity_persona_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), created_at TEXT NOT NULL);
            -- Identity Core: Weekly Self-Notes
            CREATE TABLE IF NOT EXISTS identity_self_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, note_text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), period TEXT, created_at TEXT NOT NULL);
            -- Identity Core: Runtime Provider (single-row config)
            CREATE TABLE IF NOT EXISTS identity_provider (id INTEGER PRIMARY KEY CHECK(id=1), provider TEXT NOT NULL DEFAULT 'local_symbolic_core', model TEXT, updated_at TEXT NOT NULL);
            -- Identity Core: Cyber Missions
            CREATE TABLE IF NOT EXISTS identity_missions (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','closed','archived')), created_at TEXT NOT NULL, closed_at TEXT);
            -- Identity Core: Cyber Findings
            CREATE TABLE IF NOT EXISTS identity_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL REFERENCES identity_missions(id), severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')), summary TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
            -- Identity Core: Remediation Packages
            CREATE TABLE IF NOT EXISTS identity_remediation (id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL REFERENCES identity_missions(id), package_json TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, applied_at TEXT);
            INSERT OR IGNORE INTO trusted_sources (id,name,base_url,source_type,confidence_score,enabled,created_at) VALUES
                ('sec_edgar','SEC EDGAR','https://data.sec.gov','sec_edgar',0.99,1,datetime('now')),
                ('fred_api','Federal Reserve FRED','https://api.stlouisfed.org/fred','fred',0.98,1,datetime('now')),
                ('ecb_data','ECB Data Portal','https://data-api.ecb.europa.eu','ecb',0.97,1,datetime('now')),
                ('coinbase','Coinbase Exchange','https://api.exchange.coinbase.com','crypto_exchange',0.93,1,datetime('now')),
                ('kraken','Kraken Exchange','https://api.kraken.com','crypto_exchange',0.92,1,datetime('now')),
                ('nasdaq_data','Nasdaq Data Link','https://data.nasdaq.com/api/v3','nasdaq',0.96,1,datetime('now'));
        """)


def audit(db_path: Path, event_type: str, actor: str, target: str | None = None, detail: dict | None = None) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO audit_log (event_type,actor,target,detail_json,created_at) VALUES (?,?,?,?,?)",
            (event_type, actor, target, json_dumps(detail) if detail else None, utc_now()),
        )


def log_event(db_path: Path, category: str, kind: str, subject: str, payload: Any) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO telemetry_events (category,kind,subject,payload_json,created_at) VALUES (?,?,?,?,?)",
            (category, kind, subject, json_dumps(payload), utc_now()),
        )


def save_market_snapshot(
    db_path: Path,
    asset_type: str,
    symbol: str,
    source: str,
    price: float | None,
    quote_ccy: str | None,
    payload: dict,
) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO market_snapshots (asset_type,symbol,source,price,quote_ccy,payload_json,created_at) VALUES (?,?,?,?,?,?,?)",
            (asset_type, symbol, source, price, quote_ccy, json_dumps(payload), utc_now()),
        )


def get_market_history(db_path: Path, asset_type: str, symbol: str, limit: int = 24) -> list[dict]:
    with get_db(db_path) as c:
        rows = c.execute(
            "SELECT price,quote_ccy,source,created_at FROM market_snapshots WHERE asset_type=? AND symbol=? ORDER BY id DESC LIMIT ?",
            (asset_type, symbol, limit),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]

