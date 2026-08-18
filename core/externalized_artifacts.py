"""Shared PostgreSQL authorities for mutable gateway artifacts.

Local JSON/JSONL implementations remain available in the gateway for local/dev.
When the canonical database is PostgreSQL, production composition can replace
those file-backed implementations with the classes in this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from typing import Any, Dict, List, Optional

from flask import g

from core.api_key_crypto import (
    API_KEY_HASH_SCHEME,
    API_KEY_STORE_VERSION,
    api_key_fingerprint,
)
from core.database import database_backend, database_url


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _connect_pg():
    if database_backend() != "postgresql":
        raise RuntimeError("shared artifact authority requires PostgreSQL")
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PostgreSQL configured but psycopg is not installed") from exc
    return psycopg.connect(database_url(), row_factory=dict_row)


class PostgresAPIKeyStore:
    """Cross-replica API-key store with immediate revocation visibility."""

    backend = "postgresql"

    def __init__(self, file_path: str, pepper: str):
        del file_path
        self.pepper = pepper
        self._lock = threading.RLock()
        self._init_schema()
        self._load_or_seed()

    def _init_schema(self) -> None:
        with _connect_pg() as conn:
            conn.execute(
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

    def _row_count(self) -> int:
        with _connect_pg() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM qc_api_keys").fetchone()["n"])

    def _load_or_seed(self) -> None:
        if self._row_count() > 0:
            return

        raw = (os.environ.get("QC_API_KEYS_JSON") or "").strip()
        if raw:
            data = json.loads(raw)
            self._seed_structured_data(data)
            return

        if self._seed_legacy_env_keys():
            return

        if os.environ.get("QC_PRODUCTION") == "1":
            raise RuntimeError(
                "PostgreSQL API-key store is empty. Seed QC_API_KEYS_JSON or "
                "QC_API_KEY/QC_ADMIN_KEY before production startup."
            )

    def _seed_structured_data(self, data: Dict[str, Any]) -> None:
        keys = data.get("keys") if isinstance(data, dict) else None
        if not isinstance(keys, list):
            raise ValueError("Invalid API keys data (expected {'keys': [...]})")
        if data.get("version") != API_KEY_STORE_VERSION or data.get("hash_scheme") != API_KEY_HASH_SCHEME:
            raise RuntimeError(f"Unsupported API-key store metadata; expected {API_KEY_HASH_SCHEME}")
        with _connect_pg() as conn:
            for item in keys:
                if not isinstance(item, dict) or not item.get("key_hash"):
                    continue
                conn.execute(
                    """
                    INSERT INTO qc_api_keys (
                        key_hash, role, permissions_json, rate_limit, created_at,
                        description, budget_capacity, budget_refill_per_minute, revoked
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (key_hash) DO NOTHING
                    """,
                    (
                        str(item["key_hash"]),
                        str(item.get("role", "reader")),
                        json.dumps(list(item.get("permissions", ["read"]))),
                        int(item.get("rate_limit", 60)),
                        str(item.get("created_at") or _utcnow()),
                        str(item.get("description", "")),
                        item.get("budget_capacity"),
                        item.get("budget_refill_per_minute"),
                        1 if bool(item.get("revoked", False)) else 0,
                    ),
                )

    def _seed_legacy_env_keys(self) -> bool:
        api_key = (os.environ.get("QC_API_KEY") or "").strip()
        admin_key = (os.environ.get("QC_ADMIN_KEY") or "").strip()
        if not api_key and not admin_key:
            return False
        if api_key:
            self._insert_raw_key(
                api_key,
                role="analyst",
                permissions=["read", "write", "execute"],
                rate_limit=120,
                description="legacy QC_API_KEY",
            )
        if admin_key:
            self._insert_raw_key(
                admin_key,
                role="admin",
                permissions=["read", "write", "execute", "admin"],
                rate_limit=240,
                description="legacy QC_ADMIN_KEY",
            )
        return True

    def _hash_key(self, key: str) -> str:
        return api_key_fingerprint(key, self.pepper)

    def _insert_raw_key(
        self,
        raw_key: str,
        *,
        role: str,
        permissions: List[str],
        rate_limit: int,
        description: str,
    ) -> str:
        key_hash = self._hash_key(raw_key)
        with _connect_pg() as conn:
            conn.execute(
                """
                INSERT INTO qc_api_keys (
                    key_hash, role, permissions_json, rate_limit, created_at,
                    description, revoked
                ) VALUES (%s,%s,%s,%s,%s,%s,0)
                ON CONFLICT (key_hash) DO NOTHING
                """,
                (
                    key_hash,
                    role,
                    json.dumps(permissions),
                    int(rate_limit),
                    _utcnow(),
                    description,
                ),
            )
        return key_hash

    @staticmethod
    def _meta(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "key_hash": row["key_hash"],
            "role": row["role"],
            "permissions": json.loads(row["permissions_json"]),
            "rate_limit": int(row["rate_limit"]),
            "created_at": row["created_at"],
            "description": row["description"],
            "budget_capacity": row["budget_capacity"],
            "budget_refill_per_minute": row["budget_refill_per_minute"],
            "revoked": bool(row["revoked"]),
        }

    def validate(self, presented_key: str) -> Optional[Dict[str, Any]]:
        if not presented_key:
            return None
        key_hash = self._hash_key(presented_key)
        with _connect_pg() as conn:
            row = conn.execute(
                "SELECT * FROM qc_api_keys WHERE key_hash=%s AND revoked=0",
                (key_hash,),
            ).fetchone()
        return self._meta(row) if row else None

    def generate_key(self, role: str, permissions: List[str], rate_limit: int, description: str) -> str:
        new_key = secrets.token_hex(32)
        self._insert_raw_key(
            new_key,
            role=role,
            permissions=list(permissions),
            rate_limit=int(rate_limit),
            description=description,
        )
        return new_key

    def _persist(self) -> None:
        # Mutations are committed directly; retained for gateway compatibility.
        return None

    def revoke(self, key_hash: str) -> bool:
        with _connect_pg() as conn:
            row = conn.execute(
                "UPDATE qc_api_keys SET revoked=1 WHERE key_hash=%s RETURNING key_hash",
                (key_hash,),
            ).fetchone()
        return bool(row)

    def list_keys(self) -> List[Dict[str, Any]]:
        with _connect_pg() as conn:
            rows = conn.execute("SELECT * FROM qc_api_keys ORDER BY created_at, key_hash").fetchall()
        return [self._meta(row) for row in rows]

    def probe_health(self) -> Dict[str, Any]:
        return {"healthy": True, "backend": self.backend, "key_count": self._row_count()}


class PostgresAuditLog:
    """Cross-replica tamper-evident request audit chain."""

    backend = "postgresql"
    _ADVISORY_LOCK = 72427203

    def __init__(self, file_path: str, hmac_key: str):
        del file_path
        self._hmac_key = hmac_key.encode()
        self._init_schema()

    def _init_schema(self) -> None:
        with _connect_pg() as conn:
            conn.execute(
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

    def log(
        self,
        action: str,
        source_ip: str,
        user_role: str,
        status_code: int,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with _connect_pg() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._ADVISORY_LOCK,))
            prior = conn.execute(
                "SELECT record_hash FROM qc_request_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = prior["record_hash"] if prior else "0" * 64
            entry = {
                "ts": _utcnow(),
                "request_id": getattr(g, "request_id", None),
                "action": action,
                "source_ip": source_ip,
                "user_role": user_role,
                "status_code": int(status_code),
                "details": details or {},
                "previous_hash": previous_hash,
            }
            record_hash = hashlib.sha256(_json_dumps(entry).encode()).hexdigest()
            signature = hmac.new(
                self._hmac_key,
                (record_hash + previous_hash).encode(),
                hashlib.sha256,
            ).hexdigest()
            conn.execute(
                """
                INSERT INTO qc_request_audit (
                    ts, request_id, action, source_ip, user_role, status_code,
                    details_json, previous_hash, record_hash, record_hmac
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    entry["ts"],
                    entry["request_id"],
                    action,
                    source_ip,
                    user_role,
                    int(status_code),
                    json.dumps(details or {}, sort_keys=True),
                    previous_hash,
                    record_hash,
                    signature,
                ),
            )

    @staticmethod
    def _record(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": row["ts"],
            "request_id": row["request_id"],
            "action": row["action"],
            "source_ip": row["source_ip"],
            "user_role": row["user_role"],
            "status_code": int(row["status_code"]),
            "details": json.loads(row["details_json"]),
            "previous_hash": row["previous_hash"],
            "hash": row["record_hash"],
            "hmac": row["record_hmac"],
        }

    def recent(self, count: int = 100) -> List[Dict[str, Any]]:
        count = max(1, min(int(count), 1000))
        with _connect_pg() as conn:
            rows = conn.execute(
                "SELECT * FROM qc_request_audit ORDER BY sequence DESC LIMIT %s",
                (count,),
            ).fetchall()
        return [self._record(row) for row in reversed(rows)]

    def verify_integrity(self, max_lines: int = 20000) -> Dict[str, Any]:
        limit = max(1, min(int(max_lines), 20000))
        with _connect_pg() as conn:
            rows = conn.execute(
                "SELECT * FROM qc_request_audit ORDER BY sequence ASC LIMIT %s",
                (limit,),
            ).fetchall()
        errors: List[str] = []
        previous_hash = "0" * 64
        for index, row in enumerate(rows, start=1):
            record = self._record(row)
            verify_entry = {k: v for k, v in record.items() if k not in {"hash", "hmac"}}
            expected_hash = hashlib.sha256(_json_dumps(verify_entry).encode()).hexdigest()
            expected_hmac = hmac.new(
                self._hmac_key,
                (expected_hash + previous_hash).encode(),
                hashlib.sha256,
            ).hexdigest()
            if record["previous_hash"] != previous_hash:
                errors.append(f"chain break at {index}")
            if record["hash"] != expected_hash:
                errors.append(f"hash mismatch at {index}")
            if record["hmac"] != expected_hmac:
                errors.append(f"hmac mismatch at {index}")
            previous_hash = record["hash"]
        return {"valid": not errors, "entries_checked": len(rows), "errors": errors}

    def probe_health(self) -> Dict[str, Any]:
        with _connect_pg() as conn:
            count = int(conn.execute("SELECT COUNT(*) AS n FROM qc_request_audit").fetchone()["n"])
        return {"healthy": True, "backend": self.backend, "entries": count}
