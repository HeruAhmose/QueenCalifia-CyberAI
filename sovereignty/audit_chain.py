"""
sovereignty.audit_chain — Hash-Chained Tamper-Evident Audit Records
====================================================================

Each record includes a record_hash and a chain_hash linking it to all previous
records. PostgreSQL mode serializes append authority across replicas with a
transaction-scoped advisory lock so sequence and predecessor cannot fork.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.database import database_backend, database_url
from sovereignty.storage_paths import resolve_configured_sqlite_path

logger = logging.getLogger("sovereignty.audit_chain")

AUDIT_HASH_ALG = os.environ.get("QC_AUDIT_HASH_ALG", "sha256")
GENESIS_HASH = "0" * 64
_POSTGRES_AUDIT_CHAIN_LOCK = 72427202


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    timestamp: float
    record: Dict[str, Any]
    record_hash: str
    prev_chain_hash: str
    chain_hash: str
    hash_alg: str = "sha256"

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "record": self.record,
            "record_hash": self.record_hash,
            "prev_chain_hash": self.prev_chain_hash,
            "chain_hash": self.chain_hash,
            "hash_alg": self.hash_alg,
        }


def _hash_bytes(data: bytes, alg: str = "sha256") -> str:
    return hashlib.new(alg, data).hexdigest()


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_record_hash(record: dict, alg: str = "sha256") -> str:
    return _hash_bytes(_canonical_json(record), alg)


def compute_chain_hash(prev: str, record_hash: str, alg: str = "sha256") -> str:
    return _hash_bytes(f"{prev}:{record_hash}".encode("utf-8"), alg)


class AuditChain:
    """Append-only, hash-chained, thread-safe in-memory audit log."""

    def __init__(
        self,
        hash_alg: Optional[str] = None,
        persist_fn: Optional[Callable[[AuditEntry], None]] = None,
    ):
        self._lock = threading.RLock()
        self._hash_alg = hash_alg or AUDIT_HASH_ALG
        self._persist_fn = persist_fn
        self._entries: List[AuditEntry] = []
        self._head = GENESIS_HASH

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def head_hash(self) -> str:
        with self._lock:
            return self._head

    def append(self, record: Dict[str, Any]) -> AuditEntry:
        with self._lock:
            seq = len(self._entries)
            ts = time.time()
            rh = compute_record_hash(record, self._hash_alg)
            ch = compute_chain_hash(self._head, rh, self._hash_alg)
            entry = AuditEntry(
                sequence=seq,
                timestamp=ts,
                record=record,
                record_hash=rh,
                prev_chain_hash=self._head,
                chain_hash=ch,
                hash_alg=self._hash_alg,
            )
            self._entries.append(entry)
            self._head = ch
            if self._persist_fn:
                try:
                    self._persist_fn(entry)
                except Exception as exc:
                    logger.error("audit_chain.persist_failed: seq=%d: %s", seq, exc)
            return entry

    def verify(self) -> tuple[bool, Optional[int]]:
        with self._lock:
            prev = GENESIS_HASH
            for i, e in enumerate(self._entries):
                expected_rh = compute_record_hash(e.record, e.hash_alg)
                if e.record_hash != expected_rh:
                    return False, i
                if e.prev_chain_hash != prev:
                    return False, i
                expected_ch = compute_chain_hash(prev, e.record_hash, e.hash_alg)
                if e.chain_hash != expected_ch:
                    return False, i
                prev = e.chain_hash
            return True, None

    def verify_entry(self, index: int) -> bool:
        with self._lock:
            if index < 0 or index >= len(self._entries):
                return False
            e = self._entries[index]
            if e.record_hash != compute_record_hash(e.record, e.hash_alg):
                return False
            prev = GENESIS_HASH if index == 0 else self._entries[index - 1].chain_hash
            if e.prev_chain_hash != prev:
                return False
            return e.chain_hash == compute_chain_hash(prev, e.record_hash, e.hash_alg)

    def get_entry(self, index: int) -> Optional[AuditEntry]:
        with self._lock:
            return self._entries[index] if 0 <= index < len(self._entries) else None

    def export_chain(self) -> List[dict]:
        with self._lock:
            return [e.to_dict() for e in self._entries]


class SQLiteAuditChain(AuditChain):
    """Durable audit chain backed by SQLite for local/single-writer use."""

    def __init__(self, db_path: str, hash_alg: Optional[str] = None):
        self._db_path = Path(db_path).expanduser().resolve()
        super().__init__(hash_alg=hash_alg, persist_fn=self._persist_entry)
        self._init_db()
        self._load_chain()

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS qc_audit_chain (sequence INTEGER PRIMARY KEY, timestamp REAL NOT NULL, record_json TEXT NOT NULL, record_hash TEXT NOT NULL, prev_chain_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, hash_alg TEXT NOT NULL)"
            )

    def _load_chain(self) -> None:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT sequence, timestamp, record_json, record_hash, prev_chain_hash, chain_hash, hash_alg FROM qc_audit_chain ORDER BY sequence ASC"
                ).fetchall()
            self._entries = [
                AuditEntry(
                    sequence=int(row["sequence"]),
                    timestamp=float(row["timestamp"]),
                    record=json.loads(row["record_json"]),
                    record_hash=row["record_hash"],
                    prev_chain_hash=row["prev_chain_hash"],
                    chain_hash=row["chain_hash"],
                    hash_alg=row["hash_alg"],
                )
                for row in rows
            ]
            self._head = self._entries[-1].chain_hash if self._entries else GENESIS_HASH

    def _persist_entry(self, entry: AuditEntry) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO qc_audit_chain (sequence, timestamp, record_json, record_hash, prev_chain_hash, chain_hash, hash_alg) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.sequence,
                    entry.timestamp,
                    json.dumps(entry.record, sort_keys=True, separators=(",", ":"), default=str),
                    entry.record_hash,
                    entry.prev_chain_hash,
                    entry.chain_hash,
                    entry.hash_alg,
                ),
            )


class PostgresAuditChain(AuditChain):
    """PostgreSQL-backed audit chain with cross-replica serialized appends."""

    def __init__(self, url: str, hash_alg: Optional[str] = None):
        if not url:
            raise ValueError("PostgreSQL audit chain requires a database URL")
        self._url = url
        super().__init__(hash_alg=hash_alg)
        self._init_db()
        self._refresh()

    def _connect(self):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(self._url, row_factory=dict_row)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS qc_audit_chain (sequence BIGINT PRIMARY KEY, timestamp DOUBLE PRECISION NOT NULL, record_json TEXT NOT NULL, record_hash TEXT NOT NULL, prev_chain_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, hash_alg TEXT NOT NULL)"
            )

    def _read_entries(self) -> List[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT sequence, timestamp, record_json, record_hash, prev_chain_hash, chain_hash, hash_alg FROM qc_audit_chain ORDER BY sequence ASC"
            ).fetchall()
        return [
            AuditEntry(
                sequence=int(row["sequence"]),
                timestamp=float(row["timestamp"]),
                record=json.loads(row["record_json"]),
                record_hash=row["record_hash"],
                prev_chain_hash=row["prev_chain_hash"],
                chain_hash=row["chain_hash"],
                hash_alg=row["hash_alg"],
            )
            for row in rows
        ]

    def _refresh(self) -> None:
        entries = self._read_entries()
        with self._lock:
            self._entries = entries
            self._head = entries[-1].chain_hash if entries else GENESIS_HASH

    def append(self, record: Dict[str, Any]) -> AuditEntry:
        with self._connect() as conn:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_POSTGRES_AUDIT_CHAIN_LOCK,))
                last = conn.execute(
                    "SELECT sequence, chain_hash FROM qc_audit_chain ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                seq = int(last["sequence"]) + 1 if last else 0
                prev = last["chain_hash"] if last else GENESIS_HASH
                ts = time.time()
                rh = compute_record_hash(record, self._hash_alg)
                ch = compute_chain_hash(prev, rh, self._hash_alg)
                entry = AuditEntry(
                    sequence=seq,
                    timestamp=ts,
                    record=record,
                    record_hash=rh,
                    prev_chain_hash=prev,
                    chain_hash=ch,
                    hash_alg=self._hash_alg,
                )
                conn.execute(
                    "INSERT INTO qc_audit_chain (sequence, timestamp, record_json, record_hash, prev_chain_hash, chain_hash, hash_alg) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        entry.sequence,
                        entry.timestamp,
                        json.dumps(entry.record, sort_keys=True, separators=(",", ":"), default=str),
                        entry.record_hash,
                        entry.prev_chain_hash,
                        entry.chain_hash,
                        entry.hash_alg,
                    ),
                )
        self._refresh()
        return entry

    @property
    def length(self) -> int:
        self._refresh()
        return super().length

    @property
    def head_hash(self) -> str:
        self._refresh()
        return super().head_hash

    def verify(self) -> tuple[bool, Optional[int]]:
        self._refresh()
        return super().verify()

    def verify_entry(self, index: int) -> bool:
        self._refresh()
        return super().verify_entry(index)

    def get_entry(self, index: int) -> Optional[AuditEntry]:
        self._refresh()
        return super().get_entry(index)

    def export_chain(self) -> List[dict]:
        self._refresh()
        return super().export_chain()


def build_default_audit_chain() -> AuditChain:
    production = os.environ.get("QC_PRODUCTION") == "1"
    if database_backend() == "postgresql":
        try:
            return PostgresAuditChain(database_url())
        except Exception as exc:
            logger.error("audit_chain.postgresql_init_failed: %s", exc)
            if production:
                raise
            return AuditChain()

    raw_path = os.environ.get("QC_AUDIT_CHAIN_DB") or os.environ.get("QC_DB_PATH")
    try:
        db_path = resolve_configured_sqlite_path(raw_path, "audit-chain database", production=production)
    except Exception as exc:
        logger.error("audit_chain.sqlite_destination_invalid: %s", exc)
        if production:
            raise
        return AuditChain()
    if db_path is None:
        return AuditChain()
    try:
        return SQLiteAuditChain(str(db_path))
    except Exception as exc:
        logger.error("audit_chain.sqlite_init_failed: %s", exc)
        if production:
            raise
        return AuditChain()
