"""
sovereignty.audit_chain — Hash-Chained Tamper-Evident Audit Records
====================================================================

Each record includes a record_hash and a chain_hash linking it to all
previous records.  Breaking the chain requires modifying every
subsequent record.

Design:
  record_hash = H(canonical_json(record))
  chain_hash  = H(prev_chain_hash || record_hash)

Hash Agility: QC_AUDIT_HASH_ALG (sha256, sha512, sha3_256)
Export: chain can be anchored to immutable storage (S3 Object Lock, WORM)

Usage:
    chain = AuditChain()
    entry = chain.append({"event": "action_executed", ...})
    valid, bad_idx = chain.verify()  # True, None if intact
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("sovereignty.audit_chain")

AUDIT_HASH_ALG = os.environ.get("QC_AUDIT_HASH_ALG", "sha256")
GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    """Immutable audit record with hash chain linkage."""
    sequence: int
    timestamp: float
    record: Dict[str, Any]
    record_hash: str
    prev_chain_hash: str
    chain_hash: str
    hash_alg: str = "sha256"

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence, "timestamp": self.timestamp,
            "record": self.record, "record_hash": self.record_hash,
            "prev_chain_hash": self.prev_chain_hash,
            "chain_hash": self.chain_hash, "hash_alg": self.hash_alg,
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
    """Append-only, hash-chained, thread-safe audit log."""

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
                sequence=seq, timestamp=ts, record=record,
                record_hash=rh, prev_chain_hash=self._head,
                chain_hash=ch, hash_alg=self._hash_alg,
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
        """Verify full chain. Returns (valid, first_bad_index)."""
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
