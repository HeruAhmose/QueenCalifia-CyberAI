"""
sovereignty.approvals — Ed25519 + Post-Quantum Ready Approval System
=====================================================================

Asymmetric cryptographic approval replacing the v3.3 HMAC approach.
Each approver signs (decision_hash:nonce) with their Ed25519 private key.
The server verifies against registered public keys.

Crypto-Agility:
  Classical:       Ed25519 (production-ready via cryptography library)
  Post-quantum:    Dilithium via plugin hook (QC_PQ_VERIFY_HOOK)
  Hybrid policy:   Require BOTH classical+PQ per approver (QC_REQUIRE_HYBRID_SIGNATURES=1)
  Hash agility:    SHA-256 now, configurable (QC_AUDIT_HASH_ALG)

Two-Person Rule:
  - Enforced: distinct approver_id values in signatures
  - Enforced: requested_by ≠ executor actor_id
  - Minimum 2 valid signatures for prod containment

Key Management:
  Dev/test:   in-memory KeyRegistry
  Production: KMS/HSM (set QC_PQ_VERIFY_HOOK for PQ, use HSM for Ed25519)
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set
from pathlib import Path

from sovereignty.schemas import (
    ApprovalRecord,
    ApprovalSignature,
    HybridSignaturePolicy,
    SignatureAlg,
)

logger = logging.getLogger("sovereignty.approvals")

# ─── Crypto Backend ──────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    HAS_ED25519 = True
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    HAS_ED25519 = False


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"), validate=True)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def _approval_message(decision_hash: str, nonce: str) -> bytes:
    """Message signed by approvers — binds to decision + nonce."""
    return f"{decision_hash}:{nonce}".encode("utf-8")


# ─── Key Registry ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PublicKeyRecord:
    key_id: str
    alg: SignatureAlg
    owner_id: str
    public_key_b64: str


class KeyRegistry:
    """Minimal key registry. Replace with KMS/HSM lookup in production."""

    def __init__(self, keys: Sequence[PublicKeyRecord] = ()):
        self._map: Dict[tuple, PublicKeyRecord] = {}
        for k in keys:
            self._map[(k.key_id, k.alg)] = k

    def get(self, key_id: str, alg: SignatureAlg) -> Optional[PublicKeyRecord]:
        return self._map.get((key_id, alg))

    def register(self, key: PublicKeyRecord) -> None:
        self._map[(key.key_id, key.alg)] = key

    def remove(self, key_id: str, alg: SignatureAlg) -> bool:
        return self._map.pop((key_id, alg), None) is not None


# ─── Signature Verification ──────────────────────────────────────────────────

def verify_signature(
    *, key_registry: KeyRegistry, decision_hash: str, nonce: str, sig: ApprovalSignature,
) -> bool:
    """Verify a single cryptographic signature against the registry."""
    msg = _approval_message(decision_hash, nonce)

    if sig.alg == SignatureAlg.ed25519:
        return _verify_ed25519(key_registry, msg, sig)

    return _verify_pq_hook(decision_hash, nonce, sig)


def _verify_ed25519(registry: KeyRegistry, msg: bytes, sig: ApprovalSignature) -> bool:
    if not HAS_ED25519 or Ed25519PublicKey is None:
        logger.error("approvals.verify: Ed25519 backend unavailable")
        return False
    k = registry.get(sig.key_id, sig.alg)
    if not k:
        logger.warning("approvals.verify: key_id=%s not found", sig.key_id)
        return False
    if k.owner_id != sig.approver_id:
        logger.warning("approvals.verify: key owner %s != signer %s", k.owner_id, sig.approver_id)
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64d(k.public_key_b64))
        pub.verify(_b64d(sig.signature_b64), msg)
        return True
    except Exception as exc:
        logger.warning("approvals.verify: Ed25519 failed: %s", exc)
        return False


def _verify_pq_hook(decision_hash: str, nonce: str, sig: ApprovalSignature) -> bool:
    """Post-quantum verification via external hook (QC_PQ_VERIFY_HOOK)."""
    hook = os.environ.get("QC_PQ_VERIFY_HOOK", "").strip()
    if not hook:
        logger.warning("approvals.verify_pq: no hook for alg=%s", sig.alg)
        return False
    mod_name, _, fn_name = hook.partition(":")
    if not mod_name or not fn_name:
        return False
    try:
        mod = __import__(mod_name, fromlist=[fn_name])
        fn = getattr(mod, fn_name)
        return bool(fn(decision_hash=decision_hash, nonce=nonce, signature=sig.model_dump()))
    except Exception as exc:
        logger.error("approvals.verify_pq: hook failed: %s", exc)
        return False


# ─── Hybrid Signature Enforcement ────────────────────────────────────────────

def check_hybrid_requirement(
    signatures: List[ApprovalSignature],
    approver_id: str,
    policy: Optional[HybridSignaturePolicy] = None,
) -> tuple[bool, str]:
    """
    When hybrid mode is on, each approver must provide BOTH a classical
    AND a post-quantum signature.  Returns (satisfied, reason).
    """
    pol = policy or HybridSignaturePolicy()
    if not pol.require_hybrid:
        return True, "Hybrid not required"

    sigs_by_approver = [s for s in signatures if s.approver_id == approver_id]
    has_classical = any(s.alg in pol.classical_algs for s in sigs_by_approver)
    has_pq = any(s.alg in pol.pq_algs for s in sigs_by_approver)

    if has_classical and has_pq:
        return True, "Hybrid satisfied (classical + PQ)"
    if not has_classical:
        return False, f"Missing classical signature ({pol.classical_algs}) from {approver_id}"
    return False, f"Missing PQ signature ({pol.pq_algs}) from {approver_id}"


# ─── Ed25519 Signing Helper (dev/test) ──────────────────────────────────────

def sign_approval_ed25519(
    *, private_key: "Ed25519PrivateKey",
    key_id: str, approver_id: str, decision_hash: str, nonce: str,
) -> ApprovalSignature:
    """Dev/test convenience. In production, signing is client-side or HSM."""
    msg = _approval_message(decision_hash, nonce)
    sig_bytes = private_key.sign(msg)
    return ApprovalSignature(
        approver_id=approver_id,
        key_id=key_id,
        alg=SignatureAlg.ed25519,
        signature_b64=_b64e(sig_bytes),
    )


# ─── Approval Store ─────────────────────────────────────────────────────────

class ApprovalStore:
    """Abstract store. Replace with DB-backed implementation in production."""

    def create(self, *, tenant_id: str, decision_hash: str, requested_by: str, ttl_sec: int = 900) -> ApprovalRecord:
        raise NotImplementedError

    def add_signature(self, approval_id: str, sig: ApprovalSignature) -> ApprovalRecord:
        raise NotImplementedError

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        raise NotImplementedError

    def revoke(self, approval_id: str) -> bool:
        raise NotImplementedError

    def mark_nonce_used(self, nonce: str) -> bool:
        """Return False if nonce already used (replay)."""
        raise NotImplementedError


class InMemoryApprovalStore(ApprovalStore):
    """Thread-safe in-memory store for dev/test."""

    def __init__(self):
        self._lock = threading.RLock()
        self._approvals: Dict[str, ApprovalRecord] = {}
        self._used_nonces: Set[str] = set()
        self._nonce_ts: Dict[str, float] = {}

    def create(self, *, tenant_id: str, decision_hash: str, requested_by: str, ttl_sec: int = 900) -> ApprovalRecord:
        with self._lock:
            aid = secrets.token_urlsafe(16)
            nonce = secrets.token_urlsafe(16)
            now = time.time()
            rec = ApprovalRecord(
                approval_id=aid, tenant_id=tenant_id,
                decision_hash=decision_hash, requested_by=requested_by,
                created_at=now, expires_at=now + float(ttl_sec), nonce=nonce,
            )
            self._approvals[aid] = rec
            logger.info("approvals.created: id=%s by=%s ttl=%ds", aid, requested_by, ttl_sec)
            return rec

    def add_signature(self, approval_id: str, sig: ApprovalSignature) -> ApprovalRecord:
        with self._lock:
            rec = self._approvals.get(approval_id)
            if not rec:
                raise KeyError(f"Approval {approval_id} not found")
            now = time.time()
            if rec.revoked:
                raise ValueError(f"Approval {approval_id} is revoked")
            if rec.expires_at < now:
                raise ValueError(f"Approval {approval_id} has expired")
            existing = {s.approver_id for s in rec.signatures if s.alg == sig.alg}
            if sig.approver_id in existing:
                raise ValueError(f"Approver {sig.approver_id} already signed with {sig.alg}")
            rec.signatures.append(sig)
            self._approvals[approval_id] = rec
            logger.info("approvals.sig_added: id=%s by=%s alg=%s total=%d",
                        approval_id, sig.approver_id, sig.alg, len(rec.signatures))
            return rec

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        with self._lock:
            return self._approvals.get(approval_id)

    def revoke(self, approval_id: str) -> bool:
        with self._lock:
            rec = self._approvals.get(approval_id)
            if not rec:
                return False
            rec.revoked = True
            rec.revoked_at = time.time()
            self._approvals[approval_id] = rec
            return True

    def mark_nonce_used(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._used_nonces:
                return False
            self._used_nonces.add(nonce)
            self._nonce_ts[nonce] = time.time()
            self._cleanup()
            return True

    def _cleanup(self) -> None:
        cutoff = time.time() - 7200
        expired = [n for n, ts in self._nonce_ts.items() if ts < cutoff]
        for n in expired:
            self._used_nonces.discard(n)
            del self._nonce_ts[n]


class SQLiteApprovalStore(ApprovalStore):
    """Durable approval store backed by SQLite."""

    def __init__(self, db_path: str):
        self._lock = threading.RLock()
        self._db_path = Path(db_path).expanduser().resolve()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_approval_records (
                    approval_id TEXT PRIMARY KEY,
                    approval_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_used_nonces (
                    nonce TEXT PRIMARY KEY,
                    used_at REAL NOT NULL
                )
                """
            )

    def _write_record(self, rec: ApprovalRecord) -> ApprovalRecord:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO qc_approval_records (approval_id, approval_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(approval_id) DO UPDATE SET
                    approval_json=excluded.approval_json,
                    updated_at=excluded.updated_at
                """,
                (rec.approval_id, rec.model_dump_json(), time.time()),
            )
        return rec

    def create(self, *, tenant_id: str, decision_hash: str, requested_by: str, ttl_sec: int = 900) -> ApprovalRecord:
        with self._lock:
            now = time.time()
            rec = ApprovalRecord(
                approval_id=secrets.token_urlsafe(16),
                tenant_id=tenant_id,
                decision_hash=decision_hash,
                requested_by=requested_by,
                created_at=now,
                expires_at=now + float(ttl_sec),
                nonce=secrets.token_urlsafe(16),
            )
            logger.info("approvals.created: id=%s by=%s ttl=%ds", rec.approval_id, requested_by, ttl_sec)
            return self._write_record(rec)

    def add_signature(self, approval_id: str, sig: ApprovalSignature) -> ApprovalRecord:
        with self._lock:
            rec = self.get(approval_id)
            if not rec:
                raise KeyError(f"Approval {approval_id} not found")
            now = time.time()
            if rec.revoked:
                raise ValueError(f"Approval {approval_id} is revoked")
            if rec.expires_at < now:
                raise ValueError(f"Approval {approval_id} has expired")
            existing = {s.approver_id for s in rec.signatures if s.alg == sig.alg}
            if sig.approver_id in existing:
                raise ValueError(f"Approver {sig.approver_id} already signed with {sig.alg}")
            rec.signatures.append(sig)
            logger.info(
                "approvals.sig_added: id=%s by=%s alg=%s total=%d",
                approval_id,
                sig.approver_id,
                sig.alg,
                len(rec.signatures),
            )
            return self._write_record(rec)

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT approval_json FROM qc_approval_records WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
            if not row:
                return None
            return ApprovalRecord.model_validate_json(row["approval_json"])

    def revoke(self, approval_id: str) -> bool:
        with self._lock:
            rec = self.get(approval_id)
            if not rec:
                return False
            rec.revoked = True
            rec.revoked_at = time.time()
            self._write_record(rec)
            return True

    def mark_nonce_used(self, nonce: str) -> bool:
        with self._lock:
            now = time.time()
            cutoff = now - 7200
            with self._connect() as conn:
                conn.execute("DELETE FROM qc_used_nonces WHERE used_at < ?", (cutoff,))
                exists = conn.execute(
                    "SELECT 1 FROM qc_used_nonces WHERE nonce = ?",
                    (nonce,),
                ).fetchone()
                if exists:
                    return False
                conn.execute(
                    "INSERT INTO qc_used_nonces (nonce, used_at) VALUES (?, ?)",
                    (nonce, now),
                )
            return True


def build_default_approval_store() -> ApprovalStore:
    db_path = os.environ.get("QC_APPROVALS_DB") or os.environ.get("QC_DB_PATH")
    if db_path:
        try:
            return SQLiteApprovalStore(db_path)
        except Exception as exc:
            logger.error("approvals.store: failed to initialize sqlite store: %s", exc)
    return InMemoryApprovalStore()


# ─── Convenience ─────────────────────────────────────────────────────────────

DUAL_APPROVAL_ACTIONS = frozenset({
    "contain_host", "block_ip", "disable_account",
    "quarantine_file", "revoke_tokens", "rotate_credentials",
    "isolate_network_segment",
})


def requires_dual_approval(action: str, environment: str) -> bool:
    return action in DUAL_APPROVAL_ACTIONS and environment == "prod"
