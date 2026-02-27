"""
sovereignty.crypto_approval — HMAC-Based Dual Approval (DEPRECATED v3.4)
=========================================================================

.. deprecated:: v3.4
    Superseded by ``sovereignty.approvals`` (Ed25519 + PQ-ready).
    Retained for backward compatibility only.  New code MUST use approvals.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Optional, Set

logger = logging.getLogger("sovereignty.crypto_approval")

# ─── Configuration ───────────────────────────────────────────────────────────

# Signature TTL in seconds (default 30 minutes)
APPROVAL_TTL_SEC = int(os.environ.get("QC_APPROVAL_TTL_SEC", "1800"))

# Minimum role level for approval signatures
APPROVAL_MIN_ROLE_LEVEL = int(os.environ.get("QC_APPROVAL_MIN_ROLE", "2"))  # admin+

# Role level map (mirrors action_policy.py)
ROLE_LEVELS: Dict[str, int] = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
    "system": 3,
}

# Actions requiring dual approval (containment in production)
DUAL_APPROVAL_ACTIONS: FrozenSet[str] = frozenset({
    "contain_host",
    "block_ip",
    "disable_account",
    "quarantine_file",
    "revoke_tokens",
    "rotate_credentials",
})


# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ApprovalSignature:
    """Immutable cryptographic approval token."""
    action_id: str
    decision_hash: str
    approver_id: str
    approver_role: str
    nonce: str
    timestamp: float
    signature: str  # hex-encoded HMAC-SHA256

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now or time.time()
        return (now - self.timestamp) > APPROVAL_TTL_SEC

    def to_audit_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "decision_hash": self.decision_hash[:16] + "...",
            "approver_id": self.approver_id,
            "approver_role": self.approver_role,
            "nonce": self.nonce[:8] + "...",
            "timestamp": self.timestamp,
            "expired": self.is_expired(),
            "sig_prefix": self.signature[:12] + "...",
        }


@dataclass(frozen=True)
class DualApprovalResult:
    """Result of two-person verification."""
    approved: bool
    reason: str
    action_id: str = ""
    approver_1: str = ""
    approver_2: str = ""
    verified_at: float = 0.0
    policy_rule: str = ""


# ─── Approval Store ─────────────────────────────────────────────────────────

class ApprovalStore:
    """
    Manages cryptographic approval signatures with replay protection.

    Args:
        secret_provider: Callable(approver_id) -> bytes
            Returns the HMAC secret for a given approver.
            In production, this should call a KMS or HSM.
            Default: derives from QC_APPROVAL_MASTER_SECRET env var.
        audit_fn: Optional callable for audit event logging.
    """

    def __init__(
        self,
        secret_provider: Optional[Callable[[str], bytes]] = None,
        audit_fn: Optional[Callable[[dict], None]] = None,
    ):
        self._secret_provider = secret_provider or self._default_secret_provider
        self._audit_fn = audit_fn or self._default_audit
        self._used_nonces: Set[str] = set()
        self._nonce_timestamps: Dict[str, float] = {}

    # ── Signing ──────────────────────────────────────────────────────────────

    def sign(
        self,
        action_id: str,
        decision_hash: str,
        approver_id: str,
        approver_role: str,
    ) -> ApprovalSignature:
        """
        Create a cryptographic approval signature.

        Raises:
            ValueError: if approver role is insufficient.
        """
        role_level = ROLE_LEVELS.get(approver_role, -1)
        if role_level < APPROVAL_MIN_ROLE_LEVEL:
            raise ValueError(
                f"Role '{approver_role}' (level {role_level}) insufficient "
                f"for approval (requires level {APPROVAL_MIN_ROLE_LEVEL}+)"
            )

        nonce = secrets.token_hex(16)
        timestamp = time.time()

        payload = self._canonical_payload(
            action_id, decision_hash, approver_id, nonce, timestamp
        )
        secret = self._secret_provider(approver_id)
        sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()

        token = ApprovalSignature(
            action_id=action_id,
            decision_hash=decision_hash,
            approver_id=approver_id,
            approver_role=approver_role,
            nonce=nonce,
            timestamp=timestamp,
            signature=sig,
        )

        self._audit_fn({
            "event": "approval_signed",
            "action_id": action_id,
            "approver_id": approver_id,
            "approver_role": approver_role,
            "timestamp": timestamp,
            "nonce_prefix": nonce[:8],
        })

        logger.info(
            "crypto_approval.signed: action=%s approver=%s role=%s",
            action_id, approver_id, approver_role,
        )
        return token

    # ── Single Signature Verification ────────────────────────────────────────

    def verify_single(
        self,
        token: ApprovalSignature,
        expected_action_id: str,
        expected_decision_hash: str,
    ) -> tuple[bool, str]:
        """
        Verify a single approval signature.

        Returns:
            (valid: bool, reason: str)
        """
        # Check action_id binding
        if token.action_id != expected_action_id:
            return False, f"Action ID mismatch: {token.action_id} != {expected_action_id}"

        # Check decision_hash binding (tamper detection)
        if token.decision_hash != expected_decision_hash:
            return False, "Decision hash mismatch — model output may have been tampered"

        # Check expiration
        if token.is_expired():
            elapsed = time.time() - token.timestamp
            return False, f"Signature expired ({elapsed:.0f}s > {APPROVAL_TTL_SEC}s TTL)"

        # Check replay (nonce uniqueness)
        if token.nonce in self._used_nonces:
            return False, "Nonce replay detected — signature already consumed"

        # Check role level
        role_level = ROLE_LEVELS.get(token.approver_role, -1)
        if role_level < APPROVAL_MIN_ROLE_LEVEL:
            return False, f"Approver role '{token.approver_role}' insufficient for approval"

        # Recompute HMAC
        payload = self._canonical_payload(
            token.action_id, token.decision_hash,
            token.approver_id, token.nonce, token.timestamp,
        )
        secret = self._secret_provider(token.approver_id)
        expected_sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(token.signature, expected_sig):
            logger.warning(
                "crypto_approval.INVALID_SIGNATURE: action=%s approver=%s",
                token.action_id, token.approver_id,
            )
            return False, "HMAC signature verification failed"

        return True, "Signature valid"

    # ── Dual Approval Verification ───────────────────────────────────────────

    def verify_dual(
        self,
        action_id: str,
        decision_hash: str,
        token_a: ApprovalSignature,
        token_b: ApprovalSignature,
    ) -> DualApprovalResult:
        """
        Verify that two distinct approvers have signed the same action.

        This is the ONLY method the SovereigntyExecutor should call
        for production containment actions.
        """
        now = time.time()

        # Rule 1: Separation of duties — distinct approvers
        if token_a.approver_id == token_b.approver_id:
            self._audit_fn({
                "event": "dual_approval_rejected",
                "reason": "same_approver",
                "action_id": action_id,
                "approver": token_a.approver_id,
                "timestamp": now,
            })
            return DualApprovalResult(
                approved=False,
                reason="Two-person rule violation: both signatures from same approver",
                action_id=action_id,
                policy_rule="DUAL_SAME_APPROVER",
            )

        # Rule 2: Verify signature A
        valid_a, reason_a = self.verify_single(token_a, action_id, decision_hash)
        if not valid_a:
            self._audit_fn({
                "event": "dual_approval_rejected",
                "reason": f"sig_a_invalid: {reason_a}",
                "action_id": action_id,
                "approver_a": token_a.approver_id,
                "timestamp": now,
            })
            return DualApprovalResult(
                approved=False,
                reason=f"Approver A ({token_a.approver_id}): {reason_a}",
                action_id=action_id,
                approver_1=token_a.approver_id,
                policy_rule="DUAL_SIG_A_INVALID",
            )

        # Rule 3: Verify signature B
        valid_b, reason_b = self.verify_single(token_b, action_id, decision_hash)
        if not valid_b:
            self._audit_fn({
                "event": "dual_approval_rejected",
                "reason": f"sig_b_invalid: {reason_b}",
                "action_id": action_id,
                "approver_b": token_b.approver_id,
                "timestamp": now,
            })
            return DualApprovalResult(
                approved=False,
                reason=f"Approver B ({token_b.approver_id}): {reason_b}",
                action_id=action_id,
                approver_2=token_b.approver_id,
                policy_rule="DUAL_SIG_B_INVALID",
            )

        # Both valid — consume nonces (replay prevention)
        self._used_nonces.add(token_a.nonce)
        self._used_nonces.add(token_b.nonce)
        self._nonce_timestamps[token_a.nonce] = now
        self._nonce_timestamps[token_b.nonce] = now

        # Periodic nonce cleanup (prevent unbounded growth)
        self._cleanup_expired_nonces(now)

        self._audit_fn({
            "event": "dual_approval_granted",
            "action_id": action_id,
            "approver_a": token_a.approver_id,
            "approver_a_role": token_a.approver_role,
            "approver_b": token_b.approver_id,
            "approver_b_role": token_b.approver_role,
            "decision_hash_prefix": decision_hash[:16],
            "timestamp": now,
        })

        logger.info(
            "crypto_approval.DUAL_APPROVED: action=%s approvers=(%s, %s)",
            action_id, token_a.approver_id, token_b.approver_id,
        )

        return DualApprovalResult(
            approved=True,
            reason="Dual approval verified: two distinct authorized signers confirmed",
            action_id=action_id,
            approver_1=token_a.approver_id,
            approver_2=token_b.approver_id,
            verified_at=now,
            policy_rule="DUAL_APPROVED",
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _canonical_payload(
        action_id: str,
        decision_hash: str,
        approver_id: str,
        nonce: str,
        timestamp: float,
    ) -> bytes:
        """
        Deterministic canonical form for HMAC input.
        JSON with sorted keys + separators ensures byte-exact reproducibility.
        """
        obj = {
            "action_id": action_id,
            "approver_id": approver_id,
            "decision_hash": decision_hash,
            "nonce": nonce,
            "timestamp": timestamp,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _cleanup_expired_nonces(self, now: float) -> None:
        """Remove nonces older than 2x TTL to bound memory."""
        cutoff = now - (APPROVAL_TTL_SEC * 2)
        expired = [n for n, ts in self._nonce_timestamps.items() if ts < cutoff]
        for n in expired:
            self._used_nonces.discard(n)
            del self._nonce_timestamps[n]
        if expired:
            logger.debug("crypto_approval.nonce_cleanup: removed %d expired nonces", len(expired))

    @staticmethod
    def _default_secret_provider(approver_id: str) -> bytes:
        """
        Default: derive per-approver secret from master secret.
        PRODUCTION: Replace with KMS/HSM lookup.
        """
        master = os.environ.get("QC_APPROVAL_MASTER_SECRET", "CHANGE-ME-IN-PRODUCTION")
        return hashlib.sha256(f"{master}:{approver_id}".encode("utf-8")).digest()

    @staticmethod
    def _default_audit(record: dict) -> None:
        logger.info("crypto_approval.audit: %s", json.dumps(record, default=str))


# ─── Convenience: Check if action requires dual approval ────────────────────

def requires_dual_approval(action: str, environment: str) -> bool:
    """Check if an action requires two-person cryptographic approval."""
    return action in DUAL_APPROVAL_ACTIONS and environment == "prod"
