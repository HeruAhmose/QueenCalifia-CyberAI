"""
sovereignty.executor — Audit-First Action Execution Engine
============================================================

The SovereigntyExecutor is the ONLY authorized path for executing
state-changing actions in QueenCalifia CyberAI.

v3.4 execution flow:
  1. Policy evaluation (ActionPolicy)
  2. Confidence check (hard floor)
  3. Approval verification — full cryptographic validation:
     a. Record exists, not revoked/expired
     b. Decision-hash binding (tamper detection)
     c. Two-person rule (requester ≠ executor)
     d. Nonce replay prevention
     e. Ed25519/PQ signature verification
     f. Threshold (≥2 distinct approvers for prod containment)
     g. Hybrid policy check (classical+PQ if enabled)
  4. Idempotency guard (REQUIRED for containment)
  5. AUDIT RECORD (hash-chained, written BEFORE execution)
  6. Dry-run check (default in production)
  7. Action dispatch + post-execution audit
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Callable, Dict, Optional, Set

from sovereignty.action_policy import ActionPolicy, PolicyDecision
from sovereignty.approvals import (
    ApprovalStore,
    build_default_approval_store,
    KeyRegistry,
    check_hybrid_requirement,
    verify_signature,
)
from sovereignty.audit_chain import AuditChain, build_default_audit_chain
from sovereignty.schemas import ActionRequest, HybridSignaturePolicy, ProposedAction

logger = logging.getLogger("sovereignty.executor")


class SovereigntyError(RuntimeError):
    """Raised when the sovereignty layer blocks an action."""
    def __init__(self, message: str, policy_rule: str = "", decision_dump: Optional[dict] = None):
        super().__init__(message)
        self.policy_rule = policy_rule
        self.decision_dump = decision_dump or {}


def stable_hash(obj: dict) -> str:
    """Deterministic SHA-256 hash for tamper detection."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class SovereigntyExecutor:
    """
    Central execution engine.  All action requests flow through here.

    v3.4 constructor adds:
      - approval_store: Ed25519 approval store
      - key_registry: public key registry for verification
      - audit_chain: hash-chained audit log
      - hybrid_policy: classical+PQ enforcement toggle
    """

    def __init__(
        self,
        policy: Optional[ActionPolicy] = None,
        audit_write_fn: Optional[Callable[[Dict], None]] = None,
        idempotency_check_fn: Optional[Callable[[ActionRequest], bool]] = None,
        action_dispatch_fn: Optional[Callable[[ActionRequest], Dict]] = None,
        approval_store: Optional[ApprovalStore] = None,
        key_registry: Optional[KeyRegistry] = None,
        audit_chain: Optional[AuditChain] = None,
        hybrid_policy: Optional[HybridSignaturePolicy] = None,
    ):
        self.policy = policy or ActionPolicy()
        self.audit_write_fn = audit_write_fn or self._default_audit
        self.idempotency_check_fn = idempotency_check_fn
        self.action_dispatch_fn = action_dispatch_fn or self._default_dispatch
        self.approval_store = approval_store or build_default_approval_store()
        self.key_registry = key_registry or KeyRegistry()
        self.audit_chain = audit_chain or build_default_audit_chain()
        self.hybrid_policy = hybrid_policy or HybridSignaturePolicy()

    # ── Main Execution Path ──────────────────────────────────────────────────

    def execute(self, req: ActionRequest) -> Dict[str, Any]:
        start_time = time.monotonic()
        decision_dump = req.decision.model_dump()

        # Step 1: Policy evaluation
        policy_result = self.policy.evaluate(req)
        if not policy_result.allowed:
            self._write_audit(req, policy_result, "DENIED", decision_dump)
            raise SovereigntyError(
                f"Policy denied: {policy_result.reason}",
                policy_rule=policy_result.policy_rule,
                decision_dump=decision_dump,
            )

        # Step 2: Confidence enforcement
        if req.decision.confidence < policy_result.min_confidence:
            self._write_audit(req, policy_result, "CONFIDENCE_DENIED", decision_dump)
            raise SovereigntyError(
                f"Confidence {req.decision.confidence:.3f} below floor "
                f"{policy_result.min_confidence:.3f} ({policy_result.reason})",
                policy_rule="CONFIDENCE_HARD_FLOOR",
                decision_dump=decision_dump,
            )

        # Step 3: Approval verification (full cryptographic validation)
        if policy_result.requires_approval and not req.approval_id:
            self._write_audit(req, policy_result, "APPROVAL_REQUIRED", decision_dump)
            raise SovereigntyError(
                "Approval required for this action in production. "
                "Submit via /api/incidents/<id>/approve/<action_id>",
                policy_rule="APPROVAL_GATE",
                decision_dump=decision_dump,
            )

        if policy_result.requires_approval and req.approval_id:
            self._verify_approval(req=req, policy=policy_result, decision_dump=decision_dump)

        # Step 4: Idempotency guard (REQUIRED for containment actions)
        is_containment = req.decision.action in ProposedAction.containment_actions()
        if is_containment and self.idempotency_check_fn is None:
            self._write_audit(req, policy_result, "IDEMPOTENCY_GUARD_MISSING", decision_dump)
            raise SovereigntyError(
                "Idempotency guard required for containment actions but not configured",
                policy_rule="IDEMPOTENCY_GUARD_REQUIRED",
                decision_dump=decision_dump,
            )

        if self.idempotency_check_fn and self.idempotency_check_fn(req):
            self._write_audit(req, policy_result, "IDEMPOTENT_SKIP", decision_dump)
            return {
                "status": "skipped",
                "reason": "idempotent_action_already_applied",
                "action": req.decision.action.value,
            }

        # Step 5: AUDIT RECORD (hash-chained, written BEFORE execution)
        self._write_audit(req, policy_result, "EXECUTING" if not req.dry_run else "DRY_RUN", decision_dump)

        # Step 6: Dry-run check
        if req.dry_run and is_containment:
            logger.info("sovereignty.dry_run: action=%s targets=%s",
                        req.decision.action.value, req.decision.targets[:3])
            return {
                "status": "dry_run",
                "would_execute": req.decision.action.value,
                "targets": req.decision.targets,
                "confidence": req.decision.confidence,
                "policy_rule": policy_result.policy_rule,
                "message": "Dry-run mode active. Set dry_run=False or QC_CONTAINMENT_MODE=auto to execute.",
            }

        # Step 7: Action dispatch
        try:
            result = self.action_dispatch_fn(req)
        except Exception as exc:
            self._write_audit(req, policy_result, "DISPATCH_FAILED", decision_dump, error=str(exc))
            raise

        elapsed = time.monotonic() - start_time
        self._write_audit(req, policy_result, "EXECUTED", decision_dump, elapsed=elapsed)

        return {
            "status": "executed",
            "action": req.decision.action.value,
            "targets": req.decision.targets,
            "result": result,
            "elapsed_sec": round(elapsed, 4),
            "policy_rule": policy_result.policy_rule,
        }

    # ── Cryptographic Approval Verification ──────────────────────────────────

    def _verify_approval(self, *, req: ActionRequest, policy: PolicyDecision, decision_dump: dict) -> None:
        """
        Full 7-step cryptographic approval verification.
        """
        rec = self.approval_store.get(req.approval_id or "")

        # 1. Record must exist
        if not rec:
            self._write_audit(req, policy, "APPROVAL_INVALID", decision_dump)
            raise SovereigntyError("Invalid approval_id", policy_rule="APPROVAL_INVALID", decision_dump=decision_dump)

        now = time.time()

        # 2. Not revoked or expired
        if rec.revoked:
            self._write_audit(req, policy, "APPROVAL_REVOKED", decision_dump)
            raise SovereigntyError("Approval has been revoked", policy_rule="APPROVAL_REVOKED", decision_dump=decision_dump)

        if rec.expires_at < now:
            self._write_audit(req, policy, "APPROVAL_EXPIRED", decision_dump)
            raise SovereigntyError(
                f"Approval expired ({now - rec.expires_at:.0f}s ago)",
                policy_rule="APPROVAL_EXPIRED", decision_dump=decision_dump,
            )

        # 3. Decision hash binding (tamper detection)
        expected_hash = stable_hash(decision_dump)
        if rec.decision_hash != expected_hash:
            self._write_audit(req, policy, "APPROVAL_HASH_MISMATCH", decision_dump)
            raise SovereigntyError(
                "Approval does not match this action (hash mismatch)",
                policy_rule="APPROVAL_HASH_MISMATCH", decision_dump=decision_dump,
            )

        # 4. Two-person rule: requester cannot execute
        if req.actor_id and rec.requested_by == req.actor_id:
            self._write_audit(req, policy, "APPROVAL_TWO_PERSON_VIOLATION", decision_dump)
            raise SovereigntyError(
                "Two-person rule violation (requester cannot execute)",
                policy_rule="APPROVAL_TWO_PERSON_VIOLATION", decision_dump=decision_dump,
            )

        # 5. Nonce replay prevention
        if not self.approval_store.mark_nonce_used(rec.nonce):
            self._write_audit(req, policy, "APPROVAL_REPLAY_DETECTED", decision_dump)
            raise SovereigntyError(
                "Approval replay detected (nonce reuse)",
                policy_rule="APPROVAL_REPLAY_DETECTED", decision_dump=decision_dump,
            )

        # 6. Verify cryptographic signatures + count valid approvers
        is_containment = req.decision.action in ProposedAction.containment_actions()
        required = 2 if (req.environment == "prod" and is_containment) else 1

        valid_approvers: Set[str] = set()
        for sig in rec.signatures:
            if req.actor_id and sig.approver_id == req.actor_id:
                continue  # executor cannot count as approver
            if verify_signature(
                key_registry=self.key_registry,
                decision_hash=rec.decision_hash,
                nonce=rec.nonce, sig=sig,
            ):
                valid_approvers.add(sig.approver_id)

        if len(valid_approvers) < required:
            self._write_audit(req, policy, "APPROVAL_INSUFFICIENT", decision_dump)
            raise SovereigntyError(
                f"Insufficient approvals: have {len(valid_approvers)}, require {required}",
                policy_rule="APPROVAL_INSUFFICIENT", decision_dump=decision_dump,
            )

        # 7. Hybrid policy check (classical + PQ if enabled)
        if self.hybrid_policy.require_hybrid:
            for approver in valid_approvers:
                satisfied, reason = check_hybrid_requirement(
                    rec.signatures, approver, self.hybrid_policy,
                )
                if not satisfied:
                    self._write_audit(req, policy, "APPROVAL_HYBRID_MISSING", decision_dump)
                    raise SovereigntyError(
                        f"Hybrid signature requirement not met: {reason}",
                        policy_rule="APPROVAL_HYBRID_MISSING", decision_dump=decision_dump,
                    )

        logger.info("sovereignty.approval_verified: id=%s approvers=%s",
                     req.approval_id, sorted(valid_approvers))

    # ── Audit Helpers ────────────────────────────────────────────────────────

    def _write_audit(
        self, req: ActionRequest, policy: PolicyDecision, outcome: str,
        decision_dump: dict, error: Optional[str] = None, elapsed: Optional[float] = None,
    ):
        record = {
            "timestamp": time.time(),
            "outcome": outcome,
            "tenant_id": req.tenant_id,
            "trace_id": req.trace_id,
            "request_id": req.request_id,
            "actor_id": req.actor_id,
            "actor_role": req.actor_role,
            "environment": req.environment,
            "dry_run": req.dry_run,
            "approval_id": req.approval_id,
            "action": req.decision.action.value,
            "confidence": req.decision.confidence,
            "risk": req.decision.risk.value,
            "targets": req.decision.targets[:10],
            "decision_hash": stable_hash(decision_dump),
            "policy_rule": policy.policy_rule,
            "policy_reason": policy.reason[:500],
            "min_confidence": policy.min_confidence,
        }
        if error:
            record["error"] = error[:500]
        if elapsed is not None:
            record["elapsed_sec"] = round(elapsed, 4)

        # Hash-chain
        try:
            self.audit_chain.append(record)
        except Exception as exc:
            logger.warning("sovereignty.audit_chain_append_failed: %s", exc)

        try:
            self.audit_write_fn(record)
        except Exception as exc:
            logger.critical("sovereignty.AUDIT_WRITE_FAILED: outcome=%s error=%s", outcome, exc)
            if outcome in ("EXECUTING", "DRY_RUN"):
                raise SovereigntyError(
                    "Audit write failed — action blocked for safety",
                    policy_rule="AUDIT_FAILURE_BLOCK",
                ) from exc

    @staticmethod
    def _default_audit(record: dict) -> None:
        logger.info("sovereignty.audit: %s", json.dumps(record, default=str))

    @staticmethod
    def _default_dispatch(req: ActionRequest) -> dict:
        logger.warning("sovereignty.dispatch.noop: action=%s", req.decision.action.value)
        return {"status": "noop", "message": "No dispatch function configured"}
