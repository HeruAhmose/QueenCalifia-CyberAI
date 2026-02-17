"""
sovereignty.executor — Audit-First Action Execution Engine
============================================================

The SovereigntyExecutor is the ONLY authorized path for executing
state-changing actions in QueenCalifia CyberAI.

Execution flow:
  1. Policy evaluation (ActionPolicy)
  2. Confidence check (hard floor enforcement)
  3. Approval verification (for prod containment)
  4. Idempotency guard (prevent duplicate actions)
  5. AUDIT RECORD WRITTEN (before any action)
  6. Dry-run check (default in production)
  7. Action dispatch (Celery task or direct call)
  8. Post-execution audit update

Critical safety properties:
  - Audit record is ALWAYS written before execution
  - Dry-run is the default for dangerous actions in production
  - Idempotent actions are detected and skipped
  - Every execution is traceable via trace_id + request_id
  - Model output hash is included in audit for tamper detection
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Callable, Dict, Optional

from sovereignty.action_policy import ActionPolicy, PolicyDecision
from sovereignty.schemas import ActionRequest, ProposedAction

logger = logging.getLogger("sovereignty.executor")


class SovereigntyError(RuntimeError):
    """Raised when the sovereignty layer blocks an action."""

    def __init__(self, message: str, policy_rule: str = "", decision_dump: Optional[dict] = None):
        super().__init__(message)
        self.policy_rule = policy_rule
        self.decision_dump = decision_dump or {}


def stable_hash(obj: dict) -> str:
    """Deterministic SHA-256 hash of a dict for tamper detection."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class SovereigntyExecutor:
    """
    Central execution engine.  All action requests flow through here.

    Args:
        policy: ActionPolicy instance (defaults to standard policy)
        audit_write_fn: Callable that writes an audit record dict.
                        Signature: (record: dict) -> None
        idempotency_check_fn: Callable that returns True if this action
                              has already been applied.
                              Signature: (req: ActionRequest) -> bool
        action_dispatch_fn: Callable that actually executes the action.
                           Signature: (req: ActionRequest) -> dict
    """

    def __init__(
        self,
        policy: Optional[ActionPolicy] = None,
        audit_write_fn: Optional[Callable[[Dict], None]] = None,
        idempotency_check_fn: Optional[Callable[[ActionRequest], bool]] = None,
        action_dispatch_fn: Optional[Callable[[ActionRequest], Dict]] = None,
    ):
        self.policy = policy or ActionPolicy()
        self.audit_write_fn = audit_write_fn or self._default_audit
        self.idempotency_check_fn = idempotency_check_fn or (lambda req: False)
        self.action_dispatch_fn = action_dispatch_fn or self._default_dispatch

    # ── Main Execution Path ──────────────────────────────────────────────────

    def execute(self, req: ActionRequest) -> Dict[str, Any]:
        """
        Execute an action request through the sovereignty pipeline.

        Returns:
            dict with status, action details, and audit reference.

        Raises:
            SovereigntyError if policy denies the action.
        """
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

        # Step 2: Confidence enforcement (belt-and-suspenders with policy)
        if req.decision.confidence < policy_result.min_confidence:
            self._write_audit(req, policy_result, "CONFIDENCE_DENIED", decision_dump)
            raise SovereigntyError(
                f"Confidence {req.decision.confidence:.3f} below floor "
                f"{policy_result.min_confidence:.3f} ({policy_result.reason})",
                policy_rule="CONFIDENCE_HARD_FLOOR",
                decision_dump=decision_dump,
            )

        # Step 3: Approval verification
        if policy_result.requires_approval and not req.approval_id:
            self._write_audit(req, policy_result, "APPROVAL_REQUIRED", decision_dump)
            raise SovereigntyError(
                "Approval required for this action in production. "
                "Submit via /api/incidents/<id>/approve/<action_id>",
                policy_rule="APPROVAL_GATE",
                decision_dump=decision_dump,
            )

        # Step 4: Idempotency guard
        if self.idempotency_check_fn(req):
            self._write_audit(req, policy_result, "IDEMPOTENT_SKIP", decision_dump)
            logger.info(
                "sovereignty.idempotent: action=%s targets=%s already applied",
                req.decision.action.value, req.decision.targets[:3],
            )
            return {
                "status": "skipped",
                "reason": "idempotent_action_already_applied",
                "action": req.decision.action.value,
            }

        # Step 5: AUDIT RECORD (written BEFORE execution)
        self._write_audit(req, policy_result, "EXECUTING" if not req.dry_run else "DRY_RUN", decision_dump)

        # Step 6: Dry-run check
        is_dangerous = req.decision.action in ProposedAction.containment_actions()
        if req.dry_run and is_dangerous:
            logger.info(
                "sovereignty.dry_run: action=%s targets=%s confidence=%.3f",
                req.decision.action.value, req.decision.targets[:3], req.decision.confidence,
            )
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

        # Step 8: Post-execution audit
        self._write_audit(req, policy_result, "EXECUTED", decision_dump, elapsed=elapsed)

        logger.info(
            "sovereignty.executed: action=%s targets=%s confidence=%.3f elapsed=%.3fs",
            req.decision.action.value, req.decision.targets[:3], req.decision.confidence, elapsed,
        )

        return {
            "status": "executed",
            "action": req.decision.action.value,
            "targets": req.decision.targets,
            "result": result,
            "elapsed_sec": round(elapsed, 4),
            "policy_rule": policy_result.policy_rule,
        }

    # ── Audit Helpers ────────────────────────────────────────────────────────

    def _write_audit(
        self,
        req: ActionRequest,
        policy: PolicyDecision,
        outcome: str,
        decision_dump: dict,
        error: Optional[str] = None,
        elapsed: Optional[float] = None,
    ):
        """Write an audit record.  This MUST succeed for execution to proceed."""
        record = {
            "timestamp": time.time(),
            "outcome": outcome,
            "tenant_id": req.tenant_id,
            "trace_id": req.trace_id,
            "request_id": req.request_id,
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

        try:
            self.audit_write_fn(record)
        except Exception as exc:
            logger.critical(
                "sovereignty.AUDIT_WRITE_FAILED: outcome=%s action=%s error=%s",
                outcome, req.decision.action.value, exc,
            )
            # If audit write fails, we MUST NOT proceed with execution
            if outcome in ("EXECUTING", "DRY_RUN"):
                raise SovereigntyError(
                    "Audit write failed — action blocked for safety",
                    policy_rule="AUDIT_FAILURE_BLOCK",
                ) from exc

    # ── Defaults ─────────────────────────────────────────────────────────────

    @staticmethod
    def _default_audit(record: dict) -> None:
        """Default audit: structured log output (replace with your audit module)."""
        logger.info("sovereignty.audit: %s", json.dumps(record, default=str))

    @staticmethod
    def _default_dispatch(req: ActionRequest) -> dict:
        """Default dispatch: no-op (replace with Celery task enqueue)."""
        logger.warning(
            "sovereignty.dispatch.noop: action=%s — no dispatch function configured",
            req.decision.action.value,
        )
        return {"status": "noop", "message": "No action dispatch function configured"}
