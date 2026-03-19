"""
sovereignty.state_invariants — Incident Response State Machine Invariants
==========================================================================

Enforces legal state transitions and lifecycle constraints for the
Incident Response engine.  Every status change MUST pass through
this validator.

Design:
  - Finite state machine: only declared transitions are legal
  - Phase ordering: containment → eradication → recovery (no skipping)
  - Severity monotonicity: severity can only increase (never downgrade)
  - Evidence immutability: evidence cannot be deleted, only tombstoned
  - Closure prerequisites: root_cause + lessons_learned required
  - Concurrent safety: all checks are pure functions (no shared state)

This module is deliberately separate from the IR engine to enforce
separation of concerns: the engine handles WHAT happens, the invariant
module enforces WHAT IS ALLOWED.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("sovereignty.state_invariants")


# ─── State Machine Definition ────────────────────────────────────────────────

class IRStatus(str, Enum):
    """Canonical incident statuses (mirrors IncidentStatus)."""
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IRSeverity(IntEnum):
    """Severity levels — monotonically increasing only."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Legal state transitions: (from_state) -> frozenset({to_states})
LEGAL_TRANSITIONS: Dict[IRStatus, FrozenSet[IRStatus]] = {
    IRStatus.NEW: frozenset({
        IRStatus.TRIAGED,
        IRStatus.FALSE_POSITIVE,
    }),
    IRStatus.TRIAGED: frozenset({
        IRStatus.INVESTIGATING,
        IRStatus.CONTAINING,      # Fast-track for auto-response
        IRStatus.FALSE_POSITIVE,
    }),
    IRStatus.INVESTIGATING: frozenset({
        IRStatus.CONTAINING,
        IRStatus.ERADICATING,     # Direct if containment not needed
        IRStatus.FALSE_POSITIVE,
    }),
    IRStatus.CONTAINING: frozenset({
        IRStatus.ERADICATING,
        IRStatus.INVESTIGATING,   # Back to investigation if containment reveals more
    }),
    IRStatus.ERADICATING: frozenset({
        IRStatus.RECOVERING,
        IRStatus.CONTAINING,      # Re-contain if eradication incomplete
    }),
    IRStatus.RECOVERING: frozenset({
        IRStatus.CLOSED,
        IRStatus.ERADICATING,     # Back to eradication if recovery reveals residual threat
    }),
    IRStatus.CLOSED: frozenset(),         # Terminal — no transitions out
    IRStatus.FALSE_POSITIVE: frozenset(), # Terminal — no transitions out
}

# Phase ordering for containment → eradication → recovery sequence
PHASE_ORDER: Dict[IRStatus, int] = {
    IRStatus.NEW: 0,
    IRStatus.TRIAGED: 1,
    IRStatus.INVESTIGATING: 2,
    IRStatus.CONTAINING: 3,
    IRStatus.ERADICATING: 4,
    IRStatus.RECOVERING: 5,
    IRStatus.CLOSED: 6,
    IRStatus.FALSE_POSITIVE: 6,
}


# ─── Violation Types ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class InvariantViolation:
    """Immutable record of an invariant violation."""
    rule: str
    message: str
    current_state: str = ""
    requested_state: str = ""
    severity: str = "ERROR"

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "message": self.message,
            "current_state": self.current_state,
            "requested_state": self.requested_state,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class InvariantCheckResult:
    """Result of invariant validation."""
    valid: bool
    violations: Tuple[InvariantViolation, ...]

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "violation_count": self.violation_count,
            "violations": [v.to_dict() for v in self.violations],
        }


# ─── Invariant Checker ──────────────────────────────────────────────────────

class IRInvariantChecker:
    """
    Pure-function invariant checker for incident lifecycle.
    All methods are stateless — they inspect the incident data
    and return validation results without side effects.
    """

    # ── State Transition Validation ──────────────────────────────────────────

    @staticmethod
    def validate_transition(
        current_status: str,
        requested_status: str,
    ) -> InvariantCheckResult:
        """
        Check if a state transition is legal.

        Returns:
            InvariantCheckResult with valid=True if transition is allowed.
        """
        violations: List[InvariantViolation] = []

        # Parse statuses
        try:
            current = IRStatus(current_status)
        except ValueError:
            violations.append(InvariantViolation(
                rule="SM_INVALID_CURRENT",
                message=f"Unknown current status: '{current_status}'",
                current_state=current_status,
                requested_state=requested_status,
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        try:
            requested = IRStatus(requested_status)
        except ValueError:
            violations.append(InvariantViolation(
                rule="SM_INVALID_REQUESTED",
                message=f"Unknown requested status: '{requested_status}'",
                current_state=current_status,
                requested_state=requested_status,
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        # No-op transition
        if current == requested:
            return InvariantCheckResult(valid=True, violations=())

        # Terminal state check
        if current in (IRStatus.CLOSED, IRStatus.FALSE_POSITIVE):
            violations.append(InvariantViolation(
                rule="SM_TERMINAL_STATE",
                message=f"Cannot transition from terminal state '{current.value}'",
                current_state=current.value,
                requested_state=requested.value,
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        # Legal transition check
        allowed = LEGAL_TRANSITIONS.get(current, frozenset())
        if requested not in allowed:
            allowed_str = ", ".join(sorted(s.value for s in allowed))
            violations.append(InvariantViolation(
                rule="SM_ILLEGAL_TRANSITION",
                message=(
                    f"Transition '{current.value}' → '{requested.value}' is not allowed. "
                    f"Legal transitions from '{current.value}': [{allowed_str}]"
                ),
                current_state=current.value,
                requested_state=requested.value,
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        return InvariantCheckResult(valid=True, violations=())

    # ── Severity Monotonicity ────────────────────────────────────────────────

    @staticmethod
    def validate_severity_change(
        current_severity: int,
        requested_severity: int,
    ) -> InvariantCheckResult:
        """
        Enforce severity monotonicity: severity can only increase.
        Downgrading severity is a potential cover-up indicator.
        """
        violations: List[InvariantViolation] = []

        if requested_severity < current_severity:
            violations.append(InvariantViolation(
                rule="SEV_MONOTONIC",
                message=(
                    f"Severity downgrade not permitted: "
                    f"{current_severity} → {requested_severity}. "
                    f"Severity can only increase during an active incident."
                ),
                severity="ERROR",
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        return InvariantCheckResult(valid=True, violations=())

    # ── Closure Prerequisites ────────────────────────────────────────────────

    @staticmethod
    def validate_closure(
        current_status: str,
        has_root_cause: bool,
        has_lessons_learned: bool,
        evidence_count: int,
        action_count: int,
    ) -> InvariantCheckResult:
        """
        Validate that closure prerequisites are met.
        Cannot close without documenting root cause and lessons learned.
        """
        violations: List[InvariantViolation] = []

        # Must be in a closeable state
        try:
            status = IRStatus(current_status)
        except ValueError:
            violations.append(InvariantViolation(
                rule="CLOSE_INVALID_STATUS",
                message=f"Unknown status: '{current_status}'",
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        # Only recovering → closed is normal path
        if status not in (IRStatus.RECOVERING, IRStatus.INVESTIGATING, IRStatus.TRIAGED):
            violations.append(InvariantViolation(
                rule="CLOSE_WRONG_PHASE",
                message=(
                    f"Cannot close from '{status.value}'. "
                    f"Incident must reach 'recovering' phase before closure."
                ),
                current_state=status.value,
                requested_state="closed",
                severity="ERROR",
            ))

        # Root cause required
        if not has_root_cause:
            violations.append(InvariantViolation(
                rule="CLOSE_NO_ROOT_CAUSE",
                message="Root cause documentation required before closure",
                severity="ERROR",
            ))

        # Lessons learned required
        if not has_lessons_learned:
            violations.append(InvariantViolation(
                rule="CLOSE_NO_LESSONS",
                message="Lessons learned documentation required before closure",
                severity="ERROR",
            ))

        # Warning (not blocking): no evidence collected
        if evidence_count == 0:
            violations.append(InvariantViolation(
                rule="CLOSE_NO_EVIDENCE",
                message="Warning: closing incident with zero evidence collected",
                severity="WARNING",
            ))

        has_errors = any(v.severity == "ERROR" for v in violations)
        return InvariantCheckResult(
            valid=not has_errors,
            violations=tuple(violations),
        )

    # ── Evidence Immutability ────────────────────────────────────────────────

    @staticmethod
    def validate_evidence_operation(
        operation: str,
        is_tombstoned: bool = False,
    ) -> InvariantCheckResult:
        """
        Enforce evidence immutability constraints.
        Evidence can be added or tombstoned, but never deleted or modified.
        """
        violations: List[InvariantViolation] = []

        if operation == "delete":
            violations.append(InvariantViolation(
                rule="EVIDENCE_NO_DELETE",
                message="Evidence cannot be deleted. Use tombstoning to mark as invalid.",
                severity="ERROR",
            ))
        elif operation == "modify" and is_tombstoned:
            violations.append(InvariantViolation(
                rule="EVIDENCE_TOMBSTONED",
                message="Tombstoned evidence cannot be modified.",
                severity="ERROR",
            ))
        elif operation not in ("add", "tombstone", "modify", "read"):
            violations.append(InvariantViolation(
                rule="EVIDENCE_UNKNOWN_OP",
                message=f"Unknown evidence operation: '{operation}'",
                severity="ERROR",
            ))

        return InvariantCheckResult(
            valid=len(violations) == 0,
            violations=tuple(violations),
        )

    # ── Action Precondition Validation ───────────────────────────────────────

    @staticmethod
    def validate_action_preconditions(
        incident_status: str,
        action_type: str,
        requires_approval: bool,
        has_approval: bool,
    ) -> InvariantCheckResult:
        """
        Validate that action preconditions are met for the current state.
        Containment actions require the incident to be in an active phase.
        """
        violations: List[InvariantViolation] = []

        CONTAINMENT_ACTIONS = {
            "block_ip", "block_domain", "isolate_host",
            "disable_account", "quarantine_file", "kill_process",
            "contain_host", "revoke_tokens", "rotate_credentials",
        }

        try:
            status = IRStatus(incident_status)
        except ValueError:
            violations.append(InvariantViolation(
                rule="ACTION_INVALID_STATUS",
                message=f"Unknown incident status: '{incident_status}'",
            ))
            return InvariantCheckResult(valid=False, violations=tuple(violations))

        # Cannot execute actions on closed/FP incidents
        if status in (IRStatus.CLOSED, IRStatus.FALSE_POSITIVE):
            violations.append(InvariantViolation(
                rule="ACTION_TERMINAL_STATE",
                message=f"Cannot execute actions on '{status.value}' incident",
                severity="ERROR",
            ))

        # Containment actions require active investigation or containment phase
        if action_type in CONTAINMENT_ACTIONS:
            valid_phases = {
                IRStatus.TRIAGED, IRStatus.INVESTIGATING,
                IRStatus.CONTAINING, IRStatus.ERADICATING,
            }
            if status not in valid_phases:
                violations.append(InvariantViolation(
                    rule="ACTION_WRONG_PHASE",
                    message=(
                        f"Containment action '{action_type}' not permitted in "
                        f"phase '{status.value}'. Required: triaged/investigating/containing/eradicating."
                    ),
                    severity="ERROR",
                ))

        # Approval check
        if requires_approval and not has_approval:
            violations.append(InvariantViolation(
                rule="ACTION_NO_APPROVAL",
                message=f"Action '{action_type}' requires approval before execution",
                severity="ERROR",
            ))

        has_errors = any(v.severity == "ERROR" for v in violations)
        return InvariantCheckResult(
            valid=not has_errors,
            violations=tuple(violations),
        )

    # ── Compound Validation ──────────────────────────────────────────────────

    @classmethod
    def validate_all(
        cls,
        current_status: str,
        requested_status: Optional[str] = None,
        current_severity: Optional[int] = None,
        requested_severity: Optional[int] = None,
        is_closing: bool = False,
        has_root_cause: bool = False,
        has_lessons_learned: bool = False,
        evidence_count: int = 0,
        action_count: int = 0,
    ) -> InvariantCheckResult:
        """
        Run all applicable invariant checks in one call.
        Returns combined result with all violations.
        """
        all_violations: List[InvariantViolation] = []

        # State transition
        if requested_status is not None:
            result = cls.validate_transition(current_status, requested_status)
            all_violations.extend(result.violations)

        # Severity monotonicity
        if current_severity is not None and requested_severity is not None:
            result = cls.validate_severity_change(current_severity, requested_severity)
            all_violations.extend(result.violations)

        # Closure prerequisites
        if is_closing:
            result = cls.validate_closure(
                current_status, has_root_cause, has_lessons_learned,
                evidence_count, action_count,
            )
            all_violations.extend(result.violations)

        has_errors = any(v.severity == "ERROR" for v in all_violations)
        return InvariantCheckResult(
            valid=not has_errors,
            violations=tuple(all_violations),
        )
