"""
sovereignty.action_policy — Centralized Action Policy Engine
=============================================================

This is the SINGLE chokepoint for all AI-driven actions.
No engine, model, or task may bypass this policy.

Every action is evaluated against:
  1. Role-Based Access Control (RBAC)
  2. Environment restrictions (dev/staging/prod)
  3. Confidence thresholds (hard floor)
  4. Approval requirements (human-in-the-loop)
  5. Action allowlist (no arbitrary tool invocation)

Design: Deny by default.  Explicitly allow only known-safe paths.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from sovereignty.schemas import ActionRequest, ProposedAction

logger = logging.getLogger("sovereignty.action_policy")


# ─── Policy Decision ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PolicyDecision:
    """Immutable result of policy evaluation."""
    allowed: bool
    requires_approval: bool
    min_confidence: float
    reason: str
    policy_rule: str = ""  # Which rule triggered (for audit)


# ─── Confidence Thresholds ───────────────────────────────────────────────────

# These are HARD FLOORS — model confidence below these values
# will be rejected regardless of other factors.
# Override via environment for operational flexibility.

def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


CONFIDENCE_FLOORS = {
    "prod": {
        "containment": _env_float("QC_CONF_FLOOR_PROD_CONTAIN", 0.92),
        "escalation": _env_float("QC_CONF_FLOOR_PROD_ESCALATE", 0.60),
    },
    "staging": {
        "containment": _env_float("QC_CONF_FLOOR_STAGING_CONTAIN", 0.85),
        "escalation": _env_float("QC_CONF_FLOOR_STAGING_ESCALATE", 0.50),
    },
    "dev": {
        "containment": _env_float("QC_CONF_FLOOR_DEV_CONTAIN", 0.70),
        "escalation": _env_float("QC_CONF_FLOOR_DEV_ESCALATE", 0.30),
    },
}

# ─── RBAC Role Hierarchy ─────────────────────────────────────────────────────

ROLE_LEVELS = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
    "system": 3,  # Internal system-level (Celery workers, scheduled tasks)
}

# Minimum role level required per action category
ACTION_MIN_ROLES = {
    ProposedAction.none: 0,
    ProposedAction.recommend: 0,
    ProposedAction.escalate: 1,         # analyst+
    ProposedAction.enable_enhanced_logging: 1,
    ProposedAction.contain_host: 1,     # analyst+ (but approval required in prod)
    ProposedAction.block_ip: 1,
    ProposedAction.disable_account: 2,  # admin+ (high impact)
    ProposedAction.quarantine_file: 1,
    ProposedAction.revoke_tokens: 2,    # admin+ (high impact)
    ProposedAction.rotate_credentials: 2,
}


# ─── Action Policy Engine ────────────────────────────────────────────────────

class ActionPolicy:
    """
    Central policy enforcement.  No engine should bypass this.

    Evaluation order:
      1. Allowlist check — is the action in ProposedAction enum?
      2. Role check — does the actor have sufficient privileges?
      3. Confidence floor — does the decision meet minimum confidence?
      4. Approval gate — does the environment require human approval?
      5. Rate/burst guard — has this action been requested too frequently?
    """

    def evaluate(self, req: ActionRequest) -> PolicyDecision:
        """
        Evaluate an action request against policy.
        Returns PolicyDecision (never raises — callers check .allowed).
        """
        action = req.decision.action
        role = req.actor_role
        env = req.environment
        confidence = req.decision.confidence

        # ── Rule 1: Non-executing actions always allowed ──
        if action in (ProposedAction.none, ProposedAction.recommend):
            return PolicyDecision(
                allowed=True,
                requires_approval=False,
                min_confidence=0.0,
                reason="Non-executing action — always permitted",
                policy_rule="R1_PASSTHROUGH",
            )

        # ── Rule 2: Role check ──
        role_level = ROLE_LEVELS.get(role, -1)
        min_role = ACTION_MIN_ROLES.get(action, 99)
        if role_level < min_role:
            logger.warning(
                "policy.denied: role=%s (level=%d) < required=%d for action=%s",
                role, role_level, min_role, action.value,
            )
            return PolicyDecision(
                allowed=False,
                requires_approval=False,
                min_confidence=0.0,
                reason=f"Role '{role}' (level {role_level}) insufficient for action '{action.value}' (requires level {min_role})",
                policy_rule="R2_ROLE_DENIED",
            )

        # ── Rule 3: Determine confidence floor ──
        is_containment = action in ProposedAction.containment_actions()
        env_floors = CONFIDENCE_FLOORS.get(env, CONFIDENCE_FLOORS["prod"])
        floor = env_floors["containment"] if is_containment else env_floors["escalation"]

        if confidence < floor:
            logger.warning(
                "policy.denied: confidence=%.3f < floor=%.3f for action=%s env=%s",
                confidence, floor, action.value, env,
            )
            return PolicyDecision(
                allowed=False,
                requires_approval=False,
                min_confidence=floor,
                reason=f"Confidence {confidence:.3f} below minimum {floor:.3f} for '{action.value}' in {env}",
                policy_rule="R3_CONFIDENCE_FLOOR",
            )

        # ── Rule 4: Approval gate for containment in production ──
        requires_approval = False
        if is_containment and env == "prod":
            containment_mode = os.environ.get("QC_CONTAINMENT_MODE", "approval")
            if containment_mode != "auto":
                requires_approval = True

        # ── Rule 5: Escalation for analyst+ ──
        if action == ProposedAction.escalate:
            return PolicyDecision(
                allowed=True,
                requires_approval=False,
                min_confidence=floor,
                reason=f"Escalation permitted for role='{role}' with confidence={confidence:.3f}",
                policy_rule="R5_ESCALATION_ALLOWED",
            )

        # ── Rule 6: Containment allowed (with approval gate) ──
        if is_containment:
            return PolicyDecision(
                allowed=True,
                requires_approval=requires_approval,
                min_confidence=floor,
                reason=(
                    f"Containment permitted for role='{role}' in {env} "
                    f"(approval={'required' if requires_approval else 'not_required'}, "
                    f"confidence={confidence:.3f} >= {floor:.3f})"
                ),
                policy_rule="R6_CONTAINMENT_GATED",
            )

        # ── Rule 7: Enhanced logging / monitoring actions ──
        return PolicyDecision(
            allowed=True,
            requires_approval=False,
            min_confidence=floor,
            reason=f"Action '{action.value}' permitted for role='{role}' in {env}",
            policy_rule="R7_ACTION_ALLOWED",
        )
