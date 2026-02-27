"""
sovereignty.action_policy — Centralized Action Policy Engine
=============================================================

The SINGLE chokepoint for all AI-driven actions.

v3.5 additions:
  - Red team actions: require engagement scope + admin role
  - Purple team actions: combined red/blue assessment policies
  - Blue team detection: analyst+ for hunting/detection deployment
  - Quantum operations: admin+ for key generation/rotation
  - Engagement scope validation for all offensive operations
  - Threat intel actions: analyst+ for feed sync/IOC ingest

Evaluation order:
  1. Allowlist check — action in ProposedAction enum?
  2. Role check — sufficient privileges?
  3. Engagement scope — authorized for offensive ops?
  4. Confidence floor — meets minimum confidence?
  5. Approval gate — human approval required?
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from sovereignty.schemas import ActionRequest, ProposedAction

logger = logging.getLogger("sovereignty.action_policy")


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable result of policy evaluation."""
    allowed: bool
    requires_approval: bool
    min_confidence: float
    reason: str
    policy_rule: str = ""


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


CONFIDENCE_FLOORS = {
    "prod": {
        "containment": _env_float("QC_CONF_FLOOR_PROD_CONTAIN", 0.92),
        "escalation": _env_float("QC_CONF_FLOOR_PROD_ESCALATE", 0.60),
        "red_team": _env_float("QC_CONF_FLOOR_PROD_REDTEAM", 0.85),
        "purple_team": _env_float("QC_CONF_FLOOR_PROD_PURPLE", 0.80),
        "quantum": _env_float("QC_CONF_FLOOR_PROD_QUANTUM", 0.70),
        "detection": _env_float("QC_CONF_FLOOR_PROD_DETECT", 0.60),
        "intel": _env_float("QC_CONF_FLOOR_PROD_INTEL", 0.50),
    },
    "staging": {
        "containment": _env_float("QC_CONF_FLOOR_STAGING_CONTAIN", 0.85),
        "escalation": _env_float("QC_CONF_FLOOR_STAGING_ESCALATE", 0.50),
        "red_team": 0.70,
        "purple_team": 0.60,
        "quantum": 0.50,
        "detection": 0.40,
        "intel": 0.30,
    },
    "dev": {
        "containment": _env_float("QC_CONF_FLOOR_DEV_CONTAIN", 0.70),
        "escalation": _env_float("QC_CONF_FLOOR_DEV_ESCALATE", 0.30),
        "red_team": 0.50,
        "purple_team": 0.40,
        "quantum": 0.30,
        "detection": 0.20,
        "intel": 0.10,
    },
}


ROLE_LEVELS = {
    "viewer": 0,
    "analyst": 1,
    "admin": 2,
    "system": 3,
}


# Minimum role level per action
ACTION_MIN_ROLES = {
    ProposedAction.none: 0,
    ProposedAction.recommend: 0,
    ProposedAction.escalate: 1,
    ProposedAction.enable_enhanced_logging: 1,
    # Blue containment
    ProposedAction.contain_host: 1,
    ProposedAction.block_ip: 1,
    ProposedAction.disable_account: 2,
    ProposedAction.quarantine_file: 1,
    ProposedAction.revoke_tokens: 2,
    ProposedAction.rotate_credentials: 2,
    ProposedAction.isolate_network_segment: 2,
    # Blue detection/hunting
    ProposedAction.deploy_detection_rule: 1,
    ProposedAction.execute_hunt_query: 1,
    ProposedAction.correlate_iocs: 1,
    ProposedAction.enrich_indicator: 1,
    # Red team (admin+ required for offensive ops)
    ProposedAction.recon_passive: 1,
    ProposedAction.recon_active: 2,
    ProposedAction.simulate_phishing: 2,
    ProposedAction.simulate_exploit: 2,
    ProposedAction.simulate_lateral_move: 2,
    ProposedAction.simulate_exfiltration: 2,
    ProposedAction.simulate_persistence: 2,
    ProposedAction.simulate_privilege_escalation: 2,
    ProposedAction.simulate_c2_beacon: 2,
    # Purple team
    ProposedAction.purple_gap_analysis: 1,
    ProposedAction.purple_attack_replay: 2,
    ProposedAction.purple_coverage_score: 1,
    ProposedAction.purple_ttx_scenario: 1,
    ProposedAction.purple_auto_validate: 2,
    # Quantum
    ProposedAction.quantum_key_generate: 2,
    ProposedAction.quantum_verify_signature: 1,
    ProposedAction.quantum_entropy_harvest: 2,
    ProposedAction.quantum_rotate_lattice_keys: 2,
    # Threat intel
    ProposedAction.intel_feed_sync: 1,
    ProposedAction.intel_ioc_ingest: 1,
    ProposedAction.intel_attribution_map: 1,
}


class ActionPolicy:
    """
    Central policy enforcement.
    """

    def evaluate(self, req: ActionRequest) -> PolicyDecision:
        action = req.decision.action
        role = req.actor_role
        env = req.environment
        confidence = req.decision.confidence

        # ── Rule 1: Non-executing always allowed ──
        if action in (ProposedAction.none, ProposedAction.recommend):
            return PolicyDecision(
                allowed=True, requires_approval=False, min_confidence=0.0,
                reason="Non-executing action — always permitted",
                policy_rule="R1_PASSTHROUGH",
            )

        # ── Rule 2: Role check ──
        role_level = ROLE_LEVELS.get(role, -1)
        min_role = ACTION_MIN_ROLES.get(action, 99)
        if role_level < min_role:
            return PolicyDecision(
                allowed=False, requires_approval=False, min_confidence=0.0,
                reason=f"Role '{role}' (level {role_level}) insufficient for '{action.value}' (requires {min_role})",
                policy_rule="R2_ROLE_DENIED",
            )

        # ── Classify action ──
        is_containment = action in ProposedAction.containment_actions()
        is_red = action in ProposedAction.red_team_actions()
        is_purple = action in ProposedAction.purple_team_actions()
        is_quantum = action in ProposedAction.quantum_actions()
        is_detection = action in (
            ProposedAction.deploy_detection_rule, ProposedAction.execute_hunt_query,
            ProposedAction.correlate_iocs, ProposedAction.enrich_indicator,
        )
        is_intel = action in (
            ProposedAction.intel_feed_sync, ProposedAction.intel_ioc_ingest,
            ProposedAction.intel_attribution_map,
        )

        # ── Rule 3: Determine confidence floor ──
        env_floors = CONFIDENCE_FLOORS.get(env, CONFIDENCE_FLOORS["prod"])
        if is_containment:
            floor = env_floors["containment"]
        elif is_red:
            floor = env_floors["red_team"]
        elif is_purple:
            floor = env_floors["purple_team"]
        elif is_quantum:
            floor = env_floors["quantum"]
        elif is_detection:
            floor = env_floors["detection"]
        elif is_intel:
            floor = env_floors["intel"]
        elif action == ProposedAction.escalate:
            floor = env_floors["escalation"]
        else:
            floor = env_floors["escalation"]

        if confidence < floor:
            return PolicyDecision(
                allowed=False, requires_approval=False, min_confidence=floor,
                reason=f"Confidence {confidence:.3f} below floor {floor:.3f} for '{action.value}' in {env}",
                policy_rule="R3_CONFIDENCE_FLOOR",
            )

        # ── Rule 4: Red team requires engagement authorization ──
        if is_red and env == "prod":
            engagement_id = req.context.get("engagement_id", "")
            if not engagement_id:
                return PolicyDecision(
                    allowed=False, requires_approval=False, min_confidence=floor,
                    reason="Red team actions in prod require engagement_id in context",
                    policy_rule="R4_ENGAGEMENT_REQUIRED",
                )

        # ── Rule 5: Approval gate ──
        requires_approval = False
        containment_mode = os.environ.get("QC_CONTAINMENT_MODE", "approval")

        if is_containment and env == "prod" and containment_mode != "auto":
            requires_approval = True

        if is_red and env == "prod":
            requires_approval = True  # All prod red team needs approval

        if action in (ProposedAction.purple_attack_replay, ProposedAction.purple_auto_validate) and env == "prod":
            requires_approval = True

        if is_quantum and action in (ProposedAction.quantum_key_generate, ProposedAction.quantum_rotate_lattice_keys) and env == "prod":
            requires_approval = True

        # ── Rule 6: Escalation ──
        if action == ProposedAction.escalate:
            return PolicyDecision(
                allowed=True, requires_approval=False, min_confidence=floor,
                reason=f"Escalation permitted for role='{role}' confidence={confidence:.3f}",
                policy_rule="R6_ESCALATION_ALLOWED",
            )

        # ── Rule 7: Containment ──
        if is_containment:
            return PolicyDecision(
                allowed=True, requires_approval=requires_approval, min_confidence=floor,
                reason=(
                    f"Containment permitted for role='{role}' in {env} "
                    f"(approval={'required' if requires_approval else 'not_required'}, "
                    f"confidence={confidence:.3f} >= {floor:.3f})"
                ),
                policy_rule="R7_CONTAINMENT_GATED",
            )

        # ── Rule 8: Red team ──
        if is_red:
            return PolicyDecision(
                allowed=True, requires_approval=requires_approval, min_confidence=floor,
                reason=f"Red team '{action.value}' permitted in {env} (approval={'required' if requires_approval else 'no'})",
                policy_rule="R8_REDTEAM_GATED",
            )

        # ── Rule 9: Purple team ──
        if is_purple:
            return PolicyDecision(
                allowed=True, requires_approval=requires_approval, min_confidence=floor,
                reason=f"Purple team '{action.value}' permitted in {env}",
                policy_rule="R9_PURPLE_ALLOWED",
            )

        # ── Rule 10: Quantum ──
        if is_quantum:
            return PolicyDecision(
                allowed=True, requires_approval=requires_approval, min_confidence=floor,
                reason=f"Quantum op '{action.value}' permitted for role='{role}' in {env}",
                policy_rule="R10_QUANTUM_ALLOWED",
            )

        # ── Rule 11: Detection/hunting + intel ──
        return PolicyDecision(
            allowed=True, requires_approval=False, min_confidence=floor,
            reason=f"Action '{action.value}' permitted for role='{role}' in {env}",
            policy_rule="R11_ACTION_ALLOWED",
        )
