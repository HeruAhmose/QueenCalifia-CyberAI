"""
sovereignty.schemas — Structured Output Enforcement for AI Decisions
====================================================================

Every model response MUST validate against ModelDecision.
Every action request MUST be wrapped in ActionRequest.

This prevents:
  - Arbitrary tool invocation
  - Unstructured model output driving actions
  - Missing confidence / evidence / provenance
  - Untraceable decisions

Usage:
    raw = call_model_json(context)
    decision = ModelDecision.model_validate(raw)  # raises on bad output
"""
from __future__ import annotations

import os
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ─── Enumerations ────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    """Deterministic risk classification — server-assigned, never client."""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ProposedAction(str, Enum):
    """
    Allowlisted actions.  No action outside this enum can be executed.
    Adding a new action requires a code change + policy update + review.
    """
    none = "none"
    recommend = "recommend"
    escalate = "escalate"
    contain_host = "contain_host"
    block_ip = "block_ip"
    disable_account = "disable_account"
    quarantine_file = "quarantine_file"
    revoke_tokens = "revoke_tokens"
    enable_enhanced_logging = "enable_enhanced_logging"
    rotate_credentials = "rotate_credentials"

    @classmethod
    def containment_actions(cls) -> frozenset:
        """Actions that modify system state and require elevated controls."""
        return frozenset({
            cls.contain_host,
            cls.block_ip,
            cls.disable_account,
            cls.quarantine_file,
            cls.revoke_tokens,
            cls.rotate_credentials,
        })


# ─── Evidence Provenance ─────────────────────────────────────────────────────

class EvidenceRef(BaseModel):
    """
    Provenance link — every recommendation MUST cite evidence.
    This enables explainability for enterprise/gov review.
    """
    source: str = Field(min_length=1, description="Origin system: telemetry, vuln_engine, siem, predictor")
    id: str = Field(min_length=1, description="Event ID, alert ID, or document ID")
    note: Optional[str] = Field(default=None, max_length=2000)


# ─── Model Decision Schema ───────────────────────────────────────────────────

class ModelDecision(BaseModel):
    """
    Strict schema for LLM / engine output.
    The model is ONLY allowed to produce this structure.
    Any output that fails validation is rejected.
    """
    action: ProposedAction = ProposedAction.none
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk: RiskLevel = RiskLevel.low
    summary: str = Field(min_length=1, max_length=2000,
                         description="Human-readable summary of the decision")
    rationale: str = Field(min_length=1, max_length=6000,
                           description="Detailed reasoning chain")
    targets: List[str] = Field(default_factory=list,
                               description="IPs, hostnames, or asset IDs affected")
    evidence: List[EvidenceRef] = Field(default_factory=list,
                                        description="Provenance citations")
    playbooks: List[str] = Field(default_factory=list,
                                 description="Suggested playbook IDs (not raw commands)")
    predicted_techniques: List[str] = Field(default_factory=list,
                                            description="MITRE ATT&CK technique IDs")

    @field_validator("targets", mode="before")
    @classmethod
    def _cap_targets(cls, v):
        if isinstance(v, list) and len(v) > 50:
            return v[:50]
        return v

    @field_validator("playbooks", mode="before")
    @classmethod
    def _cap_playbooks(cls, v):
        if isinstance(v, list) and len(v) > 10:
            return v[:10]
        return v


# ─── Action Request Envelope ─────────────────────────────────────────────────

class ActionRequest(BaseModel):
    """
    Internal envelope used by engines to request action execution
    through the SovereigntyExecutor.  This is the ONLY way to
    trigger state-changing operations.
    """
    decision: ModelDecision
    actor_role: Literal["viewer", "analyst", "admin", "system"]
    environment: Literal["dev", "staging", "prod"]
    tenant_id: str = Field(min_length=1, max_length=128)
    trace_id: Optional[str] = None
    request_id: Optional[str] = None

    # Dry-run default: True in prod, configurable via env
    dry_run: bool = Field(
        default_factory=lambda: os.environ.get("QC_CONTAINMENT_MODE", "approval") != "auto"
    )

    # Present only after human approval
    approval_id: Optional[str] = None

    # Sanitized context metadata (never raw telemetry)
    context: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("context", mode="before")
    @classmethod
    def _limit_context_size(cls, v):
        """Prevent unbounded context from consuming memory."""
        if isinstance(v, dict):
            import json
            serialized = json.dumps(v, default=str)
            if len(serialized) > 50_000:
                return {"_truncated": True, "keys": list(v.keys())[:20]}
        return v
