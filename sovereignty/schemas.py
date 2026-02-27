"""
sovereignty.schemas — Structured Output Enforcement for AI Decisions
====================================================================

Every model response MUST validate against ModelDecision.
Every action request MUST be wrapped in ActionRequest.

v3.4 additions:
  - actor_id: stable user/service identity for two-person rule
  - SignatureAlg: Ed25519 + PQ algorithm registry (crypto-agility)
  - ApprovalSignature: per-approver cryptographic signature (Pydantic)
  - ApprovalRecord: approval lifecycle envelope with TTL, nonce, revocation
  - HybridSignaturePolicy: enforce classical+PQ in production (toggle)

Usage:
    raw = call_model_json(context)
    decision = ModelDecision.model_validate(raw)  # raises on bad output
"""
from __future__ import annotations

import os
import time
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

    v3.5: Purple team (recon, infiltration, hunt), quantum ops added.
    """
    # ── Core ─────────────────────────────────────────────────────────────
    none = "none"
    recommend = "recommend"
    escalate = "escalate"

    # ── Blue Team (Containment) ──────────────────────────────────────────
    contain_host = "contain_host"
    block_ip = "block_ip"
    disable_account = "disable_account"
    quarantine_file = "quarantine_file"
    revoke_tokens = "revoke_tokens"
    enable_enhanced_logging = "enable_enhanced_logging"
    rotate_credentials = "rotate_credentials"

    # ── Blue Team (Detection & Hunting) ──────────────────────────────────
    deploy_detection_rule = "deploy_detection_rule"
    execute_hunt_query = "execute_hunt_query"
    correlate_iocs = "correlate_iocs"
    enrich_indicator = "enrich_indicator"
    isolate_network_segment = "isolate_network_segment"

    # ── Red Team (Authorized Offensive Simulation) ───────────────────────
    recon_passive = "recon_passive"
    recon_active = "recon_active"
    simulate_phishing = "simulate_phishing"
    simulate_exploit = "simulate_exploit"
    simulate_lateral_move = "simulate_lateral_move"
    simulate_exfiltration = "simulate_exfiltration"
    simulate_persistence = "simulate_persistence"
    simulate_privilege_escalation = "simulate_privilege_escalation"
    simulate_c2_beacon = "simulate_c2_beacon"

    # ── Purple Team (Combined Assessment) ────────────────────────────────
    purple_gap_analysis = "purple_gap_analysis"
    purple_attack_replay = "purple_attack_replay"
    purple_coverage_score = "purple_coverage_score"
    purple_ttx_scenario = "purple_ttx_scenario"
    purple_auto_validate = "purple_auto_validate"

    # ── Quantum Operations ───────────────────────────────────────────────
    quantum_key_generate = "quantum_key_generate"
    quantum_verify_signature = "quantum_verify_signature"
    quantum_entropy_harvest = "quantum_entropy_harvest"
    quantum_rotate_lattice_keys = "quantum_rotate_lattice_keys"

    # ── Threat Intel ─────────────────────────────────────────────────────
    intel_feed_sync = "intel_feed_sync"
    intel_ioc_ingest = "intel_ioc_ingest"
    intel_attribution_map = "intel_attribution_map"

    @classmethod
    def containment_actions(cls) -> frozenset:
        """Actions that modify system state and require elevated controls."""
        return frozenset({
            cls.contain_host, cls.block_ip, cls.disable_account,
            cls.quarantine_file, cls.revoke_tokens, cls.rotate_credentials,
            cls.isolate_network_segment,
        })

    @classmethod
    def red_team_actions(cls) -> frozenset:
        """Offensive simulation actions — require authorization scope."""
        return frozenset({
            cls.recon_active, cls.simulate_phishing, cls.simulate_exploit,
            cls.simulate_lateral_move, cls.simulate_exfiltration,
            cls.simulate_persistence, cls.simulate_privilege_escalation,
            cls.simulate_c2_beacon,
        })

    @classmethod
    def purple_team_actions(cls) -> frozenset:
        """Combined red+blue assessment actions."""
        return cls.red_team_actions() | frozenset({
            cls.recon_passive, cls.purple_gap_analysis, cls.purple_attack_replay,
            cls.purple_coverage_score, cls.purple_ttx_scenario,
            cls.purple_auto_validate,
        })

    @classmethod
    def quantum_actions(cls) -> frozenset:
        """Quantum-resilient operations."""
        return frozenset({
            cls.quantum_key_generate, cls.quantum_verify_signature,
            cls.quantum_entropy_harvest, cls.quantum_rotate_lattice_keys,
        })

    @classmethod
    def blue_team_actions(cls) -> frozenset:
        """Detection, hunting, and defensive actions."""
        return cls.containment_actions() | frozenset({
            cls.deploy_detection_rule, cls.execute_hunt_query,
            cls.correlate_iocs, cls.enrich_indicator,
        })


# ─── Evidence Provenance ─────────────────────────────────────────────────────

class EvidenceRef(BaseModel):
    """Provenance link — every recommendation MUST cite evidence."""
    source: str = Field(min_length=1, description="Origin system: telemetry, vuln_engine, siem, predictor")
    id: str = Field(min_length=1, description="Event ID, alert ID, or document ID")
    note: Optional[str] = Field(default=None, max_length=2000)


# ─── Model Decision Schema ───────────────────────────────────────────────────

class ModelDecision(BaseModel):
    """
    Strict schema for LLM / engine output.
    The model is ONLY allowed to produce this structure.
    """
    action: ProposedAction = ProposedAction.none
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk: RiskLevel = RiskLevel.low
    summary: str = Field(min_length=1, max_length=2000)
    rationale: str = Field(min_length=1, max_length=6000)
    targets: List[str] = Field(default_factory=list)
    evidence: List[EvidenceRef] = Field(default_factory=list)
    playbooks: List[str] = Field(default_factory=list)
    predicted_techniques: List[str] = Field(default_factory=list)

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
    Internal envelope for action execution through SovereigntyExecutor.
    This is the ONLY way to trigger state-changing operations.
    """
    decision: ModelDecision

    # v3.4: Stable identity for two-person rule
    actor_id: str = Field(
        default="",
        max_length=128,
        description="Stable user/service identity (not role). Required for approval verification.",
    )

    actor_role: Literal["viewer", "analyst", "admin", "system"]
    environment: Literal["dev", "staging", "prod"]
    tenant_id: str = Field(min_length=1, max_length=128)
    trace_id: Optional[str] = None
    request_id: Optional[str] = None

    dry_run: bool = Field(
        default_factory=lambda: os.environ.get("QC_CONTAINMENT_MODE", "approval") != "auto"
    )

    approval_id: Optional[str] = None

    # v3.4: Client-provided nonce for replay resistance
    approval_nonce: Optional[str] = Field(default=None, max_length=128)

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


# ─── Signature Algorithm Registry (Crypto-Agility) ──────────────────────────

class SignatureAlg(str, Enum):
    """
    Crypto-agility: classical + PQ + quantum-native.
    No schema changes needed when PQ backend becomes available.
    """
    ed25519 = "ed25519"
    dilithium2 = "dilithium2"
    dilithium3 = "dilithium3"
    dilithium5 = "dilithium5"
    kyber768 = "kyber768"            # KEM (key encapsulation)
    sphincs_sha2_256f = "sphincs_sha2_256f"  # Hash-based (stateless)
    falcon512 = "falcon512"          # Compact lattice signatures


# ─── Cryptographic Approval Models ──────────────────────────────────────────

class ApprovalSignature(BaseModel):
    """Individual cryptographic signature from an approver."""
    approver_id: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=1, max_length=128, description="Public key identifier (KMS/HSM key id).")
    alg: SignatureAlg
    signature_b64: str = Field(min_length=16, max_length=8192)


class ApprovalRecord(BaseModel):
    """
    Approval lifecycle envelope.  Accumulates signatures from distinct
    approvers and expires after TTL.  Back with DB in production.
    """
    approval_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    decision_hash: str = Field(min_length=32, max_length=128)
    requested_by: str = Field(min_length=1, max_length=128)
    created_at: float = Field(default_factory=lambda: time.time())
    expires_at: float = Field(default_factory=lambda: time.time() + 900.0)
    nonce: str = Field(min_length=8, max_length=128)
    signatures: List[ApprovalSignature] = Field(default_factory=list)
    revoked: bool = False
    revoked_at: Optional[float] = None
    hash_alg: str = Field(default="sha256", max_length=32)


# ─── Hybrid Signature Policy ────────────────────────────────────────────────

class HybridSignaturePolicy(BaseModel):
    """
    When QC_REQUIRE_HYBRID_SIGNATURES=1, production approvals must include
    BOTH a classical (Ed25519) AND a post-quantum (Dilithium) signature
    from each approver.  This is the "implement now" crypto-agility toggle.
    """
    require_hybrid: bool = Field(
        default_factory=lambda: os.environ.get("QC_REQUIRE_HYBRID_SIGNATURES", "0") == "1"
    )
    classical_algs: List[SignatureAlg] = Field(default=[SignatureAlg.ed25519])
    pq_algs: List[SignatureAlg] = Field(default=[
        SignatureAlg.dilithium2, SignatureAlg.dilithium3, SignatureAlg.dilithium5,
    ])


# ─── Purple Team Engagement Scope ──────────────────────────────────────────

class EngagementScope(BaseModel):
    """
    Authorization boundary for red/purple team operations.
    Every offensive action MUST reference an active engagement.
    """
    engagement_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    authorized_targets: List[str] = Field(default_factory=list, description="CIDRs, hostnames, or asset IDs")
    excluded_targets: List[str] = Field(default_factory=list, description="Explicitly off-limits")
    authorized_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK IDs (e.g. T1566)")
    max_impact_level: RiskLevel = RiskLevel.medium
    start_time: float = Field(default_factory=lambda: time.time())
    end_time: float = Field(default_factory=lambda: time.time() + 86400.0)
    approved_by: List[str] = Field(default_factory=list, min_length=0)
    rules_of_engagement: str = Field(default="", max_length=10000)
    active: bool = True


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique reference."""
    technique_id: str = Field(min_length=1, max_length=16, description="e.g. T1566.001")
    tactic: str = Field(min_length=1, max_length=64, description="e.g. initial-access")
    name: str = Field(min_length=1, max_length=256)
    severity: RiskLevel = RiskLevel.medium
    detection_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    platforms: List[str] = Field(default_factory=list)


class PurpleTeamResult(BaseModel):
    """Result of a purple team operation (attack simulation + detection validation)."""
    operation_id: str = Field(min_length=1, max_length=128)
    engagement_id: str = Field(min_length=1, max_length=128)
    technique: MitreTechnique
    attack_success: bool = False
    detection_fired: bool = False
    detection_latency_ms: Optional[float] = None
    gap_identified: bool = False
    gap_description: str = ""
    remediation_priority: RiskLevel = RiskLevel.low
    artifacts: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=lambda: time.time())


class QuantumKeySpec(BaseModel):
    """Quantum-resilient key specification."""
    algorithm: SignatureAlg
    key_size_bits: int = Field(ge=128, le=65536)
    purpose: Literal["signing", "encryption", "kem", "entropy"] = "signing"
    hardware_backed: bool = False
    rotation_interval_hours: int = Field(default=720, ge=1)
