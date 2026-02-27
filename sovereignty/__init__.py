# sovereignty — AI Action Control & Governance Layer
#
# Architecture:
#   Model Output → ModelDecision (schema-validated)
#     → ActionPolicy.evaluate()
#       → AuditRecord (hash-chained BEFORE execution)
#         → IdempotencyGuard (REQUIRED for containment)
#           → Ed25519 Dual-Signature Approval (two-person rule)
#             → Hybrid PQ enforcement (classical+PQ when enabled)
#               → TaskDispatch (Celery or direct)
#
# Design Principles (12):
#   1. Structured output enforcement — ModelDecision schema
#   2. Confidence hard floor — ≥0.92 for prod containment
#   3. Ed25519 dual-signature approval — two-person rule
#   4. Audit-first — hash-chained record before execution
#   5. Dry-run default — prod defaults dry_run=True
#   6. Prompt injection defense — entropy/homoglyph/encoding
#   7. Deterministic override — policy overrides model
#   8. State machine invariants — IR lifecycle enforcement
#   9. Entropy analysis — obfuscated payload detection
#  10. Idempotency guard — REQUIRED for containment
#  11. Post-quantum readiness — Dilithium via plugin hook
#  12. Audit hash chaining — tamper-evident append-only trail

from sovereignty.schemas import (
    ModelDecision, ActionRequest, ProposedAction, RiskLevel, EvidenceRef,
    SignatureAlg, ApprovalSignature as ApprovalSignatureModel,
    ApprovalRecord, HybridSignaturePolicy,
    EngagementScope, MitreTechnique, PurpleTeamResult, QuantumKeySpec,
)
from sovereignty.action_policy import ActionPolicy, PolicyDecision
from sovereignty.executor import SovereigntyExecutor, SovereigntyError, stable_hash
from sovereignty.prompt_guard import (
    sanitize_untrusted_text, scan_for_injection, deep_scan,
    sanitize_telemetry, shannon_entropy, strip_invisible_chars, normalize_homoglyphs,
)
from sovereignty.approvals import (
    ApprovalStore, InMemoryApprovalStore, KeyRegistry, PublicKeyRecord,
    verify_signature, sign_approval_ed25519, check_hybrid_requirement,
    requires_dual_approval, DUAL_APPROVAL_ACTIONS, HAS_ED25519,
)
from sovereignty.audit_chain import (
    AuditChain, AuditEntry, compute_record_hash, compute_chain_hash, GENESIS_HASH,
)
# Legacy HMAC (deprecated)
from sovereignty.crypto_approval import (
    ApprovalStore as LegacyHMACApprovalStore,
    ApprovalSignature as LegacyHMACSignature,
    DualApprovalResult,
)
from sovereignty.state_invariants import (
    IRInvariantChecker, InvariantViolation, InvariantCheckResult,
    IRStatus, IRSeverity, LEGAL_TRANSITIONS,
)

__all__ = [
    # Schemas
    "ModelDecision", "ActionRequest", "ProposedAction", "RiskLevel", "EvidenceRef",
    "SignatureAlg", "ApprovalSignatureModel", "ApprovalRecord", "HybridSignaturePolicy",
    # Policy
    "ActionPolicy", "PolicyDecision",
    # Executor
    "SovereigntyExecutor", "SovereigntyError", "stable_hash",
    # Prompt Guard
    "sanitize_untrusted_text", "scan_for_injection", "deep_scan",
    "sanitize_telemetry", "shannon_entropy", "strip_invisible_chars", "normalize_homoglyphs",
    # Approvals (v3.4)
    "ApprovalStore", "InMemoryApprovalStore", "KeyRegistry", "PublicKeyRecord",
    "verify_signature", "sign_approval_ed25519", "check_hybrid_requirement",
    "requires_dual_approval", "DUAL_APPROVAL_ACTIONS", "HAS_ED25519",
    # Audit Chain (v3.4)
    "AuditChain", "AuditEntry", "compute_record_hash", "compute_chain_hash", "GENESIS_HASH",
    # Legacy HMAC (deprecated)
    "LegacyHMACApprovalStore", "LegacyHMACSignature", "DualApprovalResult",
    # State Invariants
    "IRInvariantChecker", "InvariantViolation", "InvariantCheckResult",
    "IRStatus", "IRSeverity", "LEGAL_TRANSITIONS",
]
