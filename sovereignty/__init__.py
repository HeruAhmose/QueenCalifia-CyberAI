# sovereignty — AI Action Control & Governance Layer
#
# This module implements the centralized chokepoint for all AI-driven
# actions in QueenCalifia CyberAI.  No engine, model, or task may
# execute containment, escalation, or remediation without passing
# through the SovereigntyExecutor.
#
# Architecture:
#   Model Output → ModelDecision (schema-validated)
#     → ActionPolicy.evaluate()
#       → AuditRecord (written BEFORE execution)
#         → IdempotencyGuard
#           → TaskDispatch (Celery or direct)
#
# Design Principles:
#   1. Structured output enforcement — LLM must return ModelDecision schema
#   2. Confidence hard floor — containment requires ≥0.92 in production
#   3. Approval gating — prod containment requires human approval_id
#   4. Audit-first — record written before any action executes
#   5. Dry-run default — production defaults to dry_run=True
#   6. Prompt injection defense — all untrusted text sanitized before LLM
#   7. Deterministic override — policy engine overrides model suggestions

from sovereignty.schemas import (
    ModelDecision,
    ActionRequest,
    ProposedAction,
    RiskLevel,
    EvidenceRef,
)
from sovereignty.action_policy import ActionPolicy, PolicyDecision
from sovereignty.executor import SovereigntyExecutor, SovereigntyError
from sovereignty.prompt_guard import sanitize_untrusted_text, scan_for_injection

__all__ = [
    "ModelDecision",
    "ActionRequest",
    "ProposedAction",
    "RiskLevel",
    "EvidenceRef",
    "ActionPolicy",
    "PolicyDecision",
    "SovereigntyExecutor",
    "SovereigntyError",
    "sanitize_untrusted_text",
    "scan_for_injection",
]
