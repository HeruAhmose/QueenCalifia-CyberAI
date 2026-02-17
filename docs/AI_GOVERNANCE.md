# AI Governance & Sovereignty Controls

> QueenCalifia CyberAI — Defense-Grade AI Action Governance

## Overview

QueenCalifia implements a **centralized sovereignty layer** that governs all AI-driven actions. No engine, model, or automated process can execute state-changing operations without passing through the `SovereigntyExecutor`.

This document describes the governance architecture for enterprise buyers, government reviewers, and compliance auditors.

---

## Architecture: Single Chokepoint

```
Model Output → ModelDecision (schema-validated)
  → ActionPolicy.evaluate()
    → AuditRecord (written BEFORE execution)
      → IdempotencyGuard
        → TaskDispatch (Celery or direct)
```

Every path through this pipeline is:
- **Logged** — audit record written before any action
- **Traceable** — trace_id + request_id propagated end-to-end
- **Deterministic** — policy engine overrides model suggestions
- **Gated** — containment requires human approval in production

---

## Seven Sovereignty Principles

| # | Principle | Implementation |
|---|-----------|---------------|
| 1 | **Structured Output Enforcement** | LLM must return `ModelDecision` Pydantic schema — rejected otherwise |
| 2 | **Confidence Hard Floor** | Containment requires ≥0.92 confidence in production |
| 3 | **Approval Gating** | Production containment requires human `approval_id` |
| 4 | **Audit-First Execution** | Record written BEFORE action — if audit fails, action is blocked |
| 5 | **Dry-Run Default** | Production defaults to `dry_run=True` for dangerous actions |
| 6 | **Prompt Injection Defense** | All untrusted text sanitized before LLM context inclusion |
| 7 | **Deterministic Override** | Policy engine overrides model suggestions based on rules |

---

## Action Allowlist

Only these actions can be executed through the sovereignty layer:

| Action | Risk Level | Min Role | Prod Approval |
|--------|-----------|----------|---------------|
| `none` | — | viewer | No |
| `recommend` | — | viewer | No |
| `escalate` | Low | analyst | No |
| `enable_enhanced_logging` | Low | analyst | No |
| `contain_host` | High | analyst | **Yes** |
| `block_ip` | High | analyst | **Yes** |
| `quarantine_file` | High | analyst | **Yes** |
| `disable_account` | Critical | admin | **Yes** |
| `revoke_tokens` | Critical | admin | **Yes** |
| `rotate_credentials` | Critical | admin | **Yes** |

**No action outside this enum can be executed.** Adding a new action requires a code change, policy update, and review.

---

## Role-Based Access Control (RBAC)

| Role | Level | Capabilities |
|------|-------|-------------|
| `viewer` | 0 | Read-only, recommendations |
| `analyst` | 1 | Escalation, containment (with approval) |
| `admin` | 2 | Account management, credential rotation |
| `system` | 3 | Internal automation (Celery workers) |

---

## Confidence Thresholds

| Environment | Containment Floor | Escalation Floor |
|-------------|------------------|-----------------|
| Production | 0.92 | 0.60 |
| Staging | 0.85 | 0.50 |
| Development | 0.70 | 0.30 |

Configurable via environment variables (`QC_CONF_FLOOR_*`).

---

## Prompt Injection Defense

All external text is sanitized before inclusion in LLM context:

- **Injection patterns** — "ignore previous instructions", system prompt extraction, role hijacking
- **Dangerous payloads** — XSS vectors, command injection, path traversal
- **Secret patterns** — API keys, AWS credentials, private keys, tokens

Sanitization events are logged with context labels for forensic review.

---

## Audit Trail

Every sovereignty decision produces an immutable audit record containing:

- `timestamp`, `outcome` (DENIED/EXECUTING/DRY_RUN/EXECUTED)
- `tenant_id`, `trace_id`, `request_id`
- `actor_role`, `environment`, `dry_run`
- `approval_id` (if present)
- `action`, `confidence`, `risk`, `targets`
- `decision_hash` (SHA-256 of model output for tamper detection)
- `policy_rule`, `policy_reason`

---

## Zero-Trust Network Policies

Kubernetes deployments enforce deny-by-default network policies:

- All ingress/egress denied by default
- Explicit allow rules for: Ingress→API, Ingress→Frontend, API→Redis, Worker→Redis
- Pod security: `runAsNonRoot`, `readOnlyRootFilesystem`, `drop: ALL` capabilities

---

## Compliance Alignment

| Framework | Coverage |
|-----------|---------|
| NIST SP 800-61 | Incident response lifecycle |
| NIST AI RMF | Model governance, risk management |
| MITRE ATT&CK | Technique mapping in predictions + incidents |
| OWASP Top 10 | Input validation, XSS defense, injection prevention |
| CIS Controls | Security configuration, access management |
| SOC 2 Type II | Audit trail, access controls, monitoring |

---

## Operational Controls

- **Feature flag**: `QC_CONTAINMENT_MODE=approval` (default OFF for auto-actions)
- **Break-glass**: Admin can set `QC_CONTAINMENT_MODE=auto` for emergency response
- **Dry-run**: All dangerous actions default to dry-run in production
- **Idempotency**: Duplicate containment actions are detected and skipped
- **Continuous scanning**: CI pipeline includes `pip-audit`, `bandit`, SBOM generation
