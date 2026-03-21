"""
QC Advanced Training — readiness and capability catalog (no secrets in responses).
Used by external training harnesses / UIs to verify all Queen Califia surfaces before drills.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def _env_nonempty(name: str) -> bool:
    return bool((os.environ.get(name) or "").strip())


def _path_ok(p: str | None) -> tuple[bool, str]:
    if not p or not str(p).strip():
        return False, "not configured"
    path = Path(p).expanduser()
    try:
        if path.is_file():
            return True, "file exists"
        parent = path.parent
        if parent.exists() and os.access(parent, os.W_OK):
            return True, "parent writable (will create)"
        return False, "path not reachable"
    except OSError as exc:
        return False, str(exc)


def build_capabilities_catalog() -> list[dict[str, Any]]:
    """Stable list of ability areas an advanced training module should exercise."""
    return [
        {
            "id": "cyber_chat",
            "name": "QC Console / conversation",
            "probe_hints": [
                "POST /api/chat/ with mode cyber|research|lab",
                "Verify engine field: anthropic:*, openai:*, or local (meta-routing)",
            ],
            "env_signals": ["QC_LLM_URL", "QC_LLM_API_KEY", "QC_LLM_MODEL"],
        },
        {
            "id": "vulnerability_engine",
            "name": "Vulnerability scan & remediation",
            "probe_hints": [
                "POST /api/vulns/scan with acknowledge_authorized + X-QC-API-Key",
                "GET /api/vulns/remediation",
                "Optional: Celery path requires QC_REDIS_URL + worker",
            ],
            "env_signals": ["QC_REDIS_URL", "QC_USE_CELERY", "QC_API_KEYS_FILE"],
        },
        {
            "id": "market_research",
            "name": "Research & Quant / market adapters",
            "probe_hints": [
                "GET /api/market/sources",
                "GET /api/market/snapshot or related market routes",
            ],
            "env_signals": ["FRED_API_KEY", "NASDAQ_API_KEY"],
        },
        {
            "id": "forecast_lab",
            "name": "Forecast lab",
            "probe_hints": ["POST /api/forecast/run", "GET /api/forecast/status (if exposed)"],
            "env_signals": [],
        },
        {
            "id": "identity_core",
            "name": "Identity Core / persona / learning",
            "probe_hints": [
                "GET /api/identity/state",
                "Admin routes may require X-QC-Admin-Key",
            ],
            "env_signals": ["QC_ADMIN_KEY"],
        },
        {
            "id": "telemetry_predictor",
            "name": "Telemetry & zero-day predictor (gateway)",
            "probe_hints": [
                "GET /api/v1/telemetry/summary",
                "GET /api/v1/predictor/status",
                "POST /api/v1/telemetry/advanced/process (when enabled)",
            ],
            "env_signals": [],
        },
        {
            "id": "mesh_incidents",
            "name": "Security mesh / incidents / IOCs",
            "probe_hints": [
                "GET /api/mesh/status",
                "GET /api/incidents",
                "GET /api/iocs",
            ],
            "env_signals": [],
        },
        {
            "id": "evolution_memory",
            "name": "Evolution engine & memory backups",
            "probe_hints": [
                "GET /api/v1/evolution/status",
                "Memory export routes may require X-QC-Memory-Token or admin",
            ],
            "env_signals": ["QC_EVOLUTION_DB", "QC_MEMORY_BACKUP_DIR", "QC_MEMORY_EXPORT_TOKEN"],
        },
        {
            "id": "threat_intel",
            "name": "Threat intelligence auto-sync",
            "probe_hints": ["Engine runs on schedule when QC_THREAT_INTEL_AUTO_SYNC=1"],
            "env_signals": ["QC_THREAT_INTEL_DB", "QC_THREAT_INTEL_AUTO_SYNC"],
        },
    ]


def collect_route_hits(app) -> dict[str, bool]:
    """Which training-relevant routes exist on the mounted Flask app."""
    rules = {r.rule for r in app.url_map.iter_rules()}
    keys = {
        "api_chat": any("/api/chat" in r for r in rules),
        "api_vulns_scan": "/api/vulns/scan" in rules,
        "api_market_sources": "/api/market/sources" in rules,
        "api_forecast": any(r.startswith("/api/forecast") for r in rules),
        "api_identity_state": "/api/identity/state" in rules,
        "api_mesh_status": "/api/mesh/status" in rules,
        "api_incidents": "/api/incidents" in rules,
        "api_iocs": "/api/iocs" in rules,
        "api_telemetry_summary": "/api/v1/telemetry/summary" in rules,
        "api_predictor_status": "/api/v1/predictor/status" in rules,
        "api_evolution_status": "/api/v1/evolution/status" in rules,
        "healthz": "/healthz" in rules,
        "readyz": "/readyz" in rules,
    }
    return keys


def run_readiness_checks(app, settings_db_path: Path | None) -> dict[str, Any]:
    """
    Non-destructive checks. Does not call external LLM APIs (no extra cost).
    """
    checks: list[dict[str, Any]] = []
    mount_errors = app.config.get("qc_mount_debug", {}).get("errors", []) or []

    # Blueprint mount
    checks.append({
        "id": "dashboard_blueprints",
        "ok": len(mount_errors) == 0,
        "severity": "critical",
        "detail": "no mount errors" if not mount_errors else "see mount_errors",
        "mount_errors": mount_errors[:3] if mount_errors else [],
    })

    routes = collect_route_hits(app)
    checks.append({
        "id": "routes_conversation",
        "ok": routes.get("api_chat", False),
        "severity": "critical",
        "detail": "/api/chat mounted" if routes.get("api_chat") else "conversation blueprint missing",
        "routes": {"api_chat": routes.get("api_chat")},
    })
    checks.append({
        "id": "routes_vulnerability",
        "ok": routes.get("api_vulns_scan", False),
        "severity": "critical",
        "detail": "/api/vulns/scan present" if routes.get("api_vulns_scan") else "vuln route missing",
    })
    checks.append({
        "id": "routes_market_identity",
        "ok": routes.get("api_market_sources", False) and routes.get("api_identity_state", False),
        "severity": "high",
        "detail": "market + identity routes",
        "routes": {
            "market_sources": routes.get("api_market_sources"),
            "identity_state": routes.get("api_identity_state"),
        },
    })
    checks.append({
        "id": "routes_gateway_advanced",
        "ok": routes.get("api_telemetry_summary", False) and routes.get("api_predictor_status", False),
        "severity": "medium",
        "detail": "telemetry + predictor on gateway",
        "routes": {
            "telemetry_summary": routes.get("api_telemetry_summary"),
            "predictor_status": routes.get("api_predictor_status"),
        },
    })
    checks.append({
        "id": "routes_evolution",
        "ok": routes.get("api_evolution_status", False),
        "severity": "medium",
        "detail": "/api/v1/evolution/status present" if routes.get("api_evolution_status") else "evolution route missing",
    })
    checks.append({
        "id": "routes_health",
        "ok": routes.get("healthz", False) and routes.get("readyz", False),
        "severity": "high",
        "detail": "healthz + readyz",
    })

    # Conversation LLM bridge (configured, not validated)
    llm_url = _env_nonempty("QC_LLM_URL")
    llm_key = _env_nonempty("QC_LLM_API_KEY")
    checks.append({
        "id": "llm_bridge_configured",
        "ok": llm_url and llm_key,
        "severity": "medium",
        "detail": "QC_LLM_URL and QC_LLM_API_KEY set" if (llm_url and llm_key) else "LLM env incomplete — advanced dialogue drills fall back to local core",
        "hints": ["Set QC_LLM_URL (e.g. https://api.anthropic.com/v1/messages)", "Set QC_LLM_API_KEY", "Set QC_LLM_MODEL to a Claude model id"],
    })

    # DB
    db_path = settings_db_path or Path(os.environ.get("QC_DB_PATH", "data/qc_os.db"))
    db_ok, db_msg = _path_ok(str(db_path))
    checks.append({
        "id": "conversation_database",
        "ok": db_ok,
        "severity": "critical",
        "detail": db_msg,
        "path": str(db_path),
    })

    # Async scans
    redis_ok = _env_nonempty("QC_REDIS_URL")
    checks.append({
        "id": "async_scan_queue",
        "ok": redis_ok,
        "severity": "high",
        "detail": "QC_REDIS_URL set — async vuln queue likely healthy" if redis_ok else "no Redis URL — async scans may 503 in production profile",
    })

    # Market live data
    fred = _env_nonempty("FRED_API_KEY")
    nasdaq = _env_nonempty("NASDAQ_API_KEY")
    checks.append({
        "id": "market_provider_keys",
        "ok": fred or nasdaq,
        "severity": "low",
        "detail": "FRED and/or Nasdaq configured" if (fred or nasdaq) else "macro/market drills may show degraded or placeholder data",
    })

    # Admin for identity admin routes
    admin = _env_nonempty("QC_ADMIN_KEY") or _env_nonempty("QC_API_KEYS_FILE")
    checks.append({
        "id": "admin_or_structured_keys",
        "ok": admin,
        "severity": "medium",
        "detail": "admin or keys.json path configured" if admin else "admin-gated training probes may 403",
    })

    # Training module opt-in
    training_on = os.environ.get("QC_ADVANCED_TRAINING", "").strip().lower() in ("1", "true", "yes", "on")
    checks.append({
        "id": "advanced_training_flag",
        "ok": True,
        "severity": "info",
        "detail": "QC_ADVANCED_TRAINING enabled in env" if training_on else "optional: set QC_ADVANCED_TRAINING=1 to mark environment as training-certified",
        "qc_advanced_training": training_on,
    })

    critical_ok = all(c["ok"] for c in checks if c.get("severity") == "critical")
    high_ok = all(c["ok"] for c in checks if c.get("severity") == "high")

    return {
        "schema_version": 1,
        "ready_for_advanced_training": bool(critical_ok and high_ok),
        "ready_summary": {
            "critical_ok": critical_ok,
            "high_ok": high_ok,
        },
        "checks": checks,
        "capabilities_catalog": build_capabilities_catalog(),
        "training_module_notes": [
            "Call GET /api/training/readiness with X-QC-API-Key before batch drills.",
            "Do not expose Anthropic keys in browser UIs — proxy through this API or use qc_training_accelerator.py server-side.",
            "Meta-intents in conversation may bypass LLM by design; use open-ended cyber scenarios to exercise Claude.",
        ],
    }
