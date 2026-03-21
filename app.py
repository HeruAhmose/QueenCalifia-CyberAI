"""QueenCalifia Quantum CyberAI — Application Entrypoints
======================================================

Production notes (defense-oriented defaults):
- Run behind a TLS-terminating reverse proxy (mTLS if required).
- Prefer a single API worker unless you externalize state (Redis/Postgres/etc.).
- Secrets MUST be injected via environment variables or a secret manager.

Environment:
- QC_PORT / QC_HOST
- QC_PRODUCTION=1 (enables stricter headers/HSTS behavior)
- QC_API_KEYS_FILE (JSON) or QC_API_KEYS_JSON (JSON string)
- QC_API_KEY_PEPPER (recommended) and QC_AUDIT_HMAC_KEY (recommended)
- QC_SCAN_ALLOWLIST (comma-separated CIDRs, e.g. "10.0.0.0/8,192.168.0.0/16")
- QC_THREAT_INTEL_AUTO_SYNC / QC_PRODUCTION — threat-feed sync defaults on in production when unset
- QC_AUTONOMY_* — background identity learning + optional 127.0.0.1 quick scans (core/autonomy_loop.py)
- QC_AUTO_LEARNING_INTERVAL_MINUTES — throttle for biomimetic identity cycle
"""

from __future__ import annotations

import os
import sys
import json
import logging
import hashlib

from core.logging_setup import configure_logging
import argparse

from api.gateway import create_security_api, SecurityConfig
from flask import request
from core.tamerian_mesh import TamerianSecurityMesh
from engines.vulnerability_engine import VulnerabilityEngine
from engines.incident_response import IncidentResponseOrchestrator
from engines.auto_remediation import AutoRemediation
from engines.evolution_engine import EvolutionEngine
from engines.zero_day_predictor import ZeroDayPredictor
from engines.advanced_telemetry import AdvancedTelemetry
from engines.threat_intel_auto import ThreatIntelEngine
from core.autonomy_loop import start_autonomy_loop

configure_logging()
logger = logging.getLogger("queencalifia")

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _parse_origins(origins_str: str) -> list[str]:
    if not origins_str:
        # Defaults when QC_CORS_ORIGINS is unset (local dev): include Firebase URLs so
        # browser fetches from hosted dashboards are not blocked by CORS.
        return [
            "https://queencalifia.tamerian.com",
            "https://queencalifia-cyberai.web.app",
            "https://queencalifia-cyberai.firebaseapp.com",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:4173",
            "http://localhost:5000",
        ]
    return [o.strip() for o in origins_str.split(",") if o.strip()]


def build_system(no_auth: bool, origins: str) -> dict:
    """Build and wire all subsystems. Safe to call from WSGI factories."""
    mesh_config = {
        "detection_threads": int(os.environ.get("QC_DETECTION_THREADS", 8)),
        "conn_burst_threshold": int(os.environ.get("QC_CONN_BURST", 100)),
        "auth_fail_threshold": int(os.environ.get("QC_AUTH_FAIL", 5)),
        "anomaly_z_threshold": float(os.environ.get("QC_ANOMALY_Z", 3.0)),
    }
    security_mesh = TamerianSecurityMesh(config=mesh_config)

    vuln_config = {
        "scan_threads": int(os.environ.get("QC_SCAN_THREADS", 32)),
        "max_scans_per_minute": int(os.environ.get("QC_MAX_SCANS", 10)),
        "target_allowlist": os.environ.get("QC_SCAN_ALLOWLIST", ""),
        "deny_public_targets": os.environ.get("QC_DENY_PUBLIC_TARGETS", "1") == "1",
    }
    vuln_engine = VulnerabilityEngine(config=vuln_config)

    incident_orchestrator = IncidentResponseOrchestrator(config={})
    remediator = AutoRemediation()
    evolution_engine = EvolutionEngine()
    try:
        threat_intel = ThreatIntelEngine()
    except Exception:
        threat_intel = None

    # ── Zero-Day Prediction & Advanced Telemetry ──
    predictor_config = {
        "anomaly_z_threshold": float(os.environ.get("QC_ANOMALY_Z", 3.0)),
    }
    zero_day_predictor = ZeroDayPredictor(config=predictor_config)

    telemetry_config = {
        "dns_qps_threshold": int(os.environ.get("QC_DNS_QPS_THRESHOLD", 50)),
        "injection_syscall_threshold": int(os.environ.get("QC_INJECTION_THRESHOLD", 10)),
        "blast_radius_threshold": int(os.environ.get("QC_BLAST_THRESHOLD", 20)),
        "off_hours_start": int(os.environ.get("QC_OFF_HOURS_START", 22)),
        "off_hours_end": int(os.environ.get("QC_OFF_HOURS_END", 5)),
    }
    advanced_telemetry = AdvancedTelemetry(config=telemetry_config)

    def _probe(fn, name: str) -> dict:
        try:
            result = fn()
            if isinstance(result, dict):
                result.setdefault("healthy", True)
                return result
            return {"healthy": bool(result), "metrics": {"probe": name}}
        except Exception as exc:
            logger.warning("health probe failed for %s: %s", name, exc)
            return {"healthy": False, "error": str(exc), "metrics": {"probe": name}}

    def _recover(callback, probe_fn, strategy: str):
        try:
            result = callback()
            probe = _probe(probe_fn, strategy)
            if probe.get("healthy"):
                payload = result if isinstance(result, dict) else {"healed": bool(result)}
                payload.setdefault("strategy", strategy)
                payload["healed"] = True
                return payload
            return {"healed": False, "strategy": strategy, "error": probe.get("error", "post_recovery_probe_failed")}
        except Exception as exc:
            logger.warning("recovery callback failed for %s: %s", strategy, exc)
            return {"healed": False, "strategy": strategy, "error": str(exc)}

    component_specs = {
        "security_mesh": {
            "name": "Security Mesh",
            "probe": lambda: {
                "healthy": bool(security_mesh.nodes) and bool(security_mesh.circuits),
                "metrics": {
                    "nodes": len(security_mesh.nodes),
                    "circuits": len(security_mesh.circuits),
                    "active_threats": len(security_mesh.active_threats),
                },
            },
        },
        "vulnerability_engine": {
            "name": "Vulnerability Engine",
            "probe": vuln_engine.probe_health,
            "recover": lambda: vuln_engine.recover_runtime_state(),
        },
        "incident_response": {
            "name": "Incident Response",
            "probe": incident_orchestrator.probe_health,
            "recover": lambda: incident_orchestrator.reload_persisted_state(),
        },
        "auto_remediation": {
            "name": "Auto Remediation",
            "probe": remediator.probe_health,
            "recover": lambda: remediator.reload_persisted_state(),
        },
        "zero_day_predictor": {
            "name": "Zero Day Predictor",
            "probe": lambda: {
                "healthy": zero_day_predictor.get_status().get("status") == "operational",
                "metrics": {
                    "signal_bus_depth": zero_day_predictor.get_status().get("signal_bus_depth", 0),
                    "active_predictions": zero_day_predictor.get_status().get("active_predictions", {}).get("total", 0),
                },
            },
        },
        "advanced_telemetry": {
            "name": "Advanced Telemetry",
            "probe": lambda: {
                "healthy": advanced_telemetry.check_collection_health().get("overall_health") != "critical",
                "metrics": {
                    "sensors_registered": len(advanced_telemetry.sensors),
                    "overall_health": advanced_telemetry.check_collection_health().get("overall_health"),
                },
            },
        },
    }
    if threat_intel is not None:
        component_specs["threat_intel"] = {
            "name": "Threat Intelligence",
            "probe": threat_intel.probe_health,
            "recover": lambda: threat_intel.recover_runtime_state(),
        }

    for component_id, spec in component_specs.items():
        evolution_engine.register_component(component_id, spec["name"])
        evolution_engine.register_component_probe(
            component_id,
            lambda probe=spec["probe"], cid=component_id: _probe(probe, cid),
        )
        if "recover" in spec:
            evolution_engine.register_component_recovery(
                component_id,
                lambda _cid, recover=spec["recover"], probe=spec["probe"], strategy=component_id: _recover(recover, probe, strategy),
            )

    node_domain_map = {
        "network": ["vulnerability_engine"] + (["threat_intel"] if threat_intel is not None else []),
        "endpoint": ["advanced_telemetry", "auto_remediation"],
        "identity": ["incident_response", "zero_day_predictor"],
        "data": ["security_mesh", "auto_remediation"],
    }

    def _aggregate_probe(component_ids: list[str]) -> dict:
        metrics = {}
        healthy = False
        for component_id in component_ids:
            spec = component_specs.get(component_id)
            if not spec:
                continue
            result = _probe(spec["probe"], component_id)
            metrics[component_id] = result.get("metrics", {})
            healthy = healthy or bool(result.get("healthy"))
            if not healthy and "recover" in spec:
                recovery = _recover(spec["recover"], spec["probe"], component_id)
                healthy = healthy or bool(recovery.get("healed"))
        return {"healthy": healthy, "health": 1.0 if healthy else 0.0, "metrics": metrics}

    for node_id, node in security_mesh.nodes.items():
        component_ids = node_domain_map.get(node.security_domain, ["security_mesh"])
        security_mesh.register_node_recovery_check(
            node_id,
            lambda _nid, component_ids=component_ids: _aggregate_probe(component_ids),
        )

    circuit_component_map = {
        "ingestion_pipeline": ["advanced_telemetry", "threat_intel"] if threat_intel is not None else ["advanced_telemetry"],
        "detection_pipeline": ["security_mesh", "zero_day_predictor"],
        "correlation_pipeline": ["security_mesh", "incident_response"],
        "response_pipeline": ["incident_response", "auto_remediation"],
        "intelligence_pipeline": ["vulnerability_engine", "zero_day_predictor"] + (["threat_intel"] if threat_intel is not None else []),
        "audit_pipeline": ["incident_response", "auto_remediation"],
    }
    for circuit_id, circuit in security_mesh.circuits.items():
        component_ids = circuit_component_map.get(circuit.pipeline_type, ["security_mesh"])
        security_mesh.register_circuit_recovery_check(
            circuit_id,
            lambda _cid, component_ids=component_ids, circuit_id=circuit_id: {
                "healthy": _aggregate_probe(component_ids).get("healthy", False),
                "integrity_hash": hashlib.sha256(circuit_id.encode()).hexdigest()[:16],
            },
        )

    api_config = SecurityConfig(
        require_api_key=not no_auth,
        allowed_origins=_parse_origins(origins),
        rate_limit_requests_per_minute=int(os.environ.get("QC_RATE_LIMIT", 120)),
        enforce_https=os.environ.get("QC_ENFORCE_HTTPS", "0") == "1",
    )

    app = create_security_api(
        security_mesh=security_mesh,
        vuln_engine=vuln_engine,
        incident_orchestrator=incident_orchestrator,
        config=api_config,
        zero_day_predictor=zero_day_predictor,
        advanced_telemetry=advanced_telemetry,
        remediator=remediator,
        evolution_engine=evolution_engine,
        threat_intel=threat_intel,
    )

    # Background identity learning + optional safe localhost scans for evolution
    # (thread + SQLite lease; see core/autonomy_loop.py).
    start_autonomy_loop(
        db_path=os.environ.get("QC_DB_PATH", "data/queen.db"),
        vuln_engine=vuln_engine,
        evolution_engine=evolution_engine,
    )

    return {
        "app": app,
        "security_mesh": security_mesh,
        "vuln_engine": vuln_engine,
        "incident_orchestrator": incident_orchestrator,
        "remediator": remediator,
        "evolution_engine": evolution_engine,
        "zero_day_predictor": zero_day_predictor,
        "advanced_telemetry": advanced_telemetry,
        "threat_intel": threat_intel,
    }


def initialize_system_wsgi():
    """WSGI factory used by Gunicorn."""
    no_auth = os.environ.get("QC_NO_AUTH", "0") == "1"
    origins = os.environ.get("QC_CORS_ORIGINS", "")
    system = build_system(no_auth=no_auth, origins=origins)
    return system["app"]


# Gunicorn default: `app:app`
app = initialize_system_wsgi()


def _print_banner():
    print(
        r"""
╔══════════════════════════════════════════════════════════════╗
║  QUEEN CALIFIA QUANTUM CYBERAI                               ║
║  Defense-Grade Cybersecurity Intelligence Platform           ║
╚══════════════════════════════════════════════════════════════╝
"""
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Queen Califia Quantum CyberAI — Defense-Grade Cybersecurity Platform"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("QC_PORT", 5000)),
        help="API port (default: 5000)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("QC_HOST", "0.0.0.0"),
        help="Bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable API key authentication (development only!)",
    )
    parser.add_argument(
        "--origins",
        default=os.environ.get("QC_CORS_ORIGINS", ""),
        help="Comma-separated CORS origins",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (NEVER in production!)",
    )
    args = parser.parse_args()

    _print_banner()

    if args.no_auth:
        logger.warning("⚠️  API AUTHENTICATION DISABLED — DEVELOPMENT ONLY")
    if args.debug:
        logger.warning("⚠️  DEBUG MODE ENABLED — DEVELOPMENT ONLY")

    system = build_system(no_auth=args.no_auth, origins=args.origins)
    wsgi_app = system["app"]

    logger.info("🚀 Queen Califia CyberAI starting (dev server)")
    print(f"* Running on http://{args.host}:{args.port}"); wsgi_app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

