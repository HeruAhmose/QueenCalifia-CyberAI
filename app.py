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
"""

from __future__ import annotations

import os
import sys
import json
import logging

from core.logging_setup import configure_logging
import argparse

from api.gateway import create_security_api, SecurityConfig
from core.tamerian_mesh import TamerianSecurityMesh
from engines.vulnerability_engine import VulnerabilityEngine
from engines.incident_response import IncidentResponseOrchestrator
from engines.zero_day_predictor import ZeroDayPredictor
from engines.advanced_telemetry import AdvancedTelemetry

configure_logging()
logger = logging.getLogger("queencalifia")

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _parse_origins(origins_str: str) -> list[str]:
    if not origins_str:
        return [
            "https://queencalifia.tamerian.com",
            "http://localhost:3000",
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
    )

    return {
        "app": app,
        "security_mesh": security_mesh,
        "vuln_engine": vuln_engine,
        "incident_orchestrator": incident_orchestrator,
        "zero_day_predictor": zero_day_predictor,
        "advanced_telemetry": advanced_telemetry,
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
    wsgi_app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
