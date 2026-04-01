"""
QC OS backend entrypoint for Render.

Your onrender service runs `gunicorn app:app` with `rootDir: backend`.
This repository includes a *root* `app.py` (from a previous working release)
that wires `api/gateway.py` + `engines/vulnerability_engine.py`, exposing the
real vulnerability scan/remediation endpoints under `/api/vulns/*`.

This file intentionally re-exports that root WSGI app so the Render command
remains unchanged while vulnerability routes work end-to-end.
"""

from __future__ import annotations

import importlib.util
import os
import sys

from dotenv import load_dotenv
from flask_cors import CORS


def _load_root_app():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root in sys.path:
        sys.path.remove(repo_root)
    # Keep repo root at the front so `import core.*` resolves to repo-root core
    # even when callers have already prepended `backend/` to `sys.path`.
    sys.path.insert(0, repo_root)

    root_app_path = os.path.join(repo_root, "app.py")
    spec = importlib.util.spec_from_file_location("qc_root_app", root_app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load root app module from: {root_app_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


load_dotenv()
app = _load_root_app()

from core.database import init_db
from core.settings import get_settings, parse_origins

settings = get_settings()
init_db(settings.db_path)

# Make settings available to the dashboard route modules.
app.config["settings"] = settings

# Enable CORS for all dashboard API requests, including admin-gated browser flows.
CORS(
    app,
    resources={r"/api/*": {"origins": parse_origins(settings.cors_origins)}},
    supports_credentials=False,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-QC-API-Key", "X-QC-Admin-Key"],
)

# Mount the dashboard-friendly blueprints onto the security-gateway app.
# (The root security app mainly provides vuln routes; the dashboard UI also
# expects market/forecast/identity endpoints.)
qc_mount_debug = {"errors": []}
try:
    # Ensure `backend/` is on sys.path so imports like `modules.market.routes`
    # resolve correctly (gunicorn sets rootDir=backend, but local imports may not).
    backend_dir = os.path.dirname(__file__)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    from modules.conversation.routes import conversation_bp
    from modules.market.routes import market_bp
    from modules.forecast.routes import forecast_bp
    from modules.identity.routes import identity_bp
    from modules.training.routes import training_bp

    app.register_blueprint(conversation_bp, url_prefix="/api/chat")
    app.register_blueprint(market_bp, url_prefix="/api/market")
    app.register_blueprint(forecast_bp, url_prefix="/api/forecast")
    app.register_blueprint(identity_bp, url_prefix="/api/identity")
    app.register_blueprint(training_bp, url_prefix="/api/training")
except Exception:
    import traceback
    qc_mount_debug["errors"].append(traceback.format_exc())

app.config["qc_mount_debug"] = qc_mount_debug

# Public dashboard bootstrap config.
@app.get("/api/config")
def qc_public_config():
    no_auth = os.getenv("QC_NO_AUTH", "0") == "1"
    return {
        "name": settings.name,
        "persona": settings.persona,
        "capabilities": [
            "cyber_guardian",
            "research_companion",
            "forecast_lab",
            "identity_core",
            "vulnerability_scanning",
            "evolution_memory",
            "advanced_training_readiness",
            "post_quantum_readiness",
        ],
        "training": {
            "capabilities_catalog_url": "/api/training/capabilities-catalog",
            "readiness_url": "/api/training/readiness",
            "readiness_auth": "Same as chat: X-QC-API-Key (or QC_NO_AUTH=1 for dev).",
        },
        "welcome_message": (
            f"{settings.name} online. Cyber, research, quant, and identity systems are ready. "
            "Choose a mode and give me a concrete objective."
        ),
        "no_auth": no_auth,
    }, 200

# Lightweight introspection endpoint (safe; no secrets).
@app.get("/api/debug/mount")
def qc_debug_mount():
    rules = [(r.rule, tuple(sorted(r.methods or []))) for r in app.url_map.iter_rules()]
    has_market_sources = any(r[0] == "/api/market/sources" for r in rules)
    has_identity_state = any(r[0] == "/api/identity/state" for r in rules)
    has_vuln_scan = any(r[0] == "/api/vulns/scan" for r in rules)
    has_training = any(r[0].startswith("/api/training/") for r in rules)
    return {
        "has_market_sources": has_market_sources,
        "has_identity_state": has_identity_state,
        "has_vuln_scan": has_vuln_scan,
        "has_training_api": has_training,
        "errors": app.config.get("qc_mount_debug", {}).get("errors", []),
    }, 200


__all__ = ["app"]
