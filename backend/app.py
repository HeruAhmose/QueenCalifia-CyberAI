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

from core.database import init_db
from core.settings import get_settings, parse_origins


def _load_root_app():
    # Dashboard UX assumes the API is reachable without you needing to paste an
    # API key. Default to allowing requests unless explicitly configured.
    os.environ.setdefault("QC_NO_AUTH", "1")

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        # Keep repo root at the front so `import core.*` resolves to repo-root core.
        sys.path.insert(0, repo_root)

    root_app_path = os.path.join(repo_root, "app.py")
    spec = importlib.util.spec_from_file_location("qc_root_app", root_app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load root app module from: {root_app_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


load_dotenv()
settings = get_settings()
init_db(settings.db_path)

app = _load_root_app()

# Make settings available to the dashboard route modules.
app.config["settings"] = settings

# Enable CORS for all dashboard API requests.
CORS(app, resources={r"/api/*": {"origins": parse_origins(settings.cors_origins)}}, supports_credentials=False)

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

    app.register_blueprint(conversation_bp, url_prefix="/api/chat")
    app.register_blueprint(market_bp, url_prefix="/api/market")
    app.register_blueprint(forecast_bp, url_prefix="/api/forecast")
    app.register_blueprint(identity_bp, url_prefix="/api/identity")
except Exception:
    import traceback
    qc_mount_debug["errors"].append(traceback.format_exc())

app.config["qc_mount_debug"] = qc_mount_debug

# Lightweight introspection endpoint (safe; no secrets).
@app.get("/api/debug/mount")
def qc_debug_mount():
    rules = [(r.rule, tuple(sorted(r.methods or []))) for r in app.url_map.iter_rules()]
    has_market_sources = any(r[0] == "/api/market/sources" for r in rules)
    has_identity_state = any(r[0] == "/api/identity/state" for r in rules)
    has_vuln_scan = any(r[0] == "/api/vulns/scan" for r in rules)
    return {
        "has_market_sources": has_market_sources,
        "has_identity_state": has_identity_state,
        "has_vuln_scan": has_vuln_scan,
        "errors": app.config.get("qc_mount_debug", {}).get("errors", []),
    }, 200


__all__ = ["app"]
