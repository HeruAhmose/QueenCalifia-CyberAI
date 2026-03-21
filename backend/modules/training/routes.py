"""QC Advanced Training API — capability catalog and readiness (authenticated)."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from core.auth import require_api_key
from modules.training.readiness_engine import build_capabilities_catalog, run_readiness_checks

training_bp = Blueprint("training", __name__)


@training_bp.get("/capabilities-catalog")
def capabilities_catalog():
    """
    Public catalog of ability areas for training harnesses (no secrets, no auth).
    Safe to cache; use with GET /readiness for environment-specific status.
    """
    return jsonify(
        {
            "schema_version": 1,
            "name": "Queen Califia Advanced Training — capability catalog",
            "capabilities": build_capabilities_catalog(),
        },
    ), 200


@training_bp.get("/readiness")
@require_api_key
def training_readiness():
    """
    Full subsystem checklist for advanced training modules.
    Requires the same API key as /api/chat/ (or QC_NO_AUTH=1 for dev).
    """
    settings = current_app.config.get("settings")
    db_path = getattr(settings, "db_path", None) if settings else None
    payload = run_readiness_checks(current_app, db_path)
    # Always 200 so harnesses can parse JSON; use ready_for_advanced_training boolean.
    return jsonify(payload), 200
