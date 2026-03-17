"""QC OS — Market Intelligence Routes (clean: data sources only)"""
from __future__ import annotations
from flask import Blueprint, jsonify, request, current_app
from core.auth import require_api_key
from modules.market.engine import (
    get_market_snapshot, get_sources_status, fetch_fred, fetch_nasdaq,
)

market_bp = Blueprint("market", __name__)


@market_bp.get("/snapshot")
@require_api_key
def snapshot():
    at = request.args.get("asset_type", "").strip().lower()
    sym = request.args.get("symbol", "").strip().upper()
    if not at or not sym:
        return jsonify({"error": "asset_type and symbol required"}), 400
    return jsonify(get_market_snapshot(current_app.config["settings"], at, sym))


@market_bp.get("/fred/<series_id>")
@require_api_key
def fred(series_id):
    return jsonify(fetch_fred(current_app.config["settings"], series_id))


@market_bp.get("/nasdaq/<path:dataset>")
@require_api_key
def nasdaq(dataset):
    limit = request.args.get("limit", 30, type=int)
    return jsonify(fetch_nasdaq(current_app.config["settings"], dataset, limit))


@market_bp.get("/sources")
@require_api_key
def sources():
    return jsonify(get_sources_status(current_app.config["settings"]))
