"""QC OS — Market Intelligence Routes (clean: data sources only)"""
from __future__ import annotations
import requests
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
    try:
        return jsonify(get_market_snapshot(current_app.config["settings"], at, sym))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@market_bp.get("/fred/<series_id>")
@require_api_key
def fred(series_id):
    try:
        return jsonify(fetch_fred(current_app.config["settings"], series_id))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@market_bp.get("/nasdaq/<path:dataset>")
@require_api_key
def nasdaq(dataset):
    limit = request.args.get("limit", 30, type=int)
    try:
        return jsonify(fetch_nasdaq(current_app.config["settings"], dataset, limit))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except requests.HTTPError as e:
        detail = None
        if e.response is not None:
            try:
                detail = e.response.json()
            except Exception:
                detail = (e.response.text or "")[:500] or None
        return jsonify(
            {
                "error": "nasdaq_upstream_error",
                "upstream_status": e.response.status_code if e.response else None,
                "detail": detail,
            }
        ), 502
    except requests.RequestException as e:
        return jsonify({"error": "nasdaq_request_failed", "message": str(e)}), 502


@market_bp.get("/sources")
@require_api_key
def sources():
    return jsonify(get_sources_status(current_app.config["settings"]))
