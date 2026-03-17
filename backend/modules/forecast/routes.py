"""QC OS — Forecast, Portfolio & Quant Routes (complete)"""
from __future__ import annotations
from flask import Blueprint, jsonify, request, current_app
from core.auth import require_api_key, require_admin
from modules.forecast.engine import (
    create_forecast_run, create_paper_portfolio, list_paper_portfolios, compute_risk_budget,
)
from modules.market.engine import analyze_portfolio, run_quant_optimizer

forecast_bp = Blueprint("forecast", __name__)


@forecast_bp.post("/run")
@require_api_key
def run_forecast():
    """Dispatch to regime_detection, telemetry_forecast, scenario, signal_ensemble, risk_budget."""
    payload = request.get_json(silent=True) or {}
    user_id = str(payload.get("user_id", "anonymous"))
    run_type = str(payload.get("run_type", ""))
    input_data = payload.get("input", {})

    valid = ["regime_detection", "telemetry_forecast", "scenario", "signal_ensemble", "risk_budget", "optimization"]
    if run_type not in valid:
        return jsonify({"error": f"run_type must be one of: {valid}"}), 400

    settings = current_app.config["settings"]
    result = create_forecast_run(settings.db_path, user_id, run_type, input_data)
    return jsonify(result)


@forecast_bp.post("/portfolio/create")
@require_api_key
def create_portfolio():
    payload = request.get_json(silent=True) or {}
    user_id = str(payload.get("user_id", "anonymous"))
    name = str(payload.get("name", "Untitled"))
    holdings = payload.get("holdings", {})
    if not holdings or not isinstance(holdings, dict):
        return jsonify({"error": "holdings must be a non-empty dict {asset: value}"}), 400
    settings = current_app.config["settings"]
    return jsonify(create_paper_portfolio(settings.db_path, user_id, name, holdings))


@forecast_bp.get("/portfolio/list")
@require_api_key
def list_portfolios():
    user_id = request.args.get("user_id", "anonymous")
    settings = current_app.config["settings"]
    return jsonify({"portfolios": list_paper_portfolios(settings.db_path, user_id)})


@forecast_bp.post("/portfolio/risk")
@require_api_key
def risk_budget():
    """Simple risk budget: {holdings: {asset: value}, max_drawdown: 0.15}"""
    payload = request.get_json(silent=True) or {}
    holdings = payload.get("holdings", {})
    if not holdings:
        return jsonify({"error": "holdings required"}), 400
    return jsonify(compute_risk_budget(holdings, payload.get("max_drawdown", 0.15)))


@forecast_bp.post("/portfolio/analyze")
@require_api_key
def portfolio_analyze():
    """Detailed analysis: [{symbol, asset_type, units, latest_price, cost_basis}]"""
    payload = request.get_json(silent=True) or {}
    holdings = payload.get("holdings")
    if not isinstance(holdings, list) or not holdings:
        return jsonify({"error": "holdings must be a non-empty array"}), 400
    settings = current_app.config["settings"]
    return jsonify(analyze_portfolio(settings, holdings))


@forecast_bp.post("/quant/run")
@require_admin
def quant_run():
    """Admin-only: guarded research optimizer."""
    payload = request.get_json(silent=True) or {}
    settings = current_app.config["settings"]
    result = run_quant_optimizer(settings, payload)
    from core.database import audit
    audit(settings.db_path, "quant_run", "admin", None, {
        "engine_mode": result.get("engine_mode"), "quantum_ready": result.get("quantum_ready")})
    return jsonify(result)


@forecast_bp.post("/admin/promote-signal")
@require_admin
def promote_signal():
    """Admin-only: promote a completed forecast run's signals."""
    payload = request.get_json(silent=True) or {}
    run_id = payload.get("run_id", "")
    if not run_id:
        return jsonify({"error": "run_id required"}), 400

    from core.database import get_db, audit
    settings = current_app.config["settings"]

    with get_db(settings.db_path) as conn:
        run = conn.execute(
            "SELECT * FROM forecast_runs WHERE id = ? AND status = 'completed'", (run_id,)
        ).fetchone()
        if not run:
            return jsonify({"error": "run not found or not completed"}), 404
        conn.execute("UPDATE forecast_runs SET promoted = 1, status = 'reviewed' WHERE id = ?", (run_id,))

    audit(settings.db_path, "signal_promote", "admin", run_id, {"run_type": run["run_type"]})
    return jsonify({"promoted": True, "run_id": run_id})
