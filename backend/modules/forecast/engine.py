"""
QC OS — Forecast & Portfolio Lab (combined definitive)
=======================================================
Merges both approaches into one unified forecast module:

  FROM v4.2:
    - Regime detection (volatility regimes + trend states via SMA crossover)
    - Scenario analysis (what-if portfolio shocks)
    - Signal ensemble (multi-source weighted combination)
    - Risk budgeting (HHI concentration + drawdown limits)
    - Paper trading (shadow portfolios with CRUD)
    - Admin-only signal promotion

  FROM ChatGPT bootstrap:
    - Momentum/vol/mean-return computed from stored snapshot history
    - Telemetry-based heuristic signals (bullish_watch, bearish_watch, range)
    - History-dependent confidence scoring

  COMBINED:
    - detect_regime() now includes momentum + mean_return + return_vol alongside
      annualized vol + SMA trend — one function, all metrics
    - forecast_from_history() runs full regime detection on stored snapshots,
      then layers on telemetry signal classification + confidence scoring
    - New signal types: risk_off (crisis regime), quiet_accumulation (low vol + up)
    - Signal ensemble for combining multiple forecast outputs

All outputs are research-grade. Paper trading only unless admin-promoted.
"""
from __future__ import annotations

import json
import math
import uuid
from statistics import mean, pstdev

from core.database import get_db, get_market_history, utc_now, audit


# ═══════════════════════════════════════════════════════════════
#  REGIME DETECTION (combined: vol regimes + trend + momentum + mean)
# ═══════════════════════════════════════════════════════════════

def detect_regime(prices: list[float], window: int = 20) -> dict:
    """
    Combined regime detector:
    - Annualized volatility → regime classification (low/normal/high/crisis)
    - SMA crossover → trend direction (bullish/bearish)
    - Momentum → total return over period
    - Mean return → average drift per period
    - Return volatility → standard deviation of returns
    """
    if len(prices) < window + 1:
        return {"regime": "insufficient_data", "confidence": 0.0,
                "note": f"Need at least {window + 1} price points."}

    returns = [(prices[i] - prices[i - 1]) / prices[i - 1]
               for i in range(1, len(prices)) if prices[i - 1] != 0]

    if not returns:
        return {"regime": "insufficient_data", "confidence": 0.0}

    recent_returns = returns[-window:]
    vol = math.sqrt(sum(r ** 2 for r in recent_returns) / len(recent_returns)) * math.sqrt(252)

    if vol < 0.10:
        regime = "low_volatility"
    elif vol < 0.20:
        regime = "normal"
    elif vol < 0.35:
        regime = "high_volatility"
    else:
        regime = "crisis"

    sma_short = sum(prices[-5:]) / min(5, len(prices))
    sma_long = sum(prices[-window:]) / min(window, len(prices))
    trend = "bullish" if sma_short > sma_long else "bearish"

    momentum = (prices[-1] - prices[0]) / prices[0] if prices[0] != 0 else 0.0
    mean_return = mean(returns) if returns else 0.0
    return_vol = pstdev(returns) if len(returns) > 1 else 0.0

    confidence = min(0.7 + (len(prices) / 500), 0.92)

    return {
        "regime": regime,
        "trend": trend,
        "annualized_vol": round(vol, 4),
        "return_vol": round(return_vol, 6),
        "momentum": round(momentum, 6),
        "mean_return": round(mean_return, 6),
        "sma_short": round(sma_short, 2),
        "sma_long": round(sma_long, 2),
        "data_points": len(prices),
        "window": window,
        "confidence": round(confidence, 4),
        "note": "Research output only. Not a trading signal.",
    }


# ═══════════════════════════════════════════════════════════════
#  TELEMETRY FORECAST (from stored market snapshots + regime)
# ═══════════════════════════════════════════════════════════════

def forecast_from_history(db_path, asset_type: str, symbol: str, horizon: str = "short") -> dict:
    """
    Forecast using locally stored snapshot history.
    Runs full regime detection, then layers signal classification on top.
    """
    history = get_market_history(db_path, asset_type, symbol, limit=50)
    prices = [float(h["price"]) for h in history if h.get("price") not in (None, 0)]

    if len(prices) < 3:
        return {
            "asset_type": asset_type, "symbol": symbol, "horizon": horizon,
            "signal": "observe", "confidence": 0.18,
            "rationale": "Not enough local telemetry. Pull more snapshots over time.",
            "history_points": len(prices), "mode": "telemetry_stub",
        }

    window = min(20, max(3, len(prices) - 1))
    regime = detect_regime(prices, window=window)

    momentum = regime.get("momentum", 0.0)
    vol = regime.get("return_vol", 0.0)
    regime_state = regime.get("regime", "unknown")

    if regime_state == "crisis":
        signal = "risk_off"
    elif momentum > 0.015 and vol < 0.03:
        signal = "bullish_watch"
    elif momentum < -0.015 and vol < 0.03:
        signal = "bearish_watch"
    elif regime_state == "low_volatility" and momentum > 0:
        signal = "quiet_accumulation"
    else:
        signal = "range_or_unclear"

    confidence = max(0.15, min(0.72, abs(momentum) * 4 + max(0.0, 0.04 - vol)))

    return {
        "asset_type": asset_type,
        "symbol": symbol,
        "horizon": horizon,
        "signal": signal,
        "confidence": round(confidence, 4),
        "regime": regime,
        "telemetry": {
            "history_points": len(prices),
            "momentum": round(momentum, 6),
            "mean_return": regime.get("mean_return", 0.0),
            "volatility": regime.get("return_vol", 0.0),
            "trend": regime.get("trend", "unknown"),
            "regime_state": regime_state,
        },
        "rationale": (
            "Combined telemetry forecast: regime detection + momentum/volatility analysis "
            "from locally stored snapshot history. Research only."
        ),
        "mode": "telemetry_combined",
    }


# ═══════════════════════════════════════════════════════════════
#  SCENARIO ANALYSIS (what-if shocks)
# ═══════════════════════════════════════════════════════════════

def run_scenario(holdings: dict[str, float], scenarios: list[dict]) -> list[dict]:
    total_value = sum(holdings.values())
    results = []

    for scenario in scenarios:
        name = scenario.get("name", "unnamed")
        portfolio_return = 0.0

        for asset, value in holdings.items():
            weight = value / total_value if total_value > 0 else 0
            shock = scenario.get(asset, 0.0)
            portfolio_return += weight * shock

        new_value = total_value * (1 + portfolio_return)

        results.append({
            "scenario": name,
            "portfolio_return": round(portfolio_return, 4),
            "current_value": round(total_value, 2),
            "stressed_value": round(new_value, 2),
            "loss": round(total_value - new_value, 2),
            "max_component_shock": round(min(scenario.get(a, 0.0) for a in holdings), 4),
            "note": "Hypothetical scenario. Not a prediction.",
        })

    return results


# ═══════════════════════════════════════════════════════════════
#  SIGNAL ENSEMBLE (multi-source weighted combination)
# ═══════════════════════════════════════════════════════════════

def run_signal_ensemble(signals: list[dict]) -> dict:
    if not signals:
        return {"ensemble_signal": "no_signals", "confidence": 0.0}

    total_weight = sum(s.get("confidence", 0.5) for s in signals)
    if total_weight == 0:
        return {"ensemble_signal": "no_confidence", "confidence": 0.0}

    weighted_direction = sum(
        s.get("direction", 0) * s.get("confidence", 0.5) for s in signals
    ) / total_weight

    if weighted_direction > 0.2:
        ensemble = "bullish"
    elif weighted_direction < -0.2:
        ensemble = "bearish"
    else:
        ensemble = "neutral"

    directions = [s.get("direction", 0) for s in signals]
    agreement = abs(sum(directions)) / max(len(directions), 1)
    ensemble_confidence = min(0.85, (abs(weighted_direction) * 0.5 + agreement * 0.5))

    return {
        "ensemble_signal": ensemble,
        "weighted_direction": round(weighted_direction, 4),
        "agreement_score": round(agreement, 4),
        "confidence": round(ensemble_confidence, 4),
        "signal_count": len(signals),
        "signals_used": [{"name": s.get("name"), "direction": s.get("direction"),
                          "confidence": s.get("confidence")} for s in signals],
        "note": "Signal ensemble for research. Not a trading recommendation.",
    }


# ═══════════════════════════════════════════════════════════════
#  RISK BUDGET (with HHI concentration index)
# ═══════════════════════════════════════════════════════════════

def compute_risk_budget(
    holdings: dict[str, float],
    max_drawdown: float = 0.15,
    risk_free_rate: float = 0.045,
) -> dict:
    total = sum(holdings.values())
    if total <= 0:
        return {"error": "Portfolio value must be positive"}

    weights = {k: v / total for k, v in holdings.items()}
    max_loss = total * max_drawdown

    hhi = sum(w ** 2 for w in weights.values())
    effective_positions = 1.0 / hhi if hhi > 0 else len(holdings)

    return {
        "total_value": round(total, 2),
        "weights": {k: round(v, 4) for k, v in weights.items()},
        "max_drawdown_pct": max_drawdown,
        "max_loss_absolute": round(max_loss, 2),
        "risk_free_rate": risk_free_rate,
        "concentration_hhi": round(hhi, 4),
        "effective_positions": round(effective_positions, 2),
        "concentration_risk": max(weights.values()) > 0.40,
        "top_holding": max(weights, key=weights.get),
        "asset_count": len(holdings),
        "note": "Risk assessment for research purposes. Not financial advice.",
    }


# ═══════════════════════════════════════════════════════════════
#  PAPER TRADING
# ═══════════════════════════════════════════════════════════════

def create_paper_portfolio(db_path, user_id: str, name: str, holdings: dict[str, float]) -> dict:
    pid = str(uuid.uuid4())
    now = utc_now()
    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO portfolio_scenarios (id, user_id, name, holdings_json, is_paper, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (pid, user_id, name, json.dumps(holdings), now, now),
        )
    audit(db_path, "portfolio_create", user_id, pid, {"name": name, "holdings": holdings})
    return {"portfolio_id": pid, "name": name, "holdings": holdings, "is_paper": True, "created_at": now}


def list_paper_portfolios(db_path, user_id: str) -> list[dict]:
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT id, name, holdings_json, performance_json, created_at, updated_at "
            "FROM portfolio_scenarios WHERE user_id = ? AND is_paper = 1 ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
    return [{
        "portfolio_id": r["id"], "name": r["name"],
        "holdings": json.loads(r["holdings_json"]),
        "performance": json.loads(r["performance_json"]) if r["performance_json"] else None,
        "created_at": r["created_at"], "updated_at": r["updated_at"],
    } for r in rows]


# ═══════════════════════════════════════════════════════════════
#  FORECAST RUN (audited, multiplexed dispatcher)
# ═══════════════════════════════════════════════════════════════

def create_forecast_run(db_path, user_id: str, run_type: str, input_data: dict) -> dict:
    """Audited forecast run. Dispatches to the appropriate engine."""
    run_id = str(uuid.uuid4())
    now = utc_now()

    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO forecast_runs (id, user_id, run_type, input_json, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (run_id, user_id, run_type, json.dumps(input_data, default=str), now),
        )

    audit(db_path, "forecast_create", user_id, run_id, {"type": run_type})

    output = None

    if run_type == "regime_detection" and "prices" in input_data:
        output = detect_regime(input_data["prices"], input_data.get("window", 20))

    elif run_type == "telemetry_forecast" and "asset_type" in input_data and "symbol" in input_data:
        output = forecast_from_history(
            db_path, input_data["asset_type"], input_data["symbol"],
            input_data.get("horizon", "short"),
        )

    elif run_type == "scenario" and "holdings" in input_data and "scenarios" in input_data:
        output = run_scenario(input_data["holdings"], input_data["scenarios"])

    elif run_type == "signal_ensemble" and "signals" in input_data:
        output = run_signal_ensemble(input_data["signals"])

    elif run_type == "risk_budget" and "holdings" in input_data:
        output = compute_risk_budget(
            input_data["holdings"],
            input_data.get("max_drawdown", 0.15),
            input_data.get("risk_free_rate", 0.045),
        )

    if output:
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE forecast_runs SET output_json = ?, status = 'completed', completed_at = ? WHERE id = ?",
                (json.dumps(output, default=str), utc_now(), run_id),
            )

    return {
        "run_id": run_id,
        "run_type": run_type,
        "status": "completed" if output else "pending",
        "output": output,
    }
