"""
QC OS — Market Intelligence (merged)
Production-quality SEC/ECB/Kraken adapters + SHA-256 cache + market history persistence.
"""
from __future__ import annotations
import csv, io, json
from datetime import datetime, timezone, timedelta
import requests as http

from core.database import get_db, utc_now, json_dumps, sha256, save_market_snapshot, get_market_history

TIMEOUT = 12

def _json_get(url, *, params=None, headers=None):
    r = http.get(url, params=params, headers=headers, timeout=TIMEOUT); r.raise_for_status(); return r.json()

def _text_get(url, *, params=None, headers=None):
    r = http.get(url, params=params, headers=headers, timeout=TIMEOUT); r.raise_for_status(); return r.text

# ── Cache ─────────────────────────────────────────────────────
def _cache_get(db_path, source_id, query_key):
    with get_db(db_path) as c:
        row = c.execute("SELECT data_json,expires_at FROM source_cache WHERE source_id=? AND query_key=? ORDER BY fetched_at DESC LIMIT 1",
                        (source_id, query_key)).fetchone()
    if not row or row["expires_at"] < utc_now(): return None
    return json.loads(row["data_json"])

def _cache_set(db_path, source_id, query_key, data, ttl_minutes=15):
    dj = json_dumps(data); now = utc_now()
    exp = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).replace(microsecond=0).isoformat()
    with get_db(db_path) as c:
        c.execute("INSERT INTO source_cache (source_id,query_key,data_json,fetched_at,expires_at,hash_sha256) VALUES (?,?,?,?,?,?)",
                  (source_id, query_key, dj, now, exp, sha256(dj)))

# ── Coinbase ──────────────────────────────────────────────────
def fetch_coinbase(settings, symbol):
    pid = symbol.replace("/", "-").upper()
    cached = _cache_get(settings.db_path, "coinbase", pid)
    if cached:
        return cached
    d = _json_get(f"{settings.coinbase_base_url}/products/{pid}/ticker")
    result = {"asset_type": "crypto", "symbol": pid, "source": "coinbase",
              "price": float(d["price"]), "quote_ccy": pid.split("-")[-1] if "-" in pid else None, "raw": d}
    _cache_set(settings.db_path, "coinbase", pid, result, settings.cache_ttl_minutes)
    return result

# ── Kraken ────────────────────────────────────────────────────
def fetch_kraken(settings, symbol):
    pair = symbol.replace("/", "").replace("-", "").upper()
    cached = _cache_get(settings.db_path, "kraken", pair)
    if cached:
        return cached
    d = _json_get(f"{settings.kraken_base_url}/0/public/Ticker", params={"pair": pair})
    if d.get("error"): raise ValueError(", ".join(d["error"]))
    result_data = next(iter(d["result"].values()))
    result = {"asset_type": "crypto", "symbol": pair, "source": "kraken",
              "price": float(result_data["c"][0]), "quote_ccy": pair[-3:] if len(pair) >= 6 else None, "raw": result_data}
    _cache_set(settings.db_path, "kraken", pair, result, settings.cache_ttl_minutes)
    return result

# ── ECB Forex ─────────────────────────────────────────────────
def fetch_ecb_fx(settings, symbol):
    pair = symbol.replace("-", "/").upper()
    if "/" not in pair: raise ValueError("forex symbols must look like USD/EUR")
    cached = _cache_get(settings.db_path, "ecb_data", pair)
    if cached:
        return cached
    base, quote = pair.split("/", 1)
    sk = f"D.{base}.{quote}.SP00.A"
    csv_text = _text_get(f"{settings.ecb_base_url}/EXR/{sk}",
                         params={"lastNObservations": 5, "format": "csvdata"}, headers={"Accept": "text/csv"})
    reader = csv.DictReader(io.StringIO(csv_text)); rows = list(reader)
    if not rows: raise ValueError("no ECB rows returned")
    latest = rows[-1]
    vf = next((k for k in latest if k.lower() == "obs_value"), None)
    tf = next((k for k in latest if k.lower() == "time_period"), None)
    if not vf: raise ValueError("ECB response missing OBS_VALUE")
    result = {"asset_type": "forex", "symbol": pair, "source": "ecb", "price": float(latest[vf]),
              "quote_ccy": quote, "series_key": sk, "timestamp": latest.get(tf), "raw": latest}
    _cache_set(settings.db_path, "ecb_data", pair, result, settings.cache_ttl_minutes)
    return result

# ── SEC EDGAR ─────────────────────────────────────────────────
def fetch_sec_intel(settings, ticker):
    h = {"User-Agent": settings.sec_user_agent, "Accept": "application/json"}
    idx = _json_get("https://www.sec.gov/files/company_tickers.json", headers=h)
    rec = None
    for v in idx.values():
        if str(v.get("ticker", "")).upper() == ticker.upper(): rec = v; break
    if not rec: raise ValueError(f"ticker not found: {ticker}")
    cik = str(rec["cik_str"]).zfill(10)
    subs = _json_get(f"https://data.sec.gov/submissions/CIK{cik}.json", headers=h)
    recent = subs.get("filings", {}).get("recent", {})
    lf = None
    ans = recent.get("accessionNumber", [])
    if ans:
        lf = {"accession_number": ans[0], "form": recent.get("form", [None])[0],
              "filing_date": recent.get("filingDate", [None])[0], "primary_document": recent.get("primaryDocument", [None])[0]}
    return {"asset_type": "stock", "symbol": ticker.upper(), "source": "sec", "kind": "company_intel",
            "issuer": subs.get("name"), "cik": cik, "sic": subs.get("sic"),
            "sic_description": subs.get("sicDescription"), "latest_filing": lf,
            "note": "SEC is for issuer/filing intelligence, not licensed live pricing."}

# ── FRED ──────────────────────────────────────────────────────
def fetch_fred(settings, series_id):
    if not settings.fred_api_key: raise ValueError("FRED_API_KEY not configured")
    cached = _cache_get(settings.db_path, "fred_api", series_id.upper())
    if cached:
        return cached
    d = _json_get("https://api.stlouisfed.org/fred/series/observations",
                  params={"series_id": series_id, "api_key": settings.fred_api_key,
                          "file_type": "json", "sort_order": "desc", "limit": 5})
    obs = d.get("observations", [])
    if not obs: raise ValueError(f"no FRED data for {series_id}")
    latest = obs[0]
    result = {"asset_type": "macro", "symbol": series_id.upper(), "source": "fred",
              "latest_value": latest.get("value"), "timestamp": latest.get("date"), "raw": latest, "confidence": 0.98}
    _cache_set(settings.db_path, "fred_api", series_id.upper(), result, settings.cache_ttl_minutes)
    return result

# ── Nasdaq ────────────────────────────────────────────────────
def fetch_nasdaq(settings, dataset, limit=30):
    if not settings.nasdaq_api_key: raise ValueError("NASDAQ_API_KEY not configured")
    cache_key = f"{dataset}:{limit}"
    cached = _cache_get(settings.db_path, "nasdaq_data", cache_key)
    if cached:
        return cached
    d = _json_get(f"https://data.nasdaq.com/api/v3/datasets/{dataset}.json",
                  params={"api_key": settings.nasdaq_api_key, "rows": limit})
    result = {"source": "nasdaq_data", "dataset": dataset, "data": d.get("dataset", {}),
              "fetched_at": utc_now(), "confidence": 0.96}
    _cache_set(settings.db_path, "nasdaq_data", cache_key, result, settings.cache_ttl_minutes)
    return result

# ── Unified Snapshot ──────────────────────────────────────────
def get_market_snapshot(settings, asset_type, symbol):
    if asset_type == "crypto":
        try: snap = fetch_coinbase(settings, symbol)
        except Exception: snap = fetch_kraken(settings, symbol)
        save_market_snapshot(settings.db_path, "crypto", snap["symbol"], snap["source"], snap["price"], snap.get("quote_ccy"), snap)
        return snap
    if asset_type == "forex":
        snap = fetch_ecb_fx(settings, symbol)
        save_market_snapshot(settings.db_path, "forex", snap["symbol"], snap["source"], snap["price"], snap.get("quote_ccy"), snap)
        return snap
    if asset_type == "stock": return fetch_sec_intel(settings, symbol)
    if asset_type == "macro": return fetch_fred(settings, symbol or settings.default_macro_series)
    raise ValueError(f"unsupported asset_type: {asset_type}")

# ── Portfolio Analysis (with PnL + cost basis) ────────────────
def analyze_portfolio(settings, holdings):
    normalized = []; total = 0.0
    for item in holdings:
        sym = str(item.get("symbol", "")).upper(); at = str(item.get("asset_type", "")).lower()
        units = float(item.get("units", 0)); lp = item.get("latest_price"); cb = item.get("cost_basis")
        if not sym or not at: raise ValueError("each holding requires symbol and asset_type")
        if lp is None:
            hist = get_market_history(settings.db_path, at, sym, limit=1)
            lp = hist[-1]["price"] if hist else 0
        lp = float(lp or 0); mv = units * lp
        pnl = mv - (units * float(cb)) if cb is not None else None
        normalized.append({"symbol": sym, "asset_type": at, "units": units, "latest_price": lp,
                          "market_value": round(mv, 4), "pnl": round(pnl, 4) if pnl is not None else None})
        total += mv
    for i in normalized: i["weight"] = round((i["market_value"] / total) if total else 0, 6)
    alloc = {}
    for i in normalized: alloc[i["asset_type"]] = alloc.get(i["asset_type"], 0.0) + i["weight"]
    top = max(normalized, key=lambda x: x["weight"]) if normalized else None
    return {"portfolio_value": round(total, 4), "holdings": normalized,
            "allocation_by_asset_type": {k: round(v, 6) for k, v in alloc.items()},
            "top_holding": top, "flags": {"concentration_risk": bool(top and top["weight"] >= 0.35),
                                           "trading_enabled": settings.enable_trading},
            "note": "Research-only analysis. Does not auto-execute trades."}

# ── Sources Status ────────────────────────────────────────────
def get_sources_status(settings):
    """Return trusted sources as array from DB with runtime config merged."""
    from core.database import get_db
    with get_db(settings.db_path) as c:
        rows = c.execute(
            "SELECT id, name, base_url, source_type, confidence_score, enabled, last_fetched_at "
            "FROM trusted_sources"
        ).fetchall()
    sources = []
    for r in rows:
        s = dict(r)
        if s["id"] == "fred_api":
            s["configured"] = bool(settings.fred_api_key)
        elif s["id"] == "nasdaq_data":
            s["configured"] = bool(settings.nasdaq_api_key)
        else:
            s["configured"] = True
        sources.append(s)
    return {"sources": sources, "trading_enabled": settings.enable_trading}

# ── Quant Optimizer (admin-only, classical + quantum-ready) ───
def run_quant_optimizer(settings, payload):
    """Admin-only optimizer. Delegates to quantum worker when Qiskit is available."""
    candidates = payload.get("candidates", []); ra = float(payload.get("risk_aversion", 0.5))
    if not isinstance(candidates, list) or len(candidates) < 2: raise ValueError("need >= 2 candidates")

    assets = [str(c.get("symbol", "")).upper() for c in candidates]
    returns = [float(c.get("expected_return", 0)) for c in candidates]
    risks = [max(0.0001, float(c.get("risk", 0.1))) for c in candidates]

    # Try quantum worker first
    try:
        from modules.quantum.worker import run_portfolio_optimization, get_quantum_status
        q_status = get_quantum_status()
        if q_status.get("qiskit_available"):
            # Build simple diagonal covariance from risk values
            cov = [[risks[i] * risks[j] * (1.0 if i == j else 0.3)
                     for j in range(len(risks))] for i in range(len(risks))]
            q_result = run_portfolio_optimization(assets, returns, cov, ra)
            q_result["trading_enabled"] = settings.enable_trading
            q_result["mode"] = "admin_quant_lab"
            q_result["quantum_ready"] = True
            return q_result
    except Exception:
        pass

    # Classical fallback
    norm = []
    for sym, er, risk in zip(assets, returns, risks):
        norm.append({"symbol": sym, "expected_return": er, "risk": risk, "score": er - (ra * risk)})
    raw = [max(0.0, n["score"]) for n in norm]; ss = sum(raw)
    weights = [round(s / ss, 6) for s in raw] if ss > 0 else [round(1 / len(norm), 6)] * len(norm)
    alloc = []; per = 0.0; pr = 0.0
    for n, w in zip(norm, weights):
        alloc.append({**n, "weight": w, "score": round(n["score"], 6)})
        per += w * n["expected_return"]; pr += w * n["risk"]
    return {"mode": "admin_quant_lab", "engine_mode": "classical_fallback",
            "quantum_ready": False, "trading_enabled": settings.enable_trading, "allocation": alloc,
            "portfolio_expected_return": round(per, 6), "portfolio_risk_score": round(pr, 6),
            "note": "Classical fallback. Install qiskit + qiskit-aer for quantum optimization."}
