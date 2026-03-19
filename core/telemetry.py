"""
core.telemetry

Lightweight wrapper around the AdvancedTelemetry engine.

Design goals:
- Zero external deps (stdlib only).
- Safe to import even if optional engines are missing.
- Provide a single global instance (qc_telemetry) for the app + engines to use.

This is *defensive* telemetry: it collects security-relevant signals and summaries to
support anomaly detection / zero-day prediction. It is not a surveillance or exploit tool.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Optional, Tuple
import time

try:
    # Kept in engines/ so it can be unit-tested independently.
    from engines.advanced_telemetry import AdvancedTelemetry  # type: ignore
except Exception:  # pragma: no cover
    AdvancedTelemetry = None  # type: ignore


qc_telemetry = AdvancedTelemetry() if AdvancedTelemetry is not None else None


def enabled() -> bool:
    return qc_telemetry is not None


def process_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ingest one telemetry event and return a structured response with:
      - derived signals
      - current risk score
      - lightweight summary snapshot (safe for UI)
    """
    if qc_telemetry is None:
        return {
            "enabled": False,
            "signals": [],
            "risk_score": 0.0,
            "summary": {},
        }

    qc_telemetry.ingest(event)
    summary = qc_telemetry.summary()
    return {
        "enabled": True,
        "signals": summary.get("signals", []),
        "risk_score": summary.get("risk_score", 0.0),
        "summary": summary,
    }


def install_flask_hooks(app) -> None:
    """
    Optional: hook Flask request lifecycle and record minimal request metadata.
    This avoids collecting sensitive payloads by default.
    """
    if qc_telemetry is None:
        return

    try:
        from flask import request  # type: ignore
    except Exception:
        return

    @app.before_request
    def _qc_before_request():  # pragma: no cover
        request._qc_start_ts = time.time()  # type: ignore[attr-defined]

    @app.after_request
    def _qc_after_request(response):  # pragma: no cover
        try:
            start = getattr(request, "_qc_start_ts", None)
            dur_ms = (time.time() - start) * 1000.0 if start else None
            evt = {
                "type": "http_request",
                "ts": time.time(),
                "method": request.method,
                "path": request.path,
                "status": getattr(response, "status_code", None),
                "duration_ms": dur_ms,
                # Minimal identifiers; no bodies, no auth headers.
                "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
                "ua": request.headers.get("User-Agent", ""),
            }
            qc_telemetry.ingest(evt)
        except Exception:
            # Telemetry should never break the API.
            pass
        return response
