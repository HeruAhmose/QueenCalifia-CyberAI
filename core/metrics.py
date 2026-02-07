"""Prometheus metrics for QueenCalifia CyberAI.

Metrics are intentionally minimal and stable:
- HTTP request counts and latency
- Rate-limit denials (global/endpoint/budget)
- Budget cost totals

Security:
- /metrics can be protected via QC_METRICS_TOKEN (Bearer token).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional, Tuple

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore
    generate_latest = None  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"  # type: ignore


_METRICS_ENABLED = Counter is not None

if _METRICS_ENABLED:
    HTTP_REQUESTS_TOTAL = Counter(
        "qc_http_requests_total",
        "Total HTTP requests",
        ["method", "route", "status"],
    )
    HTTP_REQUEST_DURATION_SECONDS = Histogram(
        "qc_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["method", "route"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
    RATE_LIMIT_DENIED_TOTAL = Counter(
        "qc_rate_limit_denied_total",
        "Rate limit denials by scope",
        ["scope", "method", "route"],
    )
    BUDGET_COST_TOTAL = Counter(
        "qc_budget_cost_total",
        "Total budget cost charged",
        ["method", "route"],
    )


def metrics_enabled() -> bool:
    return _METRICS_ENABLED


def observe_http(method: str, route: str, status: int, duration_s: float) -> None:
    if not _METRICS_ENABLED:
        return
    HTTP_REQUESTS_TOTAL.labels(method, route, str(status)).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method, route).observe(max(0.0, float(duration_s)))


def observe_denial(scope: str, method: str, route: str) -> None:
    if not _METRICS_ENABLED:
        return
    RATE_LIMIT_DENIED_TOTAL.labels(scope, method, route).inc()


def observe_budget_cost(method: str, route: str, cost: float) -> None:
    if not _METRICS_ENABLED:
        return
    if cost <= 0:
        return
    BUDGET_COST_TOTAL.labels(method, route).inc(float(cost))


def render_latest() -> Tuple[bytes, str]:
    if not _METRICS_ENABLED or generate_latest is None:
        return b"", CONTENT_TYPE_LATEST
    return generate_latest(), CONTENT_TYPE_LATEST


def require_metrics_bearer_token(production: bool) -> Optional[str]:
    """Return required token if one should be enforced."""
    token = (os.environ.get("QC_METRICS_TOKEN") or "").strip()
    if not token:
        return None
    return token if production else None


def parse_bearer(auth_header: str) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None
