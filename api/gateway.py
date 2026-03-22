"""QueenCalifia CyberAI — Hardened Security API Gateway
====================================================

This module is intentionally *defensive*:
- Strong auth/RBAC
- Rate limiting
- Strict input validation
- Tamper-evident audit logging (append-only JSONL with hash chaining + HMAC)
- Safe-by-default scan target policy (deny public targets unless allowlisted)

Scalability notes:
- In-memory rate limiting and state are per-process. For horizontal scale, externalize:
  - rate limit counters (Redis)
  - audit logs (SIEM / WORM storage)
  - mesh/scan/incident state (DB / event bus)

Config:
- QC_API_KEYS_FILE (default: ./keys.json) or QC_API_KEYS_JSON
- QC_API_KEY_PEPPER (recommended, keeps hashes non-portable)
- QC_AUDIT_LOG_FILE (default: ./audit.log.jsonl)
- QC_AUDIT_HMAC_KEY (recommended)
- QC_SCAN_ALLOWLIST (comma-separated CIDRs)
"""

from __future__ import annotations

import os
import math
import re
import json
import time
import uuid
import hmac
import hashlib
import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict, deque
import ipaddress

from flask import Flask, request, jsonify, g, send_file

# Optional: Zero-Day predictor + operational telemetry
try:
    from engines.zero_day_predictor import ZeroDayPredictor  # type: ignore
except Exception:  # pragma: no cover
    ZeroDayPredictor = None  # type: ignore

try:
    from core.telemetry import telemetry as qc_telemetry  # type: ignore
except Exception:  # pragma: no cover
    qc_telemetry = None

from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from core.auth import require_admin
from core.log_context import set_request_id, set_principal, clear_request_id, clear_principal
from core.redis_client import key_prefix
from core.otel import instrument_flask, inject, current_trace_ids
from core.metrics import (
    metrics_enabled,
    observe_http,
    observe_denial,
    observe_budget_cost,
    render_latest,
    require_metrics_bearer_token,
    parse_bearer,
)

logger = logging.getLogger("queencalifia.api")


def _browser_cors_origin_allowed(origin: str) -> bool:
    """
    Whether to echo Access-Control-Allow-Origin for this browser Origin.

    Honors QC_CORS_ORIGINS (comma-separated exact origins from Render/env).
    Also allows Firebase Hosting (*.web.app, *.firebaseapp.com) and local dev.
    """
    origin = (origin or "").strip()
    if not origin:
        return False
    raw = (os.environ.get("QC_CORS_ORIGINS", "") or "").strip()
    if raw:
        allowed_exact = {x.strip() for x in raw.split(",") if x.strip()}
        if origin in allowed_exact:
            return True
    return (
        origin.endswith(".web.app")
        or origin.endswith(".firebaseapp.com")
        or "localhost" in origin
        or "127.0.0.1" in origin
    )


def _flask_cors_origin_values(config: SecurityConfig) -> List[Any]:
    """
    Origins passed to flask-cors must cover the same cases as _browser_cors_origin_allowed.

    When QC_CORS_ORIGINS is set, config.allowed_origins is *only* those literals; without
    regex fallbacks, Firebase preview sites (…--channel.web.app) and local dashboards
    fail the library's preflight check and the browser shows only \"Failed to fetch\".
    """
    values: List[Any] = list(config.allowed_origins)
    # Firebase Hosting: prod + preview channels for this default project id
    values.append(re.compile(r"^https://queencalifia-cyberai(?:--[a-z0-9-]+)?\.web\.app$", re.I))
    values.append(re.compile(r"^https://queencalifia-cyberai\.firebaseapp\.com$", re.I))
    # Vite / CRA hitting a hosted API
    values.append(re.compile(r"^http://localhost(?::\d+)?$", re.I))
    values.append(re.compile(r"^http://127\.0\.0\.1(?::\d+)?$", re.I))
    if "https://queencalifia.tamerian.com" not in values:
        values.append("https://queencalifia.tamerian.com")
    return values


# ─── Security Configuration ──────────────────────────────────────────────────

@dataclass(frozen=True)
class SecurityConfig:
    allowed_origins: List[str] = field(
        default_factory=lambda: [
            "https://queencalifia.tamerian.com",
            "http://localhost:3000",
            "https://queencalifia-cyberai.web.app",
            "https://*.web.app",
            "http://localhost:5000",
        ]
    )

    rate_limit_requests_per_minute: int = 120
    rate_limit_burst: int = 20

    require_api_key: bool = True
    api_key_header: str = "X-QC-API-Key"

    max_request_size_bytes: int = 1_048_576  # 1MB
    max_query_length: int = 10_000

    audit_all_requests: bool = True
    audit_log_file: str = field(default_factory=lambda: os.environ.get("QC_AUDIT_LOG_FILE", "audit.log.jsonl"))

    enforce_https: bool = False
    hsts_max_age: int = 31_536_000


# ─── Utilities ──────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_remote_addr() -> str:
    # If behind a proxy, ProxyFix will populate request.remote_addr from X-Forwarded-For.
    return request.remote_addr or "unknown"


# ─── Target Policy ──────────────────────────────────────────────────────────

class ScanTargetPolicy:
    """Allowlist enforcement for scan targets."""

    def __init__(self, allowlist: str, deny_public: bool = True):
        self.deny_public = deny_public
        self.allowed_networks: List[ipaddress._BaseNetwork] = []
        allowlist = (allowlist or "").strip()
        if allowlist:
            for part in allowlist.split(","):
                part = part.strip()
                if not part:
                    continue
                self.allowed_networks.append(ipaddress.ip_network(part, strict=False))

        # Default allowlist: private ranges only (safe-by-default)
        if not self.allowed_networks:
            self.allowed_networks = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("169.254.0.0/16"),
            ]

    def assert_allowed(self, target: str) -> None:
        target = (target or "").strip()
        if not target:
            raise ValueError("target is required")

        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            self._assert_network_allowed(network)
            return

        addr = ipaddress.ip_address(target)
        self._assert_ip_allowed(addr)

    def _assert_network_allowed(self, network: ipaddress._BaseNetwork) -> None:
        if self.deny_public and not self._is_private_or_loopback(network):
            raise ValueError("public network targets are denied by policy")
        if not any(network.subnet_of(n) or network.overlaps(n) for n in self.allowed_networks):
            raise ValueError("target network not in allowlist")

    def _assert_ip_allowed(self, addr: ipaddress._BaseAddress) -> None:
        if self.deny_public and not (addr.is_private or addr.is_loopback or addr.is_link_local):
            raise ValueError("public IP targets are denied by policy")
        if not any(addr in n for n in self.allowed_networks):
            raise ValueError("target IP not in allowlist")

    @staticmethod
    def _is_private_or_loopback(network: ipaddress._BaseNetwork) -> bool:
        # ipaddress doesn't expose is_private on networks consistently across versions
        for addr in (network.network_address, network.broadcast_address):
            if getattr(addr, "is_private", False) or getattr(addr, "is_loopback", False) or getattr(addr, "is_link_local", False):
                return True
        return False


# ─── Rate Limiting ──────────────────────────────────────────────────────────

class SlidingWindowRateLimiter:
    """Thread-safe sliding window limiter (per process).

    Callers may pass a per-key limit override to support RBAC tiers without
    instantiating separate limiter objects.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: Dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, key: str, max_requests: int) -> bool:
        max_requests = max(1, int(max_requests))
        now = time.monotonic()
        window_start = now - self.window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= window_start:
                q.popleft()
            if len(q) >= max_requests:
                return False
            q.append(now)
            return True

    def remaining(self, key: str, max_requests: int) -> int:
        max_requests = max(1, int(max_requests))
        now = time.monotonic()
        window_start = now - self.window_seconds
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= window_start:
                q.popleft()
            return max(0, max_requests - len(q))



# ─── API Keys / RBAC ─────────────────────────────────────────────────────────

class RedisBackedRateLimiter:
    """Redis-backed rate limiter for horizontal scale.

    Uses a true sliding window (ZSET) in Redis for atomic, shared counters.
    Falls back to per-process SlidingWindowRateLimiter when Redis is unavailable.
    """

    def __init__(self, prefix: str = "qc:rl:", window_seconds: int = 60):
        from core.redis_rate_limiter import RedisSlidingWindowLimiter

        self._limiter = RedisSlidingWindowLimiter(prefix=prefix, window_seconds=window_seconds)

    def is_allowed(self, key: str, max_requests: int) -> bool:
        allowed, _remaining = self._limiter.hit(key, max_requests)
        return allowed

    def remaining(self, key: str, max_requests: int) -> int:
        return self._limiter.remaining(key, max_requests)


def build_rate_limiter(prefix: str = "qc:rl:", window_seconds: int = 60):
    """Create the best available limiter.

    Env:
      - QC_REDIS_URL set => prefer RedisBackedRateLimiter
      - QC_FORCE_REDIS_RATE_LIMIT=1 => hard fail if Redis unavailable
    """
    force = os.environ.get("QC_FORCE_REDIS_RATE_LIMIT", "0") == "1"
    redis_url = os.environ.get("QC_REDIS_URL", "").strip()
    if redis_url:
        try:
            return RedisBackedRateLimiter(prefix=prefix, window_seconds=window_seconds)
        except Exception:
            if force:
                raise
    return SlidingWindowRateLimiter(window_seconds=window_seconds)


def build_scan_submit_limiter(window_seconds: int = 60):
    """Limiter for *scan submissions* (separate namespace)."""
    return build_rate_limiter(prefix=f"{key_prefix()}scan:sub:", window_seconds=window_seconds)



# ─── Rate Limit Policy (per-endpoint + RBAC tiers) ──────────────────────────

def _parse_env_json_or_kv(name: str) -> dict:
    """Parse env var as JSON object or comma-separated key=value list.

    Accepted formats:
      - JSON: {"GET /api/dashboard": 120, "POST /api/vulns/scan": {"admin": 30}}
      - KV:   GET /api/dashboard=120,POST /api/vulns/scan=30
    """
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return {}
    if raw.startswith("{") and raw.endswith("}"):
        try:
            out = json.loads(raw)
            return out if isinstance(out, dict) else {}
        except Exception:
            return {}

    out: dict = {}
    for part in re.split(r"[;,]", raw):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        try:
            out[k] = int(v)
        except Exception:
            continue
    return out


@dataclass(frozen=True)
class RateLimitPolicy:
    """Defense-oriented rate limits.

    - Global limit: per principal (API key) or per IP (public) across *all* endpoints.
    - Endpoint limits: additional per-endpoint ceilings (independent counters).

    Endpoint key format:
        "{METHOD} {FLASK_RULE}"
    Example:
        "POST /api/vulns/scan"
        "GET /api/incidents/<incident_id>"

    Env:
      - QC_ROLE_RATE_LIMITS_JSON or QC_ROLE_RATE_LIMITS
      - QC_RATE_LIMIT_ENDPOINTS_JSON or QC_RATE_LIMIT_ENDPOINTS
    """

    role_defaults: Dict[str, int] = field(default_factory=dict)
    endpoint_limits: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_env(config: SecurityConfig) -> "RateLimitPolicy":
        role_defaults = _parse_env_json_or_kv("QC_ROLE_RATE_LIMITS_JSON") or _parse_env_json_or_kv("QC_ROLE_RATE_LIMITS")
        endpoint_limits = _parse_env_json_or_kv("QC_RATE_LIMIT_ENDPOINTS_JSON") or _parse_env_json_or_kv("QC_RATE_LIMIT_ENDPOINTS")

        # Safe defaults (can be overridden by env)
        if not role_defaults:
            role_defaults = {
                "admin": 240,
                "analyst": 120,
                "reader": 60,
                "public": 30,
                "dev": config.rate_limit_requests_per_minute,
            }

        if not endpoint_limits:
            endpoint_limits = {
                "GET /api/health": 6000,
                "GET /healthz": 6000,
                "GET /readyz": 6000,
                "GET /api/ready": 6000,
                # tighter, high-cost endpoint (scan submissions)
                "POST /api/vulns/scan": {"admin": 30, "analyst": 10, "reader": 0, "public": 0},
                "POST /api/incidents/<incident_id>/approve/<action_id>": {"admin": 120, "analyst": 60, "reader": 0, "public": 0},
                "POST /api/incidents/<incident_id>/deny/<action_id>": {"admin": 120, "analyst": 60, "reader": 0, "public": 0},
                "POST /api/incidents/<incident_id>/rollback/<action_id>": {"admin": 60, "analyst": 30, "reader": 0, "public": 0},
            }

        return RateLimitPolicy(
            role_defaults={str(k): int(v) for k, v in role_defaults.items() if _is_intlike(v)},
            endpoint_limits=endpoint_limits,
        )

    def base_limit_for(self, principal: Optional[Dict[str, Any]], config: SecurityConfig) -> int:
        """Effective global RPM limit.

        Defense rule: principal-level overrides may *only* tighten limits.
        The effective limit is the minimum of:
          - role default
          - principal-specific rate_limit (when present)
        """
        if principal:
            role = str(principal.get("role", "reader"))
            role_default = int(self.role_defaults.get(role, config.rate_limit_requests_per_minute))
            principal_limit = principal.get("rate_limit", None)
            if _is_intlike(principal_limit):
                return int(min(role_default, int(principal_limit)))
            return int(role_default)
        return int(self.role_defaults.get("public", config.rate_limit_requests_per_minute))

    def endpoint_limit_for(self, method: str, rule: str, path: str, role: str) -> Optional[int]:
        """Return an endpoint limit (per minute) or None if not configured."""
        method = (method or "").upper()
        role = str(role or "public")

        keys = [
            f"{method} {rule}",
            f"{method} {path}",
            rule,
            path,
        ]

        # exact match
        for k in keys:
            if k in self.endpoint_limits:
                return _resolve_endpoint_limit(self.endpoint_limits[k], role)

        # prefix wildcard match (e.g., "POST /api/vulns/scan*" or "/api/vulns/*")
        for k, v in self.endpoint_limits.items():
            if not isinstance(k, str) or not k.endswith("*"):
                continue
            prefix = k[:-1]
            if any(str(x).startswith(prefix) for x in keys):
                return _resolve_endpoint_limit(v, role)

        return None


def _is_intlike(v: Any) -> bool:
    try:
        int(v)
        return True
    except Exception:
        return False


def _resolve_endpoint_limit(value: Any, role: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, dict):
        # role-specific
        if role in value and _is_intlike(value[role]):
            return int(value[role])
        if "default" in value and _is_intlike(value["default"]):
            return int(value["default"])
        if "*" in value and _is_intlike(value["*"]):
            return int(value["*"])
        return None
    if _is_intlike(value):
        return int(value)
    return None




# ─── Global Request Budgeting (token bucket + endpoint costs) ────────────────

def _parse_env_json(name: str) -> dict:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return {}
    if raw.startswith("{") and raw.endswith("}"):
        try:
            out = json.loads(raw)
            return out if isinstance(out, dict) else {}
        except Exception:
            return {}
    return {}


@dataclass(frozen=True)
class BudgetPolicy:
    """Global request budgeting using a token bucket.

    - Each principal gets a token bucket (capacity + refill rate).
    - Each endpoint charges a "cost" from the bucket.

    Endpoint cost key format:
        "{METHOD} {FLASK_RULE}" (same as RateLimitPolicy)

    Env:
      - QC_BUDGET_ENABLED (0/1)
      - QC_BUDGET_ROLE_BUCKETS_JSON
      - QC_BUDGET_ENDPOINT_COSTS_JSON
      - QC_BUDGET_DEFAULT_CAPACITY
      - QC_BUDGET_DEFAULT_REFILL_PER_MINUTE
    """

    enabled: bool = False
    role_buckets: Dict[str, Dict[str, float]] = field(default_factory=dict)
    endpoint_costs: Dict[str, Any] = field(default_factory=dict)
    default_capacity: float = 120.0
    default_refill_per_minute: float = 120.0

    @staticmethod
    def from_env(_config: SecurityConfig) -> "BudgetPolicy":
        enabled_flag = os.environ.get("QC_BUDGET_ENABLED", "").strip()
        role_buckets = _parse_env_json("QC_BUDGET_ROLE_BUCKETS_JSON")
        endpoint_costs = _parse_env_json("QC_BUDGET_ENDPOINT_COSTS_JSON")

        default_capacity = float(os.environ.get("QC_BUDGET_DEFAULT_CAPACITY", "120") or 120)
        default_refill = float(os.environ.get("QC_BUDGET_DEFAULT_REFILL_PER_MINUTE", "120") or 120)

        enabled = (enabled_flag == "1") or bool(role_buckets) or bool(endpoint_costs)

        # Defensive defaults (safe, can be overridden)
        if not role_buckets:
            role_buckets = {
                "admin": {"capacity": 600, "refill_per_minute": 600},
                "analyst": {"capacity": 240, "refill_per_minute": 240},
                "reader": {"capacity": 120, "refill_per_minute": 120},
                "public": {"capacity": 60, "refill_per_minute": 60},
                "dev": {"capacity": default_capacity, "refill_per_minute": default_refill},
            }

        if not endpoint_costs:
            endpoint_costs = {
                "GET /api/health": 0,
                "GET /api/ready": 0,
                "GET /healthz": 0,
                "GET /readyz": 0,
                "GET /api/dashboard": 1,
                "GET /api/incidents": 1,
                "GET /api/incidents/<incident_id>": 1,
                "POST /api/events/ingest": 2,
                "POST /api/iocs": 2,
                "POST /api/iocs/bulk": 3,
                "POST /api/vulns/scan": 10,  # expensive
                "POST /api/incidents": 2,
                "POST /api/incidents/<incident_id>/approve/<action_id>": 3,
                "POST /api/incidents/<incident_id>/deny/<action_id>": 2,
                "POST /api/incidents/<incident_id>/rollback/<action_id>": 4,
            }

        return BudgetPolicy(
            enabled=enabled,
            role_buckets=role_buckets,
            endpoint_costs=endpoint_costs,
            default_capacity=default_capacity,
            default_refill_per_minute=default_refill,
        )

    def _bucket_for_role(self, role: str) -> tuple[float, float]:
        role = str(role or "public")
        cfg = self.role_buckets.get(role) if isinstance(self.role_buckets, dict) else None
        if isinstance(cfg, dict):
            cap = float(cfg.get("capacity", self.default_capacity) or self.default_capacity)
            rpm = float(cfg.get("refill_per_minute", self.default_refill_per_minute) or self.default_refill_per_minute)
            return max(1.0, cap), max(0.0, rpm)
        return max(1.0, self.default_capacity), max(0.0, self.default_refill_per_minute)

    def bucket_for(self, principal: Optional[Dict[str, Any]], role: str) -> tuple[float, float]:
        """Return (capacity, refill_per_sec). Principal may override."""
        cap, rpm = self._bucket_for_role(role)
        if principal:
            if _is_intlike(principal.get("budget_capacity")):
                cap = float(int(principal["budget_capacity"]))
            if _is_intlike(principal.get("budget_refill_per_minute")):
                rpm = float(int(principal["budget_refill_per_minute"]))
        refill_per_sec = max(0.0, rpm / 60.0)
        return max(1.0, cap), refill_per_sec

    def cost_for(self, method: str, rule: str, path: str) -> float:
        method = (method or "").upper()
        keys = [
            f"{method} {rule}",
            f"{method} {path}",
            rule,
            path,
        ]

        for k in keys:
            if k in self.endpoint_costs and _is_intlike(self.endpoint_costs[k]):
                return float(int(self.endpoint_costs[k]))

        for k, v in (self.endpoint_costs or {}).items():
            if not isinstance(k, str) or not k.endswith("*"):
                continue
            prefix = k[:-1]
            if any(str(x).startswith(prefix) for x in keys):
                if _is_intlike(v):
                    return float(int(v))

        # Default cost
        return 1.0


def build_budget_limiter(prefix: str = "qc:budget:"):
    """Create a Redis-backed token bucket limiter (or None).

    Env:
      - QC_REDIS_URL set => prefer Redis token bucket
      - QC_FORCE_REDIS_BUDGET=1 => hard fail if Redis unavailable
    """
    force = os.environ.get("QC_FORCE_REDIS_BUDGET", "0") == "1"
    redis_url = os.environ.get("QC_REDIS_URL", "").strip()
    if not redis_url:
        return None
    try:
        from core.redis_token_bucket import RedisTokenBucket

        return RedisTokenBucket(prefix=prefix)
    except Exception:
        if force:
            raise
        return None

class APIKeyStore:
    """Hash-lookup API keys loaded from a JSON file/env."""

    def __init__(self, file_path: str, pepper: str):
        self.file_path = file_path
        self.pepper = pepper
        self._lock = threading.RLock()
        self._by_hash: Dict[str, Dict[str, Any]] = {}
        self._load_or_bootstrap()

    def _load_or_bootstrap(self) -> None:
        raw = os.environ.get("QC_API_KEYS_JSON", "").strip()
        if raw:
            data = json.loads(raw)
            self._load_data(data)
            return

        if os.path.exists(self.file_path):
            with open(self.file_path, "r", encoding="utf-8") as f:
                self._load_data(json.load(f))
            return

        if self._load_legacy_env_keys():
            return

        # Production-safe default: refuse to start without keys.
        if os.environ.get("QC_PRODUCTION") == "1" and os.environ.get("QC_ALLOW_INSECURE_BOOTSTRAP", "0") != "1":
            raise RuntimeError(
                "No API keys configured. Set QC_API_KEYS_FILE/QC_API_KEYS_JSON "
                "or QC_ALLOW_INSECURE_BOOTSTRAP=1 for initial bootstrap."
            )

        # Dev bootstrap (writes keys.json)
        admin = self.generate_key(role="admin", permissions=["read", "write", "execute", "admin"], rate_limit=240, description="bootstrap admin key")
        analyst = self.generate_key(role="analyst", permissions=["read", "write", "execute"], rate_limit=120, description="bootstrap analyst key")
        reader = self.generate_key(role="reader", permissions=["read"], rate_limit=60, description="bootstrap reader key")
        self._persist()
        logger.warning("🔑 Bootstrapped API keys (store securely; rotate immediately):")
        logger.warning("   ADMIN  = %s", admin)
        logger.warning("   ANALYST= %s", analyst)
        logger.warning("   READER = %s", reader)

    def _load_legacy_env_keys(self) -> bool:
        """Support legacy QC_API_KEY/QC_ADMIN_KEY env bootstrap."""
        api_key = (os.environ.get("QC_API_KEY", "") or "").strip()
        admin_key = (os.environ.get("QC_ADMIN_KEY", "") or "").strip()
        if not api_key and not admin_key:
            return False

        with self._lock:
            self._by_hash.clear()
            if api_key:
                self._by_hash[self._hash_key(api_key)] = {
                    "role": "analyst",
                    "permissions": ["read", "write", "execute"],
                    "rate_limit": 120,
                    "created_at": _utcnow(),
                    "description": "legacy QC_API_KEY",
                    "revoked": False,
                }
            if admin_key:
                self._by_hash[self._hash_key(admin_key)] = {
                    "role": "admin",
                    "permissions": ["read", "write", "execute", "admin"],
                    "rate_limit": 240,
                    "created_at": _utcnow(),
                    "description": "legacy QC_ADMIN_KEY",
                    "revoked": False,
                }
        logger.info("Loaded legacy environment API keys into gateway store")
        return True

    def _load_data(self, data: Dict[str, Any]) -> None:
        keys = data.get("keys") if isinstance(data, dict) else None
        if not isinstance(keys, list):
            raise ValueError("Invalid API keys data (expected {'keys': [...]})")

        with self._lock:
            self._by_hash.clear()
            for item in keys:
                if not isinstance(item, dict):
                    continue
                key_hash = item.get("key_hash")
                if not key_hash:
                    continue
                self._by_hash[str(key_hash)] = {
                    "role": item.get("role", "reader"),
                    "permissions": list(item.get("permissions", ["read"])),
                    "rate_limit": int(item.get("rate_limit", 60)),
                    "created_at": item.get("created_at", _utcnow()),
                    "description": item.get("description", ""),
                    "budget_capacity": item.get("budget_capacity"),
                    "budget_refill_per_minute": item.get("budget_refill_per_minute"),
                    "revoked": bool(item.get("revoked", False)),
                }

    def _persist(self) -> None:
        os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
        payload = {"version": 1, "keys": [{"key_hash": k, **v} for k, v in self._by_hash.items()]}
        tmp = self.file_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp, self.file_path)
        try:
            os.chmod(self.file_path, 0o600)
        except OSError:
            # Best-effort on non-POSIX.
            pass

    def _hash_key(self, key: str) -> str:
        return hashlib.sha256((key + self.pepper).encode()).hexdigest()

    def validate(self, presented_key: str) -> Optional[Dict[str, Any]]:
        if not presented_key:
            return None
        key_hash = self._hash_key(presented_key)
        with self._lock:
            meta = self._by_hash.get(key_hash)
            if not meta or meta.get("revoked"):
                return None
            return {**meta, "key_hash": key_hash}

    def generate_key(self, role: str, permissions: List[str], rate_limit: int, description: str) -> str:
        new_key = secrets.token_hex(32)
        key_hash = self._hash_key(new_key)
        with self._lock:
            self._by_hash[key_hash] = {
                "role": role,
                "permissions": permissions,
                "rate_limit": int(rate_limit),
                "created_at": _utcnow(),
                "description": description,
                "revoked": False,
            }
        return new_key

    def revoke(self, key_hash: str) -> bool:
        with self._lock:
            if key_hash in self._by_hash:
                self._by_hash[key_hash]["revoked"] = True
                self._persist()
                return True
        return False

    def list_keys(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{"key_hash": k, **v} for k, v in self._by_hash.items()]


# ─── Audit Logging ───────────────────────────────────────────────────────────

class AuditLog:
    """Append-only tamper-evident audit log (JSON Lines)."""

    def __init__(self, file_path: str, hmac_key: str):
        self.file_path = file_path
        self._hmac_key = hmac_key.encode()
        self._lock = threading.Lock()
        self._prev_hash = "0" * 64
        self._buffer: deque[Dict[str, Any]] = deque(maxlen=20000)
        self._init_prev_hash()

    def _init_prev_hash(self) -> None:
        if not os.path.exists(self.file_path):
            return
        try:
            with open(self.file_path, "rb") as f:
                # Seek from end in chunks to find last line
                f.seek(0, os.SEEK_END)
                size = f.tell()
                pos = max(0, size - 8192)
                f.seek(pos)
                tail = f.read().splitlines()
                if not tail:
                    return
                last = tail[-1].decode("utf-8", "replace")
                obj = json.loads(last)
                self._prev_hash = obj.get("hash", self._prev_hash)
        except Exception:
            logger.exception("Audit log init failed; starting new chain")

    def log(self, action: str, source_ip: str, user_role: str, status_code: int, details: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "ts": _utcnow(),
            "request_id": getattr(g, "request_id", None),
            "action": action,
            "source_ip": source_ip,
            "user_role": user_role,
            "status_code": int(status_code),
            "details": details or {},
            "previous_hash": self._prev_hash,
        }
        body = _json_dumps(entry)
        entry_hash = hashlib.sha256(body.encode()).hexdigest()
        sig = hmac.new(self._hmac_key, (entry_hash + self._prev_hash).encode(), hashlib.sha256).hexdigest()
        record = {**entry, "hash": entry_hash, "hmac": sig}

        line = _json_dumps(record) + "\n"
        with self._lock:
            os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            self._prev_hash = entry_hash
            self._buffer.append(record)

    def recent(self, count: int = 100) -> List[Dict[str, Any]]:
        count = max(1, min(int(count), 1000))
        with self._lock:
            return list(self._buffer)[-count:]

    def verify_integrity(self, max_lines: int = 20000) -> Dict[str, Any]:
        if not os.path.exists(self.file_path):
            return {"valid": True, "entries_checked": 0, "errors": []}

        errors: List[str] = []
        prev_hash = "0" * 64
        checked = 0

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    checked += 1
                    if checked > max_lines:
                        break
                    rec = json.loads(line)
                    record_hash = rec.get("hash", "")
                    record_hmac = rec.get("hmac", "")

                    verify_entry = {k: v for k, v in rec.items() if k not in {"hash", "hmac"}}
                    expected_hash = hashlib.sha256(_json_dumps(verify_entry).encode()).hexdigest()
                    expected_hmac = hmac.new(self._hmac_key, (expected_hash + prev_hash).encode(), hashlib.sha256).hexdigest()

                    if rec.get("previous_hash") != prev_hash:
                        errors.append(f"chain break at {checked}")
                    if record_hash != expected_hash:
                        errors.append(f"hash mismatch at {checked}")
                    if record_hmac != expected_hmac:
                        errors.append(f"hmac mismatch at {checked}")

                    prev_hash = record_hash
        except Exception as exc:
            return {"valid": False, "entries_checked": checked, "errors": [f"verify failed: {exc}"]}

        return {"valid": len(errors) == 0, "entries_checked": checked, "errors": errors}


# ─── Input Sanitization ──────────────────────────────────────────────────────

class InputSanitizer:
    """Conservative request sanitization (API layer only)."""

    _DANGEROUS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"\bunion\s+select\b",
        r"\bexec\s*\(",
        r"__import__",
        r"\beval\s*\(",
        r"\.\./\.\.",
        r"%00",
    ]
    _COMPILED = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]

    @classmethod
    def sanitize_string(cls, value: str, max_length: int) -> str:
        if not isinstance(value, str):
            raise ValueError("expected string")
        if len(value) > max_length:
            raise ValueError("input too long")
        for pat in cls._COMPILED:
            if pat.search(value):
                raise ValueError("prohibited pattern")
        return value.replace("\x00", "")

    @classmethod
    def sanitize_json_body(cls, data: Dict[str, Any], max_depth: int = 6) -> Dict[str, Any]:
        if max_depth <= 0:
            raise ValueError("json nesting too deep")
        if not isinstance(data, dict):
            raise ValueError("expected object")
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            key = re.sub(r"[^\w_.-]", "", str(k))[:128]
            if isinstance(v, str):
                sanitized[key] = cls.sanitize_string(v, max_length=10_000)
            elif isinstance(v, dict):
                sanitized[key] = cls.sanitize_json_body(v, max_depth - 1)
            elif isinstance(v, list):
                out = []
                for item in v[:1000]:
                    out.append(cls.sanitize_string(item, 10_000) if isinstance(item, str) else item)
                sanitized[key] = out
            else:
                sanitized[key] = v
        return sanitized


# ─── Security Headers ────────────────────────────────────────────────────────

def _add_security_headers(resp, config: SecurityConfig):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    resp.headers["Cache-Control"] = "no-store"

    # API-first CSP (no inline/script CDNs needed)
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    if os.environ.get("QC_PRODUCTION"):
        resp.headers["Strict-Transport-Security"] = f"max-age={config.hsts_max_age}; includeSubDomains"
    resp.headers.pop("Server", None)
    return resp


# ─── Decorators ──────────────────────────────────────────────────────────────

def require_permission(permission: str) -> Callable:
    def deco(fn: Callable) -> Callable:
        def wrapped(*args, **kwargs):
            if not getattr(g, "principal", None):
                return jsonify({"error": "unauthorized"}), 401
            if permission not in g.principal.get("permissions", []):
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)
        wrapped.__name__ = fn.__name__
        return wrapped
    return deco


def _vuln_async_queue_uses_celery() -> bool:
    """
    Opt-in Celery for async vulnerability scans.

    Having QC_REDIS_URL alone is not enough: without a worker consuming the
    ``scans`` queue, tasks remain PENDING forever. Default is off so
    API+Redis-only deployments use the in-process ScanJobManager + SQLite job
    store (see vuln_engine.submit_scan).
    """
    return os.environ.get("QC_USE_CELERY", "0").strip() == "1"


# ─── API Factory ─────────────────────────────────────────────────────────────

def create_security_api(
    security_mesh,
    vuln_engine,
    incident_orchestrator,
    config: Optional[SecurityConfig] = None,
    zero_day_predictor=None,
    advanced_telemetry=None,
    remediator=None,
    evolution_engine=None,
    threat_intel=None,
) -> Flask:
    config = config or SecurityConfig()

    # Secrets
    pepper = os.environ.get("QC_API_KEY_PEPPER") or os.environ.get("QC_AUDIT_HMAC_KEY") or "INSECURE-DEV-PEPPER"
    audit_hmac_key = os.environ.get("QC_AUDIT_HMAC_KEY") or pepper

    # Defensive: refuse insecure default secrets in production unless explicitly allowed.
    if os.environ.get("QC_PRODUCTION") == "1" and os.environ.get("QC_ALLOW_INSECURE_SECRETS", "0") != "1":
        if not (os.environ.get("QC_API_KEY_PEPPER") or "").strip():
            raise RuntimeError("QC_API_KEY_PEPPER must be set in production.")
        if not (os.environ.get("QC_AUDIT_HMAC_KEY") or "").strip():
            raise RuntimeError("QC_AUDIT_HMAC_KEY must be set in production.")
        if pepper == "INSECURE-DEV-PEPPER" or audit_hmac_key == "INSECURE-DEV-PEPPER":
            raise RuntimeError("Insecure default secrets detected; set QC_API_KEY_PEPPER and QC_AUDIT_HMAC_KEY.")


    key_file = os.environ.get("QC_API_KEYS_FILE", "keys.json")

    api_keys = APIKeyStore(file_path=key_file, pepper=pepper) if config.require_api_key else None
    audit = AuditLog(file_path=config.audit_log_file, hmac_key=audit_hmac_key)
    policy = RateLimitPolicy.from_env(config)
    budget_policy = BudgetPolicy.from_env(config)
    redis_pfx = key_prefix()
    budget_limiter = build_budget_limiter(prefix=f"{redis_pfx}budget:") if budget_policy.enabled else None
    global_limiter = build_rate_limiter(prefix=f"{redis_pfx}rl:", window_seconds=60)
    endpoint_limiter = build_rate_limiter(prefix=f"{redis_pfx}rl:endpoint:", window_seconds=60)
    scan_submit_limiter = build_scan_submit_limiter(window_seconds=60)

    scan_policy = ScanTargetPolicy(
        allowlist=os.environ.get("QC_SCAN_ALLOWLIST", ""),
        deny_public=os.environ.get("QC_DENY_PUBLIC_TARGETS", "1") == "1",
    )

    app = Flask(__name__)
    # --- Telemetry (optional, safe-by-default) ---
    try:
        from core.telemetry import install_flask_hooks  # type: ignore
        install_flask_hooks(app)
    except Exception:
        pass

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    CORS(
        app,
        origins=_flask_cors_origin_values(config),
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[config.api_key_header, "X-QC-Admin-Key", "Content-Type", "Authorization"],
        supports_credentials=True,
        max_age=3600,
    )

    @app.after_request
    def _force_cors(response):
        origin = request.headers.get("Origin", "")
        if _browser_cors_origin_allowed(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-QC-API-Key,X-QC-Admin-Key"
            response.headers["Access-Control-Max-Age"] = "3600"
        return response

    @app.route("/api/<path:path>", methods=["OPTIONS"])
    def _preflight(path=""):
        origin = request.headers.get("Origin", "")
        resp = app.make_response("")
        resp.status_code = 204
        if _browser_cors_origin_allowed(origin):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-QC-API-Key,X-QC-Admin-Key"
            resp.headers["Access-Control-Max-Age"] = "3600"
        return resp

    @app.before_request
    def _before_request():
        rid = (request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID") or "").strip()
        g.request_id = InputSanitizer.sanitize_string(rid, max_length=128) if rid else uuid.uuid4().hex
        set_request_id(g.request_id)
        g._start_time_monotonic = time.monotonic()

        # Browser CORS preflight must remain unauthenticated so custom key
        # headers can be negotiated before protected requests are sent.
        if request.method == "OPTIONS":
            g.principal = None
            g.user_role = "public"
            return None

        # Size guard
        if request.content_length and request.content_length > config.max_request_size_bytes:
            return jsonify({"error": "request too large"}), 413

        # HTTPS enforcement (best behind proxy)
        if config.enforce_https:
            proto = request.headers.get("X-Forwarded-Proto", request.scheme)
            if proto != "https":
                return jsonify({"error": "https required"}), 403

        principal = None
        if config.require_api_key:
            presented = request.headers.get(config.api_key_header, "").strip()
            principal = api_keys.validate(presented) if api_keys else None
            if not principal:
                # Allow unauthenticated health/readiness probes
                if request.path in ("/api/health", "/api/ready", "/healthz", "/readyz", "/metrics", "/api/config"):
                    g.principal = None
                    g.user_role = "public"
                    return None
                return jsonify({"error": "unauthorized"}), 401
        else:
            # Dev bypass (explicitly enabled via config): grant full permissions
            principal = {
                "role": "dev",
                "permissions": ["read", "write", "execute", "admin"],
                "rate_limit": config.rate_limit_requests_per_minute,
                "key_hash": "dev",
            }

        g.principal = principal
        set_principal((principal or {}).get("key_hash") if principal else f"ip:{_safe_remote_addr()}")
        g.user_role = principal.get("role") if principal else "public"
        # Rate limit
        # Rate limit (global + per-endpoint; Redis-backed when available)
        role = g.user_role or "public"
        if principal:
            identity = f"k:{principal['key_hash']}"
        else:
            identity = f"ip:{_safe_remote_addr()}"
        g.rate_limit_identity = identity

        base_limit = int(policy.base_limit_for(principal, config))
        g.rate_limit_global_limit = base_limit

        if base_limit <= 0:
            g._deny_scope = "global"
            resp = jsonify({"error": "rate_limited", "scope": "global"})
            resp.status_code = 429
            resp.headers["Retry-After"] = "60"
            return resp

        if not global_limiter.is_allowed(identity, base_limit):
            g._deny_scope = "global"
            resp = jsonify({"error": "rate_limited", "scope": "global"})
            resp.status_code = 429
            resp.headers["Retry-After"] = "60"
            return resp
        g.rate_limit_global_remaining = global_limiter.remaining(identity, base_limit)

        # Optional endpoint ceiling (additional independent counter)
        rule = request.url_rule.rule if getattr(request, "url_rule", None) else request.path
        ep_limit = policy.endpoint_limit_for(request.method, rule, request.path, role)
        if ep_limit is not None:
            endpoint_key = f"{request.method.upper()} {rule}"
            g.rate_limit_endpoint_key = endpoint_key
            g.rate_limit_endpoint_limit = int(ep_limit)

            if int(ep_limit) <= 0:
                g._deny_scope = "endpoint"
                resp = jsonify({"error": "rate_limited", "scope": "endpoint", "endpoint": endpoint_key})
                resp.status_code = 429
                resp.headers["Retry-After"] = "60"
                return resp

            ep_identity = f"{identity}|{endpoint_key}"
            if not endpoint_limiter.is_allowed(ep_identity, int(ep_limit)):
                g._deny_scope = "endpoint"
                resp = jsonify({"error": "rate_limited", "scope": "endpoint", "endpoint": endpoint_key})
                resp.status_code = 429
                resp.headers["Retry-After"] = "60"
                return resp
            g.rate_limit_endpoint_remaining = endpoint_limiter.remaining(ep_identity, int(ep_limit))


        # Optional global request budget (token bucket; Redis-backed)
        if budget_policy.enabled and budget_limiter is not None:
            cost = float(budget_policy.cost_for(request.method, rule, request.path))
            capacity, refill_per_sec = budget_policy.bucket_for(principal, role)

            g.budget_capacity = capacity
            g.budget_refill_per_sec = refill_per_sec
            g.budget_cost = cost

            try:
                allowed, remaining = budget_limiter.charge(
                    identity,
                    capacity=capacity,
                    refill_per_sec=refill_per_sec,
                    cost=cost,
                )
                g.budget_remaining = remaining
                observe_budget_cost(request.method.upper(), rule, float(cost))
            except Exception:
                # Defensive: never crash the API on budget failures unless forced
                if os.environ.get("QC_FORCE_REDIS_BUDGET", "0") == "1":
                    raise
                allowed = True
                remaining = capacity
                g.budget_remaining = remaining

            if not allowed:
                retry_after = 60
                if refill_per_sec > 0:
                    needed = max(0.0, cost - float(remaining))
                    retry_after = max(1, int(math.ceil(needed / refill_per_sec)))
                g._deny_scope = "budget"
                resp = jsonify({"error": "rate_limited", "scope": "budget", "cost": cost})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry_after)
                return resp

        return None

    @app.after_request
    def _after_request(resp):
        resp.headers["X-Request-Id"] = getattr(g, "request_id", "")
        trace_id, _span_id = current_trace_ids()
        if trace_id:
            resp.headers["X-Trace-Id"] = trace_id

        # Metrics (Prometheus)
        try:
            route = request.url_rule.rule if getattr(request, "url_rule", None) else request.path
        except Exception:
            route = request.path
        try:
            dur = time.monotonic() - float(getattr(g, "_start_time_monotonic", time.monotonic()))
        except Exception:
            dur = 0.0
        observe_http(request.method.upper(), route, int(resp.status_code), float(dur))
        deny_scope = getattr(g, "_deny_scope", None)
        if deny_scope:
            observe_denial(str(deny_scope), request.method.upper(), route)

        gl = getattr(g, "rate_limit_global_limit", None)
        if gl is not None:
            resp.headers["X-RateLimit-Limit"] = str(gl)
            resp.headers["X-RateLimit-Remaining"] = str(getattr(g, "rate_limit_global_remaining", 0))

        el = getattr(g, "rate_limit_endpoint_limit", None)
        if el is not None:
            resp.headers["X-RateLimit-Endpoint-Limit"] = str(el)
            resp.headers["X-RateLimit-Endpoint-Remaining"] = str(getattr(g, "rate_limit_endpoint_remaining", 0))
            resp.headers["X-RateLimit-Endpoint-Key"] = str(getattr(g, "rate_limit_endpoint_key", ""))

        bc = getattr(g, "budget_capacity", None)
        if bc is not None:
            resp.headers["X-Budget-Capacity"] = str(bc)
            resp.headers["X-Budget-Remaining"] = str(getattr(g, "budget_remaining", 0))
            resp.headers["X-Budget-Cost"] = str(getattr(g, "budget_cost", 0))
            resp.headers["X-Budget-Refill-Per-Second"] = str(getattr(g, "budget_refill_per_sec", 0))

        # Structured request log (never blocks responses)
        try:
            latency_ms = None
            if getattr(g, "request_start", None) is not None:
                latency_ms = int((time.time() - g.request_start) * 1000)

            logger.info(
                "request",
                extra={
                    "event": "http_request",
                    "method": request.method,
                    "path": request.path,
                    "status": resp.status_code,
                    "latency_ms": latency_ms,
                    "remote_addr": _safe_remote_addr(),
                    "role": getattr(g, "user_role", None),
                    "request_id": getattr(g, "request_id", None),
                    "principal": getattr(g, "rate_limit_identity", None),
                },
            )
        except Exception:
            # Defensive: never crash logging path
            pass
        finally:
            clear_request_id()
            clear_principal()

        return _add_security_headers(resp, config)

    @app.errorhandler(404)
    def _not_found(_):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(405)
    def _method_not_allowed(err):
        valid_methods = sorted(set(getattr(err, "valid_methods", []) or []))
        # The explicit OPTIONS catch-all on `/api/<path:path>` can turn
        # genuinely missing GET/POST API paths into 405s. Normalize those
        # cases back to 404 so clients don't see phantom endpoints.
        if request.path.startswith("/api/") and valid_methods == ["OPTIONS"]:
            return jsonify({"error": "not found"}), 404
        return jsonify({"error": "method not allowed"}), 405

    @app.errorhandler(500)
    def _internal(_):
        return jsonify({"error": "internal server error"}), 500

    # ── Endpoints ────────────────────────────────────────────────────────────

    def _health_payload() -> dict:
        return {
            "status": "operational",
            "system": "Queen Califia CyberAI",
            "timestamp": _utcnow(),
        }

    def _check_audit_log_dir() -> dict:
        audit_path = os.environ.get("QC_AUDIT_LOG_FILE", "audit.log.jsonl")
        audit_dir = os.path.dirname(audit_path) or "."
        try:
            if not os.path.isdir(audit_dir):
                os.makedirs(audit_dir, exist_ok=True)
            ok = os.access(audit_dir, os.W_OK)
            return {"name": "audit_log_dir", "ok": bool(ok), "required": True, "path": audit_dir}
        except Exception as exc:
            return {"name": "audit_log_dir", "ok": False, "required": True, "path": audit_dir, "error": str(exc)}

    def _check_redis() -> dict:
        required = os.environ.get("QC_REQUIRE_REDIS", "0") == "1"
        url = (os.environ.get("QC_REDIS_URL", "") or "").strip()

        if not url:
            return {"name": "redis", "ok": True, "required": False, "skipped": True}

        try:
            from core.redis_client import get_redis

            r = get_redis()
            r.ping()
            return {"name": "redis", "ok": True, "required": bool(required), "url": url}
        except Exception as exc:
            return {"name": "redis", "ok": False, "required": bool(required), "url": url, "error": str(exc)}

    def _healthz_response():
        return jsonify(_health_payload())

    def _readyz_response():
        checks = [
            _check_audit_log_dir(),
            _check_redis(),
        ]
        required_failures = [c for c in checks if c.get("required") and not c.get("ok")]
        payload = {
            "ready": len(required_failures) == 0,
            "timestamp": _utcnow(),
            "checks": {c["name"]: c for c in checks},
        }
        return (jsonify(payload), 200 if payload["ready"] else 503)

    @app.route("/api/health")
    def health():
        return _healthz_response()

    @app.route("/api/ready")
    def ready():
        return _readyz_response()

    @app.route("/healthz")
    def healthz():
        return _healthz_response()

    @app.route("/readyz")
    def readyz():
        return _readyz_response()

    # --- Telemetry endpoints (optional) ---
    @app.route('/api/v1/telemetry/ingest', methods=['POST'])
    @require_permission("write")
    def telemetry_ingest():
        """Ingest one telemetry event and return current derived signals."""
        try:
            from core.telemetry import process_event  # type: ignore
        except Exception:
            return jsonify({'enabled': False, 'error': 'telemetry unavailable'}), 503
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({'error': 'expected JSON object'}), 400
        return jsonify(process_event(payload))

    @app.route('/api/v1/telemetry/summary')
    @require_permission("read")
    def telemetry_summary():
        """Return a safe summary snapshot for dashboards."""
        try:
            from core.telemetry import qc_telemetry  # type: ignore
        except Exception:
            qc_telemetry = None
        if qc_telemetry is None:
            return jsonify({'enabled': False, 'summary': {}})
        return jsonify({'enabled': True, 'summary': qc_telemetry.summary()})

    # --- Zero-Day Predictor API ---
    @app.route('/api/v1/predictor/analyze', methods=['POST'])
    @require_permission("write")
    def predictor_analyze():
        """Analyze an event through the 5-layer prediction engine."""
        if zero_day_predictor is None:
            return jsonify({'enabled': False, 'error': 'predictor unavailable'}), 503
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({'error': 'expected JSON object'}), 400
        return jsonify(zero_day_predictor.analyze_event(payload))

    @app.route('/api/v1/predictor/predictions')
    @require_permission("read")
    def predictor_predictions():
        """Get active predictions above optional confidence threshold."""
        if zero_day_predictor is None:
            return jsonify({'enabled': False}), 503
        min_conf = float(request.args.get('min_confidence', 0))
        return jsonify({'predictions': zero_day_predictor.get_active_predictions(min_conf)})

    @app.route('/api/v1/predictor/status')
    @require_permission("read")
    def predictor_status():
        """Get predictor engine status."""
        if zero_day_predictor is None:
            return jsonify({'enabled': False}), 503
        return jsonify(zero_day_predictor.get_status())

    @app.route('/api/v1/predictor/landscape')
    @require_permission("read")
    def predictor_landscape():
        """Get strategic threat landscape assessment."""
        if zero_day_predictor is None:
            return jsonify({'enabled': False}), 503
        return jsonify(zero_day_predictor.get_threat_landscape())

    @app.route('/api/v1/predictor/validate', methods=['POST'])
    @require_permission("write")
    def predictor_validate():
        """Validate a prediction outcome."""
        if zero_day_predictor is None:
            return jsonify({'enabled': False}), 503
        payload = request.get_json(silent=True) or {}
        result = zero_day_predictor.validate_prediction(
            payload.get('prediction_id', ''),
            payload.get('outcome', ''),
            payload.get('notes', ''),
        )
        if result is None:
            return jsonify({'error': 'prediction not found'}), 404
        return jsonify({'validated': True, **result})

    # --- Advanced Telemetry API ---
    @app.route('/api/v1/telemetry/advanced/process', methods=['POST'])
    @require_permission("write")
    def telemetry_advanced_process():
        """Process event through 6-stream telemetry matrix."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False, 'error': 'telemetry unavailable'}), 503
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({'error': 'expected JSON object'}), 400
        tel_result = advanced_telemetry.process_event(payload)
        # Cross-feed into predictor if available
        if zero_day_predictor is not None:
            for sig in tel_result.get('predictor_signals', []):
                enriched = advanced_telemetry.enrich_signal_confidence(sig)
                zero_day_predictor.signal_bus.append(enriched)
        return jsonify(tel_result)

    @app.route('/api/v1/telemetry/advanced/status')
    @require_permission("read")
    def telemetry_advanced_status():
        """Get advanced telemetry status."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        return jsonify(advanced_telemetry.get_status())

    @app.route('/api/v1/telemetry/advanced/beacons')
    @require_permission("read")
    def telemetry_beacons():
        """Get detected beacon profiles."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        return jsonify({'beacons': advanced_telemetry.get_beacon_report()})

    @app.route('/api/v1/telemetry/advanced/risk-map')
    @require_permission("read")
    def telemetry_risk_map():
        """Get asset risk scoring map."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        return jsonify(advanced_telemetry.get_asset_risk_map())

    @app.route('/api/v1/telemetry/advanced/graph')
    @require_permission("read")
    def telemetry_lateral_graph():
        """Get lateral movement communication graph."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        return jsonify(advanced_telemetry.get_lateral_movement_graph())

    @app.route('/api/v1/telemetry/advanced/health')
    @require_permission("read")
    def telemetry_health():
        """Get collection health report."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        return jsonify(advanced_telemetry.check_collection_health())

    @app.route('/api/v1/telemetry/advanced/feedback')
    @require_permission("read")
    def telemetry_feedback():
        """Get adaptive feedback loop summary."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        return jsonify(advanced_telemetry.get_feedback_summary())

    @app.route('/api/v1/telemetry/advanced/feedback', methods=['POST'])
    @require_permission("write")
    def telemetry_record_feedback():
        """Record a prediction outcome for adaptive calibration."""
        if advanced_telemetry is None:
            return jsonify({'enabled': False}), 503
        payload = request.get_json(silent=True) or {}
        return jsonify(advanced_telemetry.record_prediction_outcome(
            payload.get('prediction_id', ''),
            payload.get('outcome', ''),
            payload.get('contributing_layers', []),
            payload.get('signal_types', []),
        ))

    @app.route("/metrics")
    def metrics():
        # Protected in production via QC_METRICS_TOKEN
        required = require_metrics_bearer_token(production=os.environ.get("QC_PRODUCTION", "0") == "1")
        if required:
            presented = parse_bearer(request.headers.get("Authorization", ""))
            if presented != required:
                return jsonify({"error": "unauthorized"}), 401

        if not metrics_enabled():
            return ("", 204)

        payload, content_type = render_latest()
        return (payload, 200, {"Content-Type": content_type})

    @app.route("/api/mesh/status")
    @require_permission("read")
    def mesh_status():
        audit.log("mesh_status_read", _safe_remote_addr(), g.user_role, 200)
        return jsonify({"success": True, "data": security_mesh.get_mesh_status()})

    @app.route("/api/threats/active")
    @require_permission("read")
    def active_threats():
        audit.log("threats_read", _safe_remote_addr(), g.user_role, 200)
        mesh = security_mesh.get_mesh_status()
        return jsonify({"success": True, "data": mesh.get("threat_posture", {})})

    @app.route("/api/events/ingest", methods=["POST"])
    @require_permission("write")
    def ingest_event():
        from core.tamerian_mesh import SecurityEvent

        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)

        event = SecurityEvent(
            source_ip=data.get("source_ip"),
            dest_ip=data.get("dest_ip"),
            source_port=data.get("source_port"),
            dest_port=data.get("dest_port"),
            protocol=data.get("protocol"),
            event_type=data.get("event_type", "unknown"),
            raw_data=data.get("raw_data", {}),
        )

        result = security_mesh.ingest_event(event)
        audit.log(
            "event_ingested",
            _safe_remote_addr(),
            g.user_role,
            200,
            details={"event_id": event.event_id, "type": event.event_type},
        )
        return jsonify({"success": True, "data": _serialize_result(result)})

    # ── IOC Management ───────────────────────────────────────────────────────

    @app.route("/api/iocs", methods=["GET"])
    @require_permission("read")
    def list_iocs():
        audit.log("iocs_read", _safe_remote_addr(), g.user_role, 200)
        iocs = security_mesh.list_active_iocs()
        return jsonify({"success": True, "data": iocs, "count": len(iocs)})

    @app.route("/api/iocs", methods=["POST"])
    @require_permission("write")
    def add_ioc():
        from core.tamerian_mesh import ThreatIndicator, ThreatSeverity

        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)

        indicator = ThreatIndicator(
            indicator_type=data.get("type", "unknown"),
            value=data.get("value", ""),
            severity=ThreatSeverity(int(data.get("severity", 2))),
            confidence=float(data.get("confidence", 0.5)),
            source=data.get("source", "api_import"),
            tags=data.get("tags", []),
            mitre_techniques=data.get("mitre", []),
        )

        key = security_mesh.add_ioc(indicator)
        audit.log("ioc_added", _safe_remote_addr(), g.user_role, 201, details={"ioc": indicator.value, "type": indicator.indicator_type})
        return jsonify({"success": True, "ioc_key": key}), 201

    @app.route("/api/iocs/bulk", methods=["POST"])
    @require_permission("write")
    def bulk_import_iocs():
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)
        iocs = data.get("iocs")
        if not isinstance(iocs, list):
            return jsonify({"error": "JSON body with 'iocs' array required"}), 400

        imported = security_mesh.bulk_import_iocs(iocs)
        audit.log("iocs_bulk_imported", _safe_remote_addr(), g.user_role, 200, details={"imported": imported, "submitted": len(iocs)})
        return jsonify({"success": True, "imported": imported, "submitted": len(iocs)})

    # ── Vulnerability Scanning ───────────────────────────────────────────────

    @app.route("/api/vulns/scan", methods=["POST"])
    @require_permission("execute")
    def start_scan():
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)

        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "Target required"}), 400

        # Explicit authorization acknowledgement (prevents accidental misuse)
        require_ack = os.environ.get("QC_REQUIRE_AUTHZ_ACK", "1") == "1"
        if require_ack and not bool(data.get("acknowledge_authorized")):
            return jsonify({"error": "authorization_ack_required", "message": "You must acknowledge you are authorized to scan this target. Set acknowledge_authorized: true in the request body."}), 400

        # Defense-grade guardrails (deny public targets unless allowlisted)
        try:
            scan_policy.assert_allowed(target if "/" not in target else target)
        except Exception as exc:
            return jsonify({"error": f"Target denied: {exc}"}), 400

        scan_type = data.get("scan_type", "full")
        mode = data.get("mode", "async")  # async|sync

        # Optional global scan submissions limiter (shared across API workers if Redis is enabled)
        try:
            max_scans_per_minute = int(os.environ.get("QC_MAX_SCANS", "10"))
            if not scan_submit_limiter.is_allowed("global", max_scans_per_minute):
                return jsonify({"error": "scan_rate_limited"}), 429
        except Exception:
            # Defensive: never crash the API on limiter failures
            pass

        if mode == "sync":
            scan = vuln_engine.scan_target(target=target, scan_type=scan_type)
            if evolution_engine:
                try:
                    evolution_engine.learn_from_completed_scan(scan.to_dict(), source="sync_scan")
                except Exception:
                    logger.exception("Automatic evolution learning failed for sync scan")
            audit.log("vuln_scan_sync", _safe_remote_addr(), g.user_role, 200, details={"target": target, "scan_id": scan.scan_id})
            return jsonify({"success": True, "data": scan.to_dict()})

        # Distributed queue (Celery+Redis) for horizontal scale
        use_celery = _vuln_async_queue_uses_celery()
        allow_local_fallback = os.environ.get("QC_ALLOW_LOCAL_SCAN_FALLBACK", "0") == "1"
        if use_celery:
            try:
                from celery_app import celery_app

                carrier: Dict[str, str] = {}
                try:
                    inject(carrier)
                except Exception:
                    carrier = {}
                carrier["request_id"] = getattr(g, "request_id", None) or ""
                async_result = celery_app.send_task(
                    "qc.run_vuln_scan",
                    args=[target, scan_type],
                    kwargs={"request_id": getattr(g, "request_id", None)},
                    headers=carrier,
                )
                payload = {"scan_id": async_result.id, "status": "queued", "target": target, "scan_type": scan_type}
                audit.log("vuln_scan_queued", _safe_remote_addr(), g.user_role, 202, details={"target": target, "scan_id": async_result.id})
                return jsonify({"success": True, "data": payload}), 202
            except Exception as exc:
                logger.exception("Celery enqueue failed")
                if not allow_local_fallback:
                    audit.log("vuln_scan_enqueue_failed", _safe_remote_addr(), g.user_role, 503, details={"target": target, "error": str(exc)})
                    return jsonify({"error": "celery_unavailable", "message": "Async scan queue unavailable; local fallback is disabled in production."}), 503
                payload = vuln_engine.submit_scan(target=target, scan_type=scan_type)
                audit.log("vuln_scan_queued_local", _safe_remote_addr(), g.user_role, 202, details={"target": target, "scan_id": payload.get("scan_id"), "error": str(exc)})
                return jsonify({"success": True, "data": payload, "degraded_mode": "local_queue_fallback"}), 202

        # Legacy fallback (single-process only)
        job = vuln_engine.submit_scan(target=target, scan_type=scan_type)
        audit.log("vuln_scan_queued", _safe_remote_addr(), g.user_role, 202, details={"target": target, "scan_id": job["scan_id"]})
        return jsonify({"success": True, "data": job}), 202

    @app.route("/api/vulns/scan/<scan_id>", methods=["GET"])
    @require_permission("read")
    def scan_status(scan_id: str):
        scan_id = InputSanitizer.sanitize_string(scan_id, max_length=128)

        use_celery = _vuln_async_queue_uses_celery()
        allow_local_fallback = os.environ.get("QC_ALLOW_LOCAL_SCAN_FALLBACK", "0") == "1"
        if use_celery:
            try:
                from celery_app import celery_app

                res = celery_app.AsyncResult(scan_id)
                payload: Dict[str, Any] = {
                    "scan_id": scan_id,
                    "state": res.state,
                    "ready": res.ready(),
                }
                if res.successful():
                    payload["result"] = _serialize_result(res.result)
                    if evolution_engine and isinstance(payload["result"], dict):
                        try:
                            evolution_engine.learn_from_completed_scan(payload["result"], source="async_scan_poll")
                        except Exception:
                            logger.exception("Automatic evolution learning failed for async scan result")
                elif res.failed():
                    payload["error"] = str(res.result)
                elif res.state in ("STARTED", "RUNNING", "WAITING"):
                    payload["meta"] = getattr(res, "info", None)
                return jsonify({"success": True, "data": payload})
            except Exception as exc:
                logger.exception("Celery status lookup failed")
                if not allow_local_fallback:
                    return jsonify({"error": "celery_status_unavailable", "message": "Async scan status backend unavailable; local fallback is disabled in production.", "scan_id": scan_id}), 503

        job = vuln_engine.get_scan_job(scan_id)
        if not job:
            return jsonify(
                {
                    "error": "scan not found",
                    "message": (
                        "No scan job with this id. If this appears briefly and then resolves, the scan store was busy — retry. "
                        "If it never resolves, your POST may have hit a different API instance than this GET "
                        "(scale to one instance or use a shared store / Celery result backend)."
                    ),
                    "scan_id": scan_id,
                }
            ), 404
        if evolution_engine and isinstance(job, dict) and job.get("status") == "completed" and isinstance(job.get("result"), dict):
            try:
                evolution_engine.learn_from_completed_scan(job["result"], source="local_scan_poll")
            except Exception:
                logger.exception("Automatic evolution learning failed for local scan result")
        return jsonify({"success": True, "data": job})

    @app.route("/api/vulns/status")
    @require_permission("read")
    def vuln_status():
        audit.log("vuln_status_read", _safe_remote_addr(), g.user_role, 200)
        return jsonify({"success": True, "data": vuln_engine.get_status()})

    @app.route("/api/vulns/remediation")
    @require_permission("read")
    def remediation_plan():
        asset_id = request.args.get("asset_id")
        if asset_id:
            asset_id = InputSanitizer.sanitize_string(asset_id, max_length=128)
        plan = None

        # Prefer the latest persisted auto-remediation plan when the caller is
        # asking for the current one-click/exportable plan rather than an
        # asset-specific vulnerability summary plan.
        if not asset_id and remediator is not None:
            try:
                persisted = list(getattr(remediator, "plans", {}).values())
                if persisted:

                    def _remediation_plan_score(p):
                        """Prefer plans with actions, then newest timestamp (ISO sortable)."""
                        try:
                            d = p.to_dict() if hasattr(p, "to_dict") else p
                        except Exception:
                            return (0, "")
                        if not isinstance(d, dict):
                            return (0, "")
                        actions = d.get("actions") or []
                        n = int(d.get("total_actions") or len(actions) or 0)
                        ts = d.get("created_at") or d.get("executed_at") or ""
                        return (n, ts)

                    best = max(persisted, key=_remediation_plan_score)
                    latest_dict = best.to_dict() if hasattr(best, "to_dict") else best
                    if isinstance(latest_dict, dict):
                        act_count = int(
                            latest_dict.get("total_actions")
                            or len(latest_dict.get("actions") or [])
                            or 0
                        )
                        # Only override vuln_engine when we have a real auto-remediation payload.
                        if act_count > 0:
                            plan = latest_dict
            except Exception:
                logger.exception("Failed to read persisted remediation plan; falling back to vulnerability plan")

        if plan is None:
            plan = vuln_engine.generate_remediation_plan(asset_id)
        audit.log("remediation_plan_read", _safe_remote_addr(), g.user_role, 200, details={"asset_id": asset_id})
        return jsonify({"success": True, "data": plan})

    @app.route("/api/vulns/webapp", methods=["POST"])
    @require_permission("execute")
    def webapp_scan():
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)
        url = data.get("url")
        if not url:
            return jsonify({"error": "URL required"}), 400

        # Explicit authorization acknowledgement (prevents accidental misuse)
        require_ack = os.environ.get("QC_REQUIRE_AUTHZ_ACK", "1") == "1"
        if require_ack and not bool(data.get("acknowledge_authorized")):
            return jsonify({"error": "authorization_ack_required", "message": "You must acknowledge you are authorized to scan this target. Set acknowledge_authorized: true in the request body."}), 400

        result = vuln_engine.scan_web_application(url)
        audit.log("webapp_scan", _safe_remote_addr(), g.user_role, 200, details={"url": url})
        return jsonify({"success": True, "data": result})

    # ── Incident Response ────────────────────────────────────────────────────

    @app.route("/api/incidents", methods=["GET"])
    @require_permission("read")
    def list_incidents():
        audit.log("incidents_read", _safe_remote_addr(), g.user_role, 200)
        incidents = [inc.to_dict() for inc in incident_orchestrator.list_incidents(limit=200)]
        incidents.sort(key=lambda i: (-_incident_severity_value(i.get("severity", "")), i.get("created_at", "")))
        return jsonify({"success": True, "data": incidents[:100], "count": len(incidents)})

    @app.route("/api/incidents", methods=["POST"])
    @require_permission("write")
    def create_incident():
        from engines.incident_response import IncidentSeverity, IncidentCategory

        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)

        incident = incident_orchestrator.create_incident(
            title=data.get("title", "Manual incident"),
            description=data.get("description", ""),
            severity=IncidentSeverity(int(data.get("severity", 2))),
            category=IncidentCategory(data.get("category", "unauthorized_access")),
            affected_assets=set(data.get("affected_assets", [])),
            indicators=data.get("indicators", []),
            mitre_techniques=data.get("mitre_techniques", []),
            auto_respond=bool(data.get("auto_respond", True)),
        )
        audit.log("incident_created", _safe_remote_addr(), g.user_role, 201, details={"incident_id": incident.incident_id})
        return jsonify({"success": True, "data": incident.to_dict()}), 201

    @app.route("/api/incidents/<incident_id>")
    @require_permission("read")
    def get_incident(incident_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        report = incident_orchestrator.get_incident_report(incident_id)
        if not report:
            return jsonify({"error": "Incident not found"}), 404
        audit.log("incident_detail_read", _safe_remote_addr(), g.user_role, 200, details={"incident_id": incident_id})
        return jsonify({"success": True, "data": report})
    @app.route("/api/incidents/<incident_id>/evidence", methods=["GET"])
    @require_permission("read")
    def list_incident_evidence(incident_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        evidence = incident_orchestrator.list_evidence(incident_id)
        audit.log(
            "incident_evidence_list",
            _safe_remote_addr(),
            g.user_role,
            200,
            details={"incident_id": incident_id, "count": len(evidence)},
        )
        return jsonify({"success": True, "data": evidence})


    @app.route("/api/incidents/<incident_id>/evidence", methods=["POST"])
    @require_permission("write")
    def add_incident_evidence(incident_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)

        try:
            ev = incident_orchestrator.add_evidence(
                incident_id=incident_id,
                evidence_type=str(data.get("evidence_type", "")),
                source=str(data.get("source", "")),
                storage_location=str(data.get("storage_location", "")),
                hash_sha256=str(data.get("hash_sha256", "")),
                size_bytes=int(data.get("size_bytes", 0) or 0),
                notes=str(data.get("notes", "")),
                collector=(g.principal or {}).get("key_hash") if getattr(g, "principal", None) else "public",
            )
        except KeyError:
            return jsonify({"error": "Incident not found"}), 404

        audit.log(
            "incident_evidence_add",
            _safe_remote_addr(),
            g.user_role,
            200,
            details={"incident_id": incident_id, "evidence_id": ev.get("evidence_id")},
        )
        return jsonify({"success": True, "data": ev})


    @app.route("/api/incidents/<incident_id>/evidence/<evidence_id>", methods=["GET"])
    @require_permission("read")
    def get_incident_evidence(incident_id: str, evidence_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        evidence_id = InputSanitizer.sanitize_string(evidence_id, max_length=64)
        try:
            ev = incident_orchestrator.get_evidence(incident_id, evidence_id)
        except KeyError:
            return jsonify({"error": "Not found"}), 404

        audit.log(
            "incident_evidence_get",
            _safe_remote_addr(),
            g.user_role,
            200,
            details={"incident_id": incident_id, "evidence_id": evidence_id},
        )
        return jsonify({"success": True, "data": ev})


    @app.route("/api/incidents/<incident_id>/evidence/<evidence_id>", methods=["DELETE"])
    @require_permission("admin")
    def delete_incident_evidence(incident_id: str, evidence_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        evidence_id = InputSanitizer.sanitize_string(evidence_id, max_length=64)

        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)
        reason = str(data.get("reason", ""))

        try:
            ev = incident_orchestrator.tombstone_evidence(
                incident_id=incident_id,
                evidence_id=evidence_id,
                actor=(g.principal or {}).get("key_hash") if getattr(g, "principal", None) else "public",
                reason=reason,
            )
        except KeyError:
            return jsonify({"error": "Not found"}), 404

        audit.log(
            "incident_evidence_tombstone",
            _safe_remote_addr(),
            g.user_role,
            200,
            details={"incident_id": incident_id, "evidence_id": evidence_id},
        )
        return jsonify({"success": True, "data": ev})




    @app.route("/api/incidents/<incident_id>/approve/<action_id>", methods=["POST"])
    @require_permission("execute")
    def approve_action_endpoint(incident_id: str, action_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        action_id = InputSanitizer.sanitize_string(action_id, max_length=64)
        success = incident_orchestrator.approve_action(incident_id, action_id, g.user_role)
        audit.log("action_approved", _safe_remote_addr(), g.user_role, 200 if success else 404, details={"incident_id": incident_id, "action_id": action_id})
        if success:
            return jsonify({"success": True, "message": "Action approved and executed"})
        return jsonify({"error": "Action not found or not pending"}), 404


    @app.route("/api/incidents/<incident_id>/deny/<action_id>", methods=["POST"])
    @require_permission("execute")
    def deny_action_endpoint(incident_id: str, action_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        action_id = InputSanitizer.sanitize_string(action_id, max_length=64)
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)
        reason = InputSanitizer.sanitize_string(str(data.get("reason", "")), max_length=500) if data.get("reason") else None

        success = incident_orchestrator.deny_action(incident_id, action_id, g.user_role, reason=reason)
        audit.log(
            "action_denied",
            _safe_remote_addr(),
            g.user_role,
            200 if success else 404,
            details={"incident_id": incident_id, "action_id": action_id, "reason": reason or ""},
        )
        if success:
            return jsonify({"success": True, "message": "Action denied"})
        return jsonify({"error": "Action not found or not pending"}), 404

    @app.route("/api/incidents/<incident_id>/rollback/<action_id>", methods=["POST"])
    @require_permission("execute")
    def rollback_action_endpoint(incident_id: str, action_id: str):
        incident_id = InputSanitizer.sanitize_string(incident_id, max_length=64)
        action_id = InputSanitizer.sanitize_string(action_id, max_length=64)
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)
        reason = InputSanitizer.sanitize_string(str(data.get("reason", "")), max_length=500) if data.get("reason") else None

        success = incident_orchestrator.rollback_action(incident_id, action_id, g.user_role, reason=reason)
        audit.log(
            "action_rolled_back",
            _safe_remote_addr(),
            g.user_role,
            200 if success else 404,
            details={"incident_id": incident_id, "action_id": action_id, "reason": reason or ""},
        )
        if success:
            return jsonify({"success": True, "message": "Action rolled back"})
        return jsonify({"error": "Action not found or not eligible for rollback"}), 404


    @app.route("/api/ir/status")
    @require_permission("read")
    def ir_status():
        audit.log("ir_status_read", _safe_remote_addr(), g.user_role, 200)
        return jsonify({"success": True, "data": incident_orchestrator.get_status()})

    # ── Audit ────────────────────────────────────────────────────────────────

    @app.route("/api/audit/log")
    @require_permission("admin")
    def get_audit_log():
        count = min(int(request.args.get("count", 100)), 1000)
        return jsonify({"success": True, "data": audit.recent(count), "count": count})

    @app.route("/api/audit/integrity")
    @require_permission("admin")
    def verify_audit_integrity():
        return jsonify({"success": True, "data": audit.verify_integrity()})

    # ── Admin: API Keys ──────────────────────────────────────────────────────

    @app.route("/api/admin/keys", methods=["GET"])
    @require_permission("admin")
    def admin_list_keys():
        return jsonify({"success": True, "data": api_keys.list_keys(), "count": len(api_keys.list_keys())})

    @app.route("/api/admin/keys", methods=["POST"])
    @require_permission("admin")
    def admin_create_key():
        data = request.get_json(silent=True) or {}
        data = InputSanitizer.sanitize_json_body(data)
        role = data.get("role", "reader")
        permissions = data.get("permissions", ["read"])
        rate_limit = int(data.get("rate_limit", 60))
        description = data.get("description", f"created:{_utcnow()}")
        if not isinstance(permissions, list) or not permissions:
            return jsonify({"error": "permissions must be a non-empty list"}), 400
        new_key = api_keys.generate_key(role=role, permissions=permissions, rate_limit=rate_limit, description=description)
        api_keys._persist()
        return jsonify({"success": True, "data": {"api_key": new_key}}), 201

    @app.route("/api/admin/keys/<key_hash>", methods=["DELETE"])
    @require_permission("admin")
    def admin_revoke_key(key_hash: str):
        key_hash = InputSanitizer.sanitize_string(key_hash, max_length=128)
        ok = api_keys.revoke(key_hash)
        return jsonify({"success": ok}), (200 if ok else 404)

    # ── Dashboard Aggregate ──────────────────────────────────────────────────

    @app.route("/api/dashboard")
    @require_permission("read")
    def dashboard():
        mesh = security_mesh.get_mesh_status()
        vulns = vuln_engine.get_status()
        ir = incident_orchestrator.get_status()
        return jsonify(
            {
                "success": True,
                "data": {
                    "mesh": {
                        "nodes_active": mesh["topology"]["active_nodes"],
                        "nodes_total": mesh["topology"]["total_nodes"],
                        "circuits_healthy": mesh["topology"]["healthy_circuits"],
                        "events_ingested": mesh["statistics"]["events_ingested"],
                        "threats_detected": mesh["statistics"]["threats_detected"],
                        "attacks_correlated": mesh["statistics"]["attacks_correlated"],
                        "ips_blocked": mesh["threat_posture"]["ips_blocked"],
                    },
                    "vulnerabilities": vulns,
                    "incidents": ir,
                    "uptime_hours": mesh["uptime_hours"],
                    "timestamp": _utcnow(),
                },
            }
        )

    # ── Infrastructure: SPKI Pin Runbook Log ──────────────────────────────

    @app.route("/api/infra/spki-log")
    @require_permission("read")
    def infra_spki_log():
        """Return recent SPKI pin runbook JSONL events (summary + per-attempt).

        Reads from the file specified by QC_SPKI_LOG_FILE (default: ./data/spki.jsonl).
        Returns the last N events (default 100, max 500).
        """
        log_file = os.environ.get("QC_SPKI_LOG_FILE", "data/spki.jsonl")
        limit = min(int(request.args.get("limit", 100)), 500)

        events = []
        if os.path.isfile(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines[-limit:]:
                    stripped = line.strip()
                    if stripped:
                        try:
                            events.append(json.loads(stripped))
                        except json.JSONDecodeError:
                            pass
            except OSError:
                pass

        summaries = [e for e in events if e.get("event_type") == "qc.redis.spki_pin.runbook"]
        attempts = [e for e in events if e.get("event_type") == "qc.redis.spki_pin.runbook.retry_attempt"]

        return jsonify({
            "success": True,
            "data": {
                "events": events,
                "summaries": summaries,
                "attempts": attempts,
                "log_file": log_file,
                "total_events": len(events),
            },
        })

    # ─── Live Scanner Endpoints ────────────────────────────────────────────

    from engines.live_scanner import LiveScanner
    from engines.auto_remediation import AutoRemediation

    live_scanner = LiveScanner()
    remediator = remediator or AutoRemediation()

    @app.route("/api/v1/scanner/scan", methods=["POST"])
    @require_permission("execute")
    def api_live_scan():
        """Launch a live network scan. Body: {target, scan_type?, ports?}"""
        body = request.get_json(force=True, silent=True) or {}
        target = body.get("target", "")
        if not target:
            return jsonify({"error": "target is required"}), 400

        # Explicit authorization acknowledgement
        require_ack = os.environ.get("QC_REQUIRE_AUTHZ_ACK", "1") == "1"
        if require_ack and not bool(body.get("acknowledge_authorized")):
            return jsonify({"error": "authorization_ack_required"}), 400

        scan_type = body.get("scan_type", "full")
        ports = body.get("ports", None)
        try:
            report = live_scanner.scan(target, scan_type=scan_type, ports=ports)
            return jsonify(report.to_dict())
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/v1/scanner/scan/<scan_id>", methods=["GET"])
    @require_permission("read")
    def api_get_scan(scan_id):
        """Get scan report by ID"""
        report = live_scanner.get_scan(scan_id)
        if report:
            return jsonify(report)
        return jsonify({"error": "Scan not found"}), 404

    @app.route("/api/v1/scanner/findings", methods=["GET"])
    @require_permission("read")
    def api_findings():
        """Get all findings, optionally filtered by severity"""
        severity = request.args.get("severity")
        status = request.args.get("status", "open")
        findings = live_scanner.get_all_findings(severity=severity, status=status)
        return jsonify({"findings": findings, "total": len(findings)})

    @app.route("/api/v1/scanner/baselines", methods=["GET"])
    @require_permission("read")
    def api_baselines():
        """Get learned network baselines"""
        return jsonify({"baselines": live_scanner.get_baselines()})

    @app.route("/api/v1/scanner/status", methods=["GET"])
    @require_permission("read")
    def api_scanner_status():
        """Get live scanner status"""
        return jsonify(live_scanner.get_status())

    # ─── Remediation Endpoints ─────────────────────────────────────────────

    @app.route("/api/v1/remediate/plan", methods=["POST"])
    @require_permission("execute")
    def api_remediation_plan():
        """Generate a remediation plan. Body: {findings?, target?, mode?}"""
        body = request.get_json(force=True, silent=True) or {}
        findings = body.get("findings", None)
        if not findings:
            findings = live_scanner.get_all_findings()
        target = body.get("target", "localhost")
        mode = body.get("mode", "preview")
        plan = remediator.generate_plan(findings, target_host=target, mode=mode)
        return jsonify(plan.to_dict())

    @app.route("/api/v1/remediate/plan/<plan_id>", methods=["GET"])
    @require_permission("read")
    def api_get_plan(plan_id):
        """Get remediation plan by ID"""
        plan = remediator.get_plan(plan_id)
        if plan:
            return jsonify(plan)
        return jsonify({"error": "Plan not found"}), 404

    @app.route("/api/v1/remediate/execute/<plan_id>", methods=["POST"])
    @require_permission("execute")
    def api_execute_plan(plan_id):
        """Execute a remediation plan"""
        body = request.get_json(force=True, silent=True) or {}
        approved_by = body.get("approved_by", "api_user")
        result = remediator.execute_plan(plan_id, approved_by=approved_by)
        return jsonify(result)

    @app.route("/api/v1/remediate/approve", methods=["POST"])
    @require_permission("execute")
    def api_approve_action():
        """Approve a single remediation action. Body: {plan_id, action_id}"""
        body = request.get_json(force=True, silent=True) or {}
        result = remediator.approve_action(
            body.get("plan_id", ""), body.get("action_id", ""),
            approved_by=body.get("approved_by", "api_user")
        )
        return jsonify(result)

    @app.route("/api/v1/remediate/status", methods=["GET"])
    @require_permission("read")
    def api_remediation_status():
        """Get remediation engine status"""
        return jsonify(remediator.get_status())

    @app.route("/api/v1/remediate/log", methods=["GET"])
    @require_permission("read")
    def api_remediation_log():
        """Get remediation action log"""
        return jsonify({"log": remediator.get_action_log()})

    @app.route("/api/v1/scanner/findings/<finding_id>/remediate", methods=["POST"])
    @require_permission("execute")
    def api_remediate_finding(finding_id):
        """One-click: generate and preview remediation for a single finding"""
        findings = live_scanner.get_all_findings()
        target_finding = [f for f in findings if f.get("finding_id") == finding_id]
        if not target_finding:
            return jsonify({"error": "Finding not found"}), 404
        body = request.get_json(force=True, silent=True) or {}
        target = body.get("target", "localhost")
        plan = remediator.generate_plan(target_finding, target_host=target)
        return jsonify(plan.to_dict())

    # ─── Evolution Engine (Self-Healing / Learning / Evolving) ──────────

    if evolution_engine is None:
        try:
            from engines.evolution_engine import EvolutionEngine
            evolution_engine = EvolutionEngine()
        except Exception:
            evolution_engine = None

    def _memory_admin_authorized() -> bool:
        principal = getattr(g, "principal", None) or {}
        if "admin" in principal.get("permissions", []):
            return True

        token = (os.environ.get("QC_MEMORY_EXPORT_TOKEN", "") or "").strip()
        provided = (request.headers.get("X-QC-Memory-Token", "") or "").strip()
        return bool(token and provided and hmac.compare_digest(provided, token))

    @app.route("/api/v1/evolution/status", methods=["GET"])
    @require_permission("read")
    def api_evolution_status():
        """Get evolution engine status — health, learning, evolution metrics"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        return jsonify(evolution_engine.get_status())

    @app.route("/api/v1/evolution/health", methods=["GET"])
    @require_permission("read")
    def api_evolution_health():
        """Run health checks on all registered components"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        return jsonify({
            cid: h.to_dict()
            for cid, h in evolution_engine.check_all_health().items()
        })

    @app.route("/api/v1/evolution/learn", methods=["POST"])
    @require_permission("write")
    def api_evolution_learn():
        """Feed scan/incident data to the learning system. Body: {scan_report?, incident?}"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        result = {}
        if body.get("scan_report"):
            result["scan_learning"] = evolution_engine.learn_from_scan(body["scan_report"])
        if body.get("incident"):
            result["incident_learning"] = evolution_engine.learn_from_incident(body["incident"])
        return jsonify(result)

    @app.route("/api/v1/evolution/evolve", methods=["POST"])
    @require_permission("execute")
    def api_evolution_evolve():
        """Trigger an evolution cycle — generates new rules, profiles, playbooks"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        return jsonify(evolution_engine.evolve())

    @app.route("/api/v1/evolution/intelligence", methods=["GET"])
    @require_permission("read")
    def api_evolution_intelligence():
        """Get comprehensive intelligence report"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        return jsonify(evolution_engine.get_intelligence_report())

    @app.route("/api/v1/evolution/baselines", methods=["GET"])
    @require_permission("read")
    def api_evolution_baselines():
        """Get learned network baselines"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        return jsonify({"baselines": evolution_engine.get_learned_baselines()})

    @app.route("/api/v1/evolution/storage", methods=["GET"])
    @require_permission("admin")
    def api_evolution_storage():
        """Get storage/backup status for persistent memory."""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        if not _memory_admin_authorized():
            return jsonify({"error": "memory_admin_required"}), 403
        return jsonify({"success": True, "data": evolution_engine.get_storage_status()})

    @app.route("/api/v1/evolution/backups", methods=["GET"])
    @require_permission("admin")
    def api_evolution_backups():
        """List available memory snapshots."""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        if not _memory_admin_authorized():
            return jsonify({"error": "memory_admin_required"}), 403
        limit = min(int(request.args.get("limit", 20)), 100)
        return jsonify({"success": True, "data": evolution_engine.list_backups(limit=limit)})

    @app.route("/api/v1/evolution/backup", methods=["POST"])
    @require_permission("admin")
    def api_evolution_backup():
        """Create a point-in-time evolution memory snapshot."""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        if not _memory_admin_authorized():
            return jsonify({"error": "memory_admin_required"}), 403
        body = request.get_json(force=True, silent=True) or {}
        body = InputSanitizer.sanitize_json_body(body)
        result = evolution_engine.create_backup(label=body.get("label"))
        return jsonify(result), 201

    @app.route("/api/v1/evolution/backups/<backup_name>", methods=["GET"])
    @require_permission("admin")
    def api_evolution_download_backup(backup_name: str):
        """Download an existing memory snapshot."""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        if not _memory_admin_authorized():
            return jsonify({"error": "memory_admin_required"}), 403

        safe_name = os.path.basename(InputSanitizer.sanitize_string(backup_name, max_length=128))
        backup_path = os.path.abspath(os.path.join(evolution_engine.backup_dir, safe_name))
        backup_root = os.path.abspath(evolution_engine.backup_dir)
        if not backup_path.startswith(backup_root + os.sep):
            return jsonify({"error": "invalid backup path"}), 400
        if not os.path.exists(backup_path):
            return jsonify({"error": "backup not found"}), 404

        return send_file(backup_path, as_attachment=True, download_name=safe_name)

    @app.route("/api/v1/evolution/evolutions", methods=["GET"])
    @require_permission("read")
    def api_evolution_list():
        """Get evolution events. Query: ?type=detection_rule|scan_profile|..."""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        etype = request.args.get("type")
        return jsonify({"evolutions": evolution_engine.get_evolutions(etype)})

    @app.route("/api/v1/evolution/false-positive", methods=["POST"])
    @require_permission("write")
    def api_mark_fp():
        """Mark a finding as false positive. Body: {rule_id, finding_hash}"""
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        return jsonify(evolution_engine.mark_false_positive(
            body.get("rule_id", ""), body.get("finding_hash", ""),
            marked_by=body.get("marked_by", "api_user"),
        ))

    # ─── One-Click Operations ──────────────────────────────────────────

    @app.route("/api/v1/one-click/scan-and-fix", methods=["POST"])
    @require_permission("execute")
    def api_one_click():
        """
        THE ONE-CLICK OPERATION.
        Scan → Learn → Predict → Remediate → Evolve — all in one call.
        Body: {target, scan_type?, auto_approve?}
        """
        if not evolution_engine:
            return jsonify({"error": "Evolution engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        target = body.get("target")
        if not target:
            return jsonify({"error": "target is required"}), 400

        # Explicit authorization acknowledgement
        require_ack = os.environ.get("QC_REQUIRE_AUTHZ_ACK", "1") == "1"
        if require_ack and not bool(body.get("acknowledge_authorized")):
            return jsonify({"error": "authorization_ack_required"}), 400

        result = evolution_engine.one_click_scan_and_fix(
            target=target,
            scan_type=body.get("scan_type", "full"),
            auto_approve=body.get("auto_approve", False),
        )
        return jsonify(result)

    # ─── Quantum Engine ────────────────────────────────────────────────

    try:
        from engines.quantum_engine import (
            QuantumKeyVault, LatticeKeyGenerator, EntropyPool,
            assess_quantum_readiness, quantum_hash, LatticeAlgorithm,
        )
        _qe_entropy = EntropyPool()
        _qe_keygen = LatticeKeyGenerator(_qe_entropy)
        _qe_vault = QuantumKeyVault(_qe_keygen)
        # Auto-bootstrap: generate initial PQ keypairs for vault activation
        _qe_vault.generate_and_store(LatticeAlgorithm.KYBER_768, purpose="kem")
        _qe_vault.generate_and_store(LatticeAlgorithm.DILITHIUM_3, purpose="signing")
        _qe_hybrid = os.environ.get("QC_HYBRID_SIGNATURES", "1") == "1"
    except Exception:
        _qe_vault = None
        _qe_hybrid = False

    @app.route("/api/v1/quantum/readiness", methods=["GET"])
    @require_permission("read")
    def api_quantum_readiness():
        """Assess post-quantum cryptographic readiness"""
        try:
            report = assess_quantum_readiness(vault=_qe_vault, hybrid_enabled=_qe_hybrid)
            return jsonify({"readiness": report.__dict__ if hasattr(report, "__dict__") else report})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/v1/quantum/keygen", methods=["POST"])
    @require_permission("admin")
    def api_quantum_keygen():
        """Generate a post-quantum keypair. Body: {algorithm?, purpose?}"""
        if not _qe_vault:
            return jsonify({"error": "Quantum engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        alg_name = body.get("algorithm", "kyber768")
        purpose = body.get("purpose", "kem")
        _alg_map = {a.value: a for a in LatticeAlgorithm}
        alg = _alg_map.get(alg_name, LatticeAlgorithm.KYBER_768)
        key_id = _qe_vault.generate_and_store(alg, purpose=purpose)
        return jsonify({"key_id": key_id, "algorithm": alg.value, "purpose": purpose})

    @app.route("/api/v1/quantum/vault", methods=["GET"])
    @require_permission("admin")
    def api_quantum_vault():
        """Get quantum key vault status"""
        if not _qe_vault:
            return jsonify({"error": "Quantum engine not available"}), 503
        return jsonify({
            "key_count": _qe_vault.key_count,
            "expired_keys": len(_qe_vault.expired_keys()),
            "rotation_history": _qe_vault.rotation_history,
        })

    @app.route("/api/v1/quantum/hash", methods=["POST"])
    @require_permission("read")
    def api_quantum_hash():
        """Compute a quantum-safe hash. Body: {data, algorithm?}"""
        body = request.get_json(force=True, silent=True) or {}
        data = body.get("data", "")
        alg = body.get("algorithm", "sha3_256")
        h = quantum_hash(data.encode() if isinstance(data, str) else data, algorithm=alg)
        return jsonify({"hash": h, "algorithm": alg})

    # ─── Threat Intelligence ───────────────────────────────────────────

    if threat_intel is None:
        try:
            from engines.threat_intel_auto import ThreatIntelEngine
            threat_intel = ThreatIntelEngine()
        except Exception:
            threat_intel = None

    @app.route("/api/v1/threat-intel/status", methods=["GET"])
    @require_permission("read")
    def api_threat_intel_status():
        if not threat_intel:
            return jsonify({"error": "Threat intel engine not available"}), 503
        return jsonify(threat_intel.get_stats())

    @app.route("/api/v1/threat-intel/feeds", methods=["GET"])
    @require_permission("read")
    def api_threat_intel_feeds():
        if not threat_intel:
            return jsonify({"error": "Threat intel engine not available"}), 503
        return jsonify({
            "items": [
                {
                    "feed_id": feed.feed_id,
                    "name": feed.name,
                    "source_url": feed.source_url,
                    "feed_format": feed.feed_format.value,
                    "status": feed.status.value,
                    "update_interval_sec": feed.update_interval_sec,
                    "last_sync": feed.last_sync,
                    "last_success": feed.last_success,
                    "error_count": feed.error_count,
                    "ioc_count": feed.ioc_count,
                    "tags": feed.tags,
                }
                for feed in threat_intel.list_feeds()
            ]
        })

    @app.route("/api/v1/threat-intel/sync", methods=["POST"])
    @require_admin
    def api_threat_intel_sync():
        if not threat_intel:
            return jsonify({"error": "Threat intel engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        feed_id = str(body.get("feed_id", "")).strip()
        if feed_id:
            result = threat_intel.sync_feed(feed_id)
            return jsonify(result), (200 if result.get("ok") else 502)
        result = threat_intel.sync_due_feeds()
        ok = all(item.get("ok") for item in result.get("results", []))
        return jsonify(result), (200 if ok else 502)

    @app.route("/api/v1/threat-intel/indicators", methods=["GET"])
    @require_permission("read")
    def api_threat_intel_indicators():
        if not threat_intel:
            return jsonify({"error": "Threat intel engine not available"}), 503
        min_conf = float(request.args.get("min_confidence", 0.5))
        indicators = threat_intel.get_high_confidence_indicators(min_conf)
        return jsonify({"indicators": [i.__dict__ for i in indicators]})

    @app.route("/api/v1/threat-intel/cves/critical", methods=["GET"])
    @require_permission("read")
    def api_threat_intel_cves():
        if not threat_intel:
            return jsonify({"error": "Threat intel engine not available"}), 503
        cves = threat_intel.get_critical_cves()
        return jsonify({"cves": [c.__dict__ for c in cves]})

    @app.route("/api/v1/threat-intel/actors", methods=["GET"])
    @require_permission("read")
    def api_threat_intel_actors():
        if not threat_intel:
            return jsonify({"error": "Threat intel engine not available"}), 503
        query = request.args.get("q", "")
        actors = threat_intel.search_actors(query) if query else []
        return jsonify({"actors": [a.__dict__ for a in actors]})

    # ─── Red / Blue / Purple Team ──────────────────────────────────────

    try:
        from engines.red_team_tactics import RedTeamEngine
        from engines.blue_team_tactics import DetectionRuleEngine, IOCCorrelationEngine, ThreatHuntEngine, SOAREngine
        from engines.purple_team import PurpleTeamOrchestrator
        red_team = RedTeamEngine()
        blue_detection = DetectionRuleEngine()
        blue_ioc = IOCCorrelationEngine()
        blue_hunt = ThreatHuntEngine()
        blue_soar = SOAREngine()
        purple_team = PurpleTeamOrchestrator(red_team=red_team, blue_detection=blue_detection)
    except Exception:
        red_team = blue_detection = blue_ioc = blue_hunt = blue_soar = purple_team = None

    @app.route("/api/v1/purple-team/assess", methods=["POST"])
    @require_permission("execute")
    def api_purple_assess():
        """Run a purple team assessment. Body: {engagement_id, techniques, target?}"""
        if not purple_team:
            return jsonify({"error": "Purple team engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        result = purple_team.run_assessment(
            engagement_id=body.get("engagement_id", f"eng-{uuid.uuid4().hex[:8]}"),
            techniques=body.get("techniques", []),
            target=body.get("target", "10.0.0.1"),
        )
        return jsonify(result.__dict__ if hasattr(result, "__dict__") else result)

    @app.route("/api/v1/purple-team/heatmap", methods=["GET"])
    @require_permission("read")
    def api_purple_heatmap():
        """Get MITRE ATT&CK coverage heatmap"""
        if not purple_team:
            return jsonify({"error": "Purple team engine not available"}), 503
        return jsonify(purple_team.get_mitre_heatmap())

    @app.route("/api/v1/blue-team/rules", methods=["GET"])
    @require_permission("read")
    def api_blue_rules():
        """Get active detection rules"""
        if not blue_detection:
            return jsonify({"error": "Blue team engine not available"}), 503
        rules = blue_detection.get_active_rules()
        return jsonify({"rules": [r.__dict__ for r in rules], "total": blue_detection.rule_count()})

    @app.route("/api/v1/blue-team/iocs", methods=["GET"])
    @require_permission("read")
    def api_blue_iocs():
        """Get IOC correlation engine status"""
        if not blue_ioc:
            return jsonify({"error": "Blue team engine not available"}), 503
        return jsonify({"ioc_count": blue_ioc.ioc_count(), "correlations": blue_ioc.correlation_count()})

    @app.route("/api/v1/blue-team/hunt", methods=["POST"])
    @require_permission("execute")
    def api_blue_hunt():
        """Execute a threat hunt. Body: {query_id, data}"""
        if not blue_hunt:
            return jsonify({"error": "Blue team engine not available"}), 503
        body = request.get_json(force=True, silent=True) or {}
        result = blue_hunt.execute_hunt(body.get("query_id", ""), body.get("data", []))
        return jsonify(result.__dict__ if hasattr(result, "__dict__") else result)

    @app.route("/api/v1/blue-team/soar/playbooks", methods=["GET"])
    @require_permission("read")
    def api_soar_playbooks():
        """Get SOAR playbook count and status"""
        if not blue_soar:
            return jsonify({"error": "SOAR engine not available"}), 503
        return jsonify({"playbook_count": blue_soar.playbook_count()})

    # Expose for integration tests
    app.security_config = config
    app.api_key_store = api_keys
    app.audit_log = audit
    app.rate_limiter = global_limiter
    app.endpoint_rate_limiter = endpoint_limiter
    app.rate_limit_policy = policy
    app.scan_submit_limiter = scan_submit_limiter

    try:
        instrument_flask(app)
    except Exception:
        # Never block API start on tracing wiring.
        pass
    return app


# ─── Helpers ────────────────────────────────────────────────────────────────

def _incident_severity_value(name: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(name).upper(), 0)


def _serialize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    serialized: Dict[str, Any] = {}
    for key, value in (result or {}).items():
        if hasattr(value, "name"):  # Enum
            serialized[key] = value.name
        elif isinstance(value, list):
            out = []
            for item in value:
                if isinstance(item, dict):
                    out.append(_serialize_result(item))
                elif hasattr(item, "name"):
                    out.append(item.name)
                else:
                    out.append(item)
            serialized[key] = out
        elif isinstance(value, dict):
            serialized[key] = _serialize_result(value)
        else:
            try:
                json.dumps(value)
                serialized[key] = value
            except Exception:
                serialized[key] = str(value)
    return serialized
