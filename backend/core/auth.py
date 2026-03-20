"""
QC OS — Auth Layer
==================
API key validation and admin gating for internal endpoints.
"""
from __future__ import annotations

import hashlib
import json
import os
from functools import wraps
from typing import Callable

from flask import jsonify, request


def _hash_api_key(value: str, pepper: str) -> str:
    return hashlib.sha256((value + pepper).encode()).hexdigest()


def _structured_key_meta(provided: str):
    if not provided:
        return None

    raw = (os.getenv("QC_API_KEYS_JSON", "") or "").strip()
    if not raw:
        file_path = (os.getenv("QC_API_KEYS_FILE", "") or "").strip()
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as handle:
                    raw = handle.read()
            except OSError:
                raw = ""
    if not raw:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    pepper = os.getenv("QC_API_KEY_PEPPER", "")
    provided_hash = _hash_api_key(provided, pepper)
    for item in data.get("keys", []) if isinstance(data, dict) else []:
        if item.get("key_hash") == provided_hash and not bool(item.get("revoked", False)):
            return item
    return None


def require_api_key(fn: Callable) -> Callable:
    """Require either the structured gateway key model or QC_API_KEY fallback."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # When explicitly disabled, allow all requests through (dashboard UX).
        if os.getenv("QC_NO_AUTH", "0") == "1":
            return fn(*args, **kwargs)

        provided = request.headers.get("X-QC-API-Key", "")
        if _structured_key_meta(provided):
            return fn(*args, **kwargs)

        expected = os.getenv("QC_API_KEY")
        if not expected:
            return fn(*args, **kwargs)

        if provided != expected:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn: Callable) -> Callable:
    """Require admin permission via structured keys or QC_ADMIN_KEY fallback."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if os.getenv("QC_NO_AUTH", "0") == "1":
            return fn(*args, **kwargs)

        provided_api_key = request.headers.get("X-QC-API-Key", "")
        meta = _structured_key_meta(provided_api_key)
        if meta and "admin" in list(meta.get("permissions", [])):
            return fn(*args, **kwargs)

        admin_key = os.getenv("QC_ADMIN_KEY")
        if not admin_key:
            return jsonify({"error": "admin access not configured"}), 403
        provided = request.headers.get("X-QC-Admin-Key", "")
        if provided != admin_key:
            return jsonify({"error": "forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper
