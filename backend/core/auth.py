"""
QC OS — Auth Layer
==================
API key validation and admin gating for internal endpoints.
"""
from __future__ import annotations

import os
from functools import wraps
from typing import Callable

from flask import jsonify, request


def require_api_key(fn: Callable) -> Callable:
    """Optional API key check. If QC_API_KEY is set, require it."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # When explicitly disabled, allow all requests through (dashboard UX).
        if os.getenv("QC_NO_AUTH", "0") == "1":
            return fn(*args, **kwargs)

        expected = os.getenv("QC_API_KEY")
        if not expected:
            return fn(*args, **kwargs)
        provided = request.headers.get("X-QC-API-Key", "")
        if provided != expected:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn: Callable) -> Callable:
    """Require admin token for internal/lab endpoints."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if os.getenv("QC_NO_AUTH", "0") == "1":
            return fn(*args, **kwargs)

        admin_key = os.getenv("QC_ADMIN_KEY")
        if not admin_key:
            return jsonify({"error": "admin access not configured"}), 403
        provided = request.headers.get("X-QC-Admin-Key", "")
        if provided != admin_key:
            return jsonify({"error": "forbidden"}), 403
        return fn(*args, **kwargs)
    return wrapper
