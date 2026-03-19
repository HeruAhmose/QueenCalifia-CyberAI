"""
QC OS — Auth Layer
==================
API key validation and admin gating for internal endpoints.

This mirrors `backend/core/auth.py` so that dashboard route modules work when
the security gateway root app (which imports from `core.*`) is loaded.
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Callable

from flask import jsonify, request


def require_api_key(fn: Callable) -> Callable:
    """If QC_API_KEY is set, require X-QC-API-Key. Bypassed by QC_NO_AUTH=1."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
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
    """If QC_ADMIN_KEY is set, require X-QC-Admin-Key. Bypassed by QC_NO_AUTH=1."""

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

