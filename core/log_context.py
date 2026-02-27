"""Logging context for request/task correlation.

This module provides a minimal context layer for structured JSON logging.

Context variables:
- request_id: propagated from HTTP -> Celery tasks when available.
- principal: API key hash or "ip:<addr>" for unauthenticated access.
"""

from __future__ import annotations

import contextvars
from typing import Optional

request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("qc_request_id", default=None)
principal_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("qc_principal", default=None)


def set_request_id(request_id: Optional[str]) -> None:
    request_id_var.set(request_id)


def get_request_id() -> Optional[str]:
    return request_id_var.get()


def clear_request_id() -> None:
    request_id_var.set(None)


def set_principal(principal: Optional[str]) -> None:
    principal_var.set(principal)


def get_principal() -> Optional[str]:
    return principal_var.get()


def clear_principal() -> None:
    principal_var.set(None)
