"""Structured (JSON) logging.

Design goals:
- Security-centric fields for incident response and auditability.
- Works for both Flask (HTTP) and Celery (tasks).
- Correlation via request_id and principal context vars.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from core.log_context import get_request_id, get_principal
from core.otel import current_trace_ids


class JSONFormatter(logging.Formatter):
    """JSON log formatter with security fields."""

    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Contextvars (HTTP/Celery correlation)
        base["request_id"] = getattr(record, "request_id", None) or get_request_id()
        base["principal"] = getattr(record, "principal", None) or get_principal()

        trace_id, span_id = current_trace_ids()
        if trace_id:
            base["trace_id"] = trace_id
        if span_id:
            base["span_id"] = span_id

        # Optional structured fields
        for k in (
            "event",
            "method",
            "path",
            "status",
            "latency_ms",
            "remote_addr",
            "role",
            "task_id",
            "task_name",
            "scan_id",
            "target",
            "error",
        ):
            v = getattr(record, k, None)
            if v is not None:
                base[k] = v

        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)

        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))


def configure_logging() -> None:
    """Configure process-wide logging.

    Env:
      - QC_LOG_LEVEL (default: INFO)
      - QC_LOG_FORMAT: json|plain (default: json when QC_PRODUCTION=1 else plain)
    """
    level = os.environ.get("QC_LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("QC_LOG_FORMAT", "")
    if not fmt:
        fmt = "json" if os.environ.get("QC_PRODUCTION", "0") == "1" else "plain"

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicate handlers on repeated imports (Gunicorn reloads)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stdout)
    if fmt.lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(name)-24s | %(levelname)-8s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
    root.addHandler(handler)

    # Keep werkzeug noise low unless debugging
    logging.getLogger("werkzeug").setLevel("WARNING" if level != "DEBUG" else "INFO")
