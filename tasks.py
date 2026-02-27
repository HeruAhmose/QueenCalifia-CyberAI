"""Background tasks (Celery).

Run worker:
  celery -A celery_app.celery_app worker -l INFO --concurrency=4 -Q scans

Safety:
- Targets are policy-checked by VulnerabilityEngine (deny public unless allowlisted).
- A Redis-backed semaphore caps concurrent scans across the cluster.
- Trace context is propagated from HTTP -> Celery via W3C TraceContext headers when enabled.

"""

from __future__ import annotations

import os
import logging
from functools import lru_cache
from typing import Any, Dict

from celery import states

from celery_app import celery_app
from core.scan_semaphore import ScanSemaphore
from core.log_context import set_request_id, clear_request_id
from core.logging_setup import configure_logging
from core.otel import start_span, attach_extracted_context, detach
from engines.vulnerability_engine import VulnerabilityEngine

configure_logging()
logger = logging.getLogger("queencalifia.tasks")


class ScanCapacityError(RuntimeError):
    """Raised when cluster scan capacity is full."""


@lru_cache(maxsize=1)
def _engine() -> VulnerabilityEngine:
    """Singleton engine per worker process."""
    config = {
        "scan_threads": int(os.environ.get("QC_SCAN_THREADS", "32")),
        "max_scans_per_minute": int(os.environ.get("QC_MAX_SCANS", "10")),
        "target_allowlist": os.environ.get("QC_SCAN_ALLOWLIST", ""),
        "deny_public_targets": os.environ.get("QC_DENY_PUBLIC_TARGETS", "1") == "1",
    }
    return VulnerabilityEngine(config=config)


@celery_app.task(bind=True, name="qc.run_vuln_scan", queue="scans")
def run_vuln_scan(self, target: str, scan_type: str = "full", request_id: str | None = None) -> Dict[str, Any]:
    """Execute a vulnerability scan and return JSON-serializable results.

    Args:
        target: IP/host/CIDR target (policy-checked by VulnerabilityEngine).
        scan_type: "full"|"quick"|...
        request_id: Correlation id propagated from the HTTP request when available.

    Retry behavior:
        If global scan capacity is full, task retries until max wait is exceeded.
    """
    set_request_id(request_id or getattr(self.request, "id", None))

    otel_token = None
    try:
        carrier = (getattr(self.request, "headers", {}) or {})
        if isinstance(carrier, dict):
            otel_token = attach_extracted_context({str(k): str(v) for k, v in carrier.items()})
    except Exception:
        otel_token = None

    semaphore = ScanSemaphore()

    max_wait_s = int(os.environ.get("QC_SCAN_QUEUE_MAX_WAIT_SECONDS", "300"))
    retry_delay_s = int(os.environ.get("QC_SCAN_QUEUE_RETRY_DELAY_SECONDS", "5"))
    max_retries = max(1, int(max_wait_s / max(1, retry_delay_s)))

    try:
        if not semaphore.acquire():
            if self.request.retries >= max_retries:
                self.update_state(state=states.FAILURE, meta={"error": "scan_capacity_exceeded"})
                raise ScanCapacityError("cluster scan capacity exceeded")
            self.update_state(state="WAITING", meta={"status": "waiting_for_capacity"})
            raise self.retry(countdown=retry_delay_s)

        with start_span(
            "qc.vuln_scan",
            {
                "qc.target": target,
                "qc.scan_type": scan_type,
                "qc.task_id": getattr(self.request, "id", None),
                "qc.task_name": self.name,
            },
        ):
            logger.info(
                "scan started",
                extra={
                    "event": "vuln_scan_start",
                    "target": target,
                    "task_id": getattr(self.request, "id", None),
                    "task_name": self.name,
                },
            )
            self.update_state(state="RUNNING", meta={"target": target, "scan_type": scan_type})

            if os.environ.get("QC_SCAN_DRY_RUN", "0").strip() == "1":
                # Load-test/benchmark mode: enforce policy but avoid real network activity.
                # This is OFF by default and should remain OFF in production.
                try:
                    # Policy check occurs inside the engine's resolver.
                    _engine()._resolve_targets(target)  # type: ignore[attr-defined]
                except Exception as e:
                    raise
                result = {
                    "scan_id": getattr(self.request, "id", None),
                    "target": target,
                    "scan_type": scan_type,
                    "started_at": None,
                    "completed_at": None,
                    "duration_seconds": 0.01,
                    "status": "completed",
                    "findings": [],
                    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "notes": ["QC_SCAN_DRY_RUN enabled"],
                }
                return result
            scan = _engine().scan_target(target=target, scan_type=scan_type)
            result = scan.to_dict()

            logger.info(
                "scan complete",
                extra={
                    "event": "vuln_scan_complete",
                    "target": target,
                    "task_id": getattr(self.request, "id", None),
                    "task_name": self.name,
                },
            )
            return result
    except Exception as exc:
        logger.exception(
            "scan failed",
            extra={
                "event": "vuln_scan_error",
                "target": target,
                "task_id": getattr(self.request, "id", None),
                "task_name": self.name,
                "error": str(exc),
            },
        )
        self.update_state(state=states.FAILURE, meta={"error": str(exc)})
        raise
    finally:
        try:
            semaphore.release()
        except Exception:
            pass
        try:
            detach(otel_token)
        except Exception:
            pass
        clear_request_id()
