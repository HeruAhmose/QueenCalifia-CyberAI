"""Celery application for QueenCalifia CyberAI.

Runs background security workloads (vulnerability scans) on a distributed queue.

Env:
  - QC_REDIS_URL: broker+backend default
  - QC_CELERY_BROKER_URL / QC_CELERY_RESULT_BACKEND: overrides
  - QC_SCAN_QUEUE_NAME: queue name for scan tasks (default: scans)
"""

from __future__ import annotations

import os

from celery import Celery
from celery.signals import task_prerun, task_postrun

from core.logging_setup import configure_logging
from core.log_context import set_request_id, clear_request_id
from core.otel import instrument_celery, attach_extracted_context, detach


def _redis_url() -> str:
    return os.environ.get("QC_REDIS_URL", "redis://localhost:6379/0")


def make_celery() -> Celery:
    broker = os.environ.get("QC_CELERY_BROKER_URL", _redis_url())
    backend = os.environ.get("QC_CELERY_RESULT_BACKEND", _redis_url())
    queue = os.environ.get("QC_SCAN_QUEUE_NAME", "scans")

    app = Celery("queencalifia", broker=broker, backend=backend, include=["tasks"])
    app.conf.update(
        worker_hijack_root_logger=False,

        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        enable_utc=True,
        timezone="UTC",
        task_track_started=True,
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_time_limit=int(os.environ.get("QC_TASK_TIME_LIMIT_SECONDS", "1200")),
        task_soft_time_limit=int(os.environ.get("QC_TASK_SOFT_TIME_LIMIT_SECONDS", "1100")),
        task_default_queue=queue,
        task_routes={
            "qc.run_vuln_scan": {"queue": queue},
        },
    )
    configure_logging()
    instrument_celery()
    return app


celery_app = make_celery()


@task_prerun.connect
def _qc_task_prerun(task_id=None, task=None, *args, **kwargs):
    # Prefer explicit kwargs, fall back to Celery headers.
    req = getattr(task, "request", None)
    rid = None
    if req is not None:
        rid = (getattr(req, "kwargs", {}) or {}).get("request_id")
        if not rid:
            rid = (getattr(req, "headers", {}) or {}).get("request_id")
    set_request_id(rid or task_id)

    # Attach trace context from Celery headers (traceparent/tracestate)
    try:
        carrier = (getattr(req, "headers", {}) or {}) if req is not None else {}
        token = attach_extracted_context({str(k): str(v) for k, v in carrier.items()}) if isinstance(carrier, dict) else None
        if req is not None:
            setattr(req, "_qc_otel_token", token)
    except Exception:
        pass


@task_postrun.connect
def _qc_task_postrun(task_id=None, task=None, *args, **kwargs):
    try:
        req = getattr(task, "request", None)
        token = getattr(req, "_qc_otel_token", None) if req is not None else None
        detach(token)
    except Exception:
        pass
    clear_request_id()
