"""
Queen Califia — background autonomy (learning + safe self-scan)

Runs in a daemon thread alongside the web process. It does NOT scan arbitrary
networks: optional recurring scans are limited to 127.0.0.1 only.

- Identity learning: calls run_learning_cycle_if_due() on an interval (throttled
  inside that function by QC_AUTO_LEARNING_INTERVAL_MINUTES).
- Evolution: ingests quick localhost scan results when enabled.
- Multi-worker: SQLite lease in QC_DB_PATH so only one process runs a tick.

Env:
  QC_AUTONOMY_ENABLED          1/0 (default: 1 when QC_PRODUCTION=1, else 0)
  QC_AUTONOMY_POLL_SECONDS     loop sleep between ticks (default 90)
  QC_AUTONOMY_LEASE_SECONDS    cross-process lease TTL (default 120)
  QC_AUTONOMY_LOCALHOST_SCAN_SECONDS
                               0 disables. If unset and QC_PRODUCTION=1, default 600 (10m).
                               Explicit value overrides; minimum 60 when > 0.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from core.database import get_db

logger = logging.getLogger("queencalifia.autonomy")

_LEASE_NAME = "autonomy_loop"


def _autonomy_enabled() -> bool:
    raw = os.environ.get("QC_AUTONOMY_ENABLED", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return os.environ.get("QC_PRODUCTION", "").strip() == "1"


def _localhost_scan_interval_seconds() -> int:
    raw = os.environ.get("QC_AUTONOMY_LOCALHOST_SCAN_SECONDS", "").strip()
    if raw in ("0", "false", "no", "off"):
        return 0
    if raw:
        return max(60, int(raw))
    if os.environ.get("QC_PRODUCTION", "").strip() == "1":
        return 600
    return 0


def _acquire_lease(db_path: Path, owner: str, ttl_seconds: float) -> bool:
    now = time.time()
    expires_at = now + ttl_seconds
    try:
        with get_db(db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS qc_autonomy_lease (
                    lease_name TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            row = conn.execute(
                "SELECT owner_id, expires_at FROM qc_autonomy_lease WHERE lease_name=?",
                (_LEASE_NAME,),
            ).fetchone()
            if row and row["owner_id"] != owner and float(row["expires_at"]) > now:
                return False
            conn.execute(
                """INSERT INTO qc_autonomy_lease (lease_name, owner_id, acquired_at, expires_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(lease_name) DO UPDATE SET
                     owner_id=excluded.owner_id,
                     acquired_at=excluded.acquired_at,
                     expires_at=excluded.expires_at""",
                (_LEASE_NAME, owner, now, expires_at),
            )
        return True
    except Exception:
        logger.exception("autonomy lease acquire failed")
        return False


def _autonomy_thread(
    *,
    db_path: Path,
    poll_seconds: float,
    lease_seconds: float,
    owner_id: str,
    vuln_engine: Any,
    evolution_engine: Any,
    run_learning_cycle_if_due: Optional[Callable[[Path], dict]],
) -> None:
    scan_every = _localhost_scan_interval_seconds()
    last_scan_monotonic = 0.0

    while True:
        time.sleep(poll_seconds)
        try:
            if not _acquire_lease(db_path, owner_id, lease_seconds):
                continue

            if run_learning_cycle_if_due is not None:
                try:
                    run_learning_cycle_if_due(db_path)
                except Exception:
                    logger.exception("autonomy identity learning tick failed")

            if (
                scan_every > 0
                and vuln_engine is not None
                and evolution_engine is not None
            ):
                now_m = time.monotonic()
                if now_m - last_scan_monotonic >= scan_every:
                    try:
                        result = vuln_engine.scan_target("127.0.0.1", scan_type="quick")
                        payload = result.to_dict() if hasattr(result, "to_dict") else result
                        evolution_engine.learn_from_completed_scan(
                            payload, source="autonomy_localhost"
                        )
                        last_scan_monotonic = now_m
                        logger.info(
                            "autonomy localhost quick scan complete | scan_id=%s findings=%s",
                            payload.get("scan_id"),
                            payload.get("vulnerabilities_found"),
                        )
                    except Exception:
                        logger.exception("autonomy localhost scan failed")
        except Exception:
            logger.exception("autonomy loop tick failed")


def start_autonomy_loop(
    *,
    db_path: Path | str | None = None,
    vuln_engine: Any = None,
    evolution_engine: Any = None,
) -> None:
    if not _autonomy_enabled():
        logger.info("autonomy loop disabled (set QC_AUTONOMY_ENABLED=1 or QC_PRODUCTION=1)")
        return

    path = Path(
        db_path
        or os.environ.get("QC_DB_PATH")
        or "data/qc_os.db"
    ).expanduser().resolve()

    poll_seconds = max(30.0, float(os.environ.get("QC_AUTONOMY_POLL_SECONDS", "90")))
    lease_seconds = max(45.0, float(os.environ.get("QC_AUTONOMY_LEASE_SECONDS", "120")))
    owner_id = f"{os.getpid()}-{uuid.uuid4().hex[:12]}"

    run_learning: Optional[Callable[[Path], dict]] = None
    try:
        from modules.identity.engine import run_learning_cycle_if_due as run_learning
    except Exception:
        logger.warning(
            "autonomy: identity learning module not importable; identity ticks skipped "
            "(expected when running without backend/modules on PYTHONPATH)"
        )

    t = threading.Thread(
        target=_autonomy_thread,
        kwargs={
            "db_path": path,
            "poll_seconds": poll_seconds,
            "lease_seconds": lease_seconds,
            "owner_id": owner_id,
            "vuln_engine": vuln_engine,
            "evolution_engine": evolution_engine,
            "run_learning_cycle_if_due": run_learning,
        },
        name="qc-autonomy-loop",
        daemon=True,
    )
    t.start()
    logger.info(
        "autonomy loop started | poll=%ss lease=%ss localhost_scan_every=%ss db=%s",
        int(poll_seconds),
        int(lease_seconds),
        _localhost_scan_interval_seconds(),
        path,
    )
