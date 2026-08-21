"""Production scanner state adapters.

The original scanner classes intentionally retain SQLite for local/dev use. This
module provides production-safe adapters so Kubernetes/API/worker composition
can avoid those local writers while preserving the existing scanner behavior.

- Vulnerability scan jobs: Celery/Redis is the distributed authority. The
  adapter prevents the inherited local qc_vuln_scan_jobs store from ever being
  initialized or written.
- Live scanner: scan reports, baselines, and finding state are persisted in the
  canonical PostgreSQL authority selected by QC_DATABASE_URL/DATABASE_URL.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.database import database_backend, database_url
from engines.live_scanner import Finding, LiveScanner, ScanReport
from engines.vulnerability_engine import VulnerabilityEngine


class CeleryVulnerabilityEngine(VulnerabilityEngine):
    """Vulnerability engine whose async job authority is Celery/Redis only."""

    job_store_backend = "celery-redis"

    def _init_job_store(self) -> None:
        # Deliberately no local DB initialization. Celery result state is the
        # production authority and workers do not need an auxiliary job table.
        return None

    def _connect_job_store(self):  # pragma: no cover - defensive guard
        raise RuntimeError(
            "local vulnerability scan-job SQLite is disabled; use Celery/Redis"
        )

    def persist_scan_job(self, **_: Any) -> None:
        raise RuntimeError(
            "local vulnerability scan-job persistence is disabled; use Celery/Redis"
        )

    def get_persisted_scan_job(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None

    def submit_scan(self, target: str, scan_type: str = "full") -> Dict[str, Any]:
        raise RuntimeError(
            "local vulnerability scan queue is disabled; submit through Celery/Redis"
        )

    def probe_health(self) -> Dict[str, Any]:
        return {
            "healthy": True,
            "metrics": {
                "job_store_backend": self.job_store_backend,
                "assets_tracked": len(self.assets),
            },
        }

    def recover_runtime_state(self) -> Dict[str, Any]:
        return {
            "healed": True,
            "strategy": "celery_redis_scan_job_authority",
            "backend": self.job_store_backend,
        }


class PostgresLiveScanner(LiveScanner):
    """LiveScanner with replica-safe PostgreSQL persistence."""

    storage_backend = "postgresql"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if database_backend() != "postgresql":
            raise RuntimeError("PostgresLiveScanner requires QC_DATABASE_URL/DATABASE_URL")
        super().__init__(config=config)

    def _connect_pg(self):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PostgreSQL configured but psycopg is not installed") from exc
        return psycopg.connect(database_url(), row_factory=dict_row)

    def _init_db(self):
        with self._connect_pg() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_live_scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT,
                    scan_type TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    total_hosts INTEGER,
                    total_findings INTEGER,
                    critical INTEGER,
                    high INTEGER,
                    risk_score DOUBLE PRECISION,
                    report_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_live_baselines (
                    host_ip TEXT PRIMARY KEY,
                    open_ports TEXT NOT NULL,
                    services TEXT NOT NULL,
                    os_guess TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS qc_live_findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    host_ip TEXT,
                    title TEXT,
                    severity TEXT,
                    cve_id TEXT,
                    cvss_score DOUBLE PRECISION,
                    status TEXT NOT NULL DEFAULT 'open',
                    remediated_at TEXT,
                    created_at TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_qc_live_findings_host ON qc_live_findings(host_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_qc_live_findings_severity ON qc_live_findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_qc_live_scans_target ON qc_live_scans(target)")

    def _persist_scan(self, report: ScanReport):
        with self._connect_pg() as conn:
            conn.execute(
                """
                INSERT INTO qc_live_scans (
                    scan_id, target, scan_type, start_time, end_time, total_hosts,
                    total_findings, critical, high, risk_score, report_json
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (scan_id) DO UPDATE SET
                    target=EXCLUDED.target,
                    scan_type=EXCLUDED.scan_type,
                    start_time=EXCLUDED.start_time,
                    end_time=EXCLUDED.end_time,
                    total_hosts=EXCLUDED.total_hosts,
                    total_findings=EXCLUDED.total_findings,
                    critical=EXCLUDED.critical,
                    high=EXCLUDED.high,
                    risk_score=EXCLUDED.risk_score,
                    report_json=EXCLUDED.report_json
                """,
                (
                    report.scan_id,
                    report.target,
                    report.scan_type,
                    report.start_time,
                    report.end_time,
                    report.total_hosts_alive,
                    report.total_findings,
                    report.critical_findings,
                    report.high_findings,
                    report.overall_risk,
                    json.dumps(report.to_dict()),
                ),
            )
            for host in report.hosts:
                for finding in host.findings:
                    conn.execute(
                        """
                        INSERT INTO qc_live_findings (
                            finding_id, scan_id, host_ip, title, severity, cve_id,
                            cvss_score, status, remediated_at, created_at
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,'open',NULL,%s)
                        ON CONFLICT (finding_id) DO UPDATE SET
                            scan_id=EXCLUDED.scan_id,
                            host_ip=EXCLUDED.host_ip,
                            title=EXCLUDED.title,
                            severity=EXCLUDED.severity,
                            cve_id=EXCLUDED.cve_id,
                            cvss_score=EXCLUDED.cvss_score,
                            created_at=EXCLUDED.created_at
                        """,
                        (
                            finding.finding_id,
                            report.scan_id,
                            host.ip,
                            finding.title,
                            finding.severity,
                            finding.cve_id,
                            finding.cvss_score,
                            finding.timestamp,
                        ),
                    )

    def _update_baselines(self, report: ScanReport):
        with self._connect_pg() as conn:
            for host in report.hosts:
                ports_json = json.dumps(host.open_ports)
                services_json = json.dumps({str(p): s.service for p, s in host.services.items()})
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """
                    INSERT INTO qc_live_baselines (
                        host_ip, open_ports, services, os_guess, first_seen, last_seen, scan_count
                    ) VALUES (%s,%s,%s,%s,%s,%s,1)
                    ON CONFLICT (host_ip) DO UPDATE SET
                        open_ports=EXCLUDED.open_ports,
                        services=EXCLUDED.services,
                        os_guess=EXCLUDED.os_guess,
                        last_seen=EXCLUDED.last_seen,
                        scan_count=qc_live_baselines.scan_count + 1
                    """,
                    (host.ip, ports_json, services_json, host.os_guess, now, now),
                )

    def _detect_drift(self, report: ScanReport):
        # Preserve the inherited execution order/semantics while using shared
        # PostgreSQL state. A future drift-algorithm change should be a separate
        # behavior PR rather than being hidden inside state migration.
        with self._connect_pg() as conn:
            for host in report.hosts:
                row = conn.execute(
                    """
                    SELECT open_ports, services
                    FROM qc_live_baselines
                    WHERE host_ip = %s AND scan_count > 1
                    """,
                    (host.ip,),
                ).fetchone()
                if not row:
                    continue
                baseline_ports = set(json.loads(row["open_ports"]))
                current_ports = set(host.open_ports)
                for port in current_ports - baseline_ports:
                    host.findings.append(
                        Finding(
                            title=f"DRIFT: New port {port} detected on {host.ip}",
                            description=(
                                f"Port {port} was not open in previous scans — potential backdoor or new service"
                            ),
                            severity="HIGH",
                            cvss_score=7.0,
                            affected_asset=host.ip,
                            port=port,
                            category="drift_detection",
                            remediation="Investigate why this port is newly open. Verify it's authorized.",
                            mitre_techniques=["T1543"],
                        )
                    )
                for port in baseline_ports - current_ports:
                    host.findings.append(
                        Finding(
                            title=f"DRIFT: Port {port} closed on {host.ip}",
                            description=(
                                f"Port {port} was previously open — service may have been stopped or blocked"
                            ),
                            severity="INFO",
                            cvss_score=0.0,
                            affected_asset=host.ip,
                            port=port,
                            category="drift_detection",
                        )
                    )

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        with self._lock:
            report = self.active_scans.get(scan_id)
            if report:
                return report.to_dict()
        with self._connect_pg() as conn:
            row = conn.execute(
                "SELECT report_json FROM qc_live_scans WHERE scan_id=%s", (scan_id,)
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def get_all_findings(self, severity: Optional[str] = None, status: str = "open") -> List[Dict]:
        with self._connect_pg() as conn:
            if severity:
                rows = conn.execute(
                    """
                    SELECT finding_id, scan_id, host_ip, title, severity, cve_id,
                           cvss_score, status, created_at
                    FROM qc_live_findings
                    WHERE severity=%s AND status=%s
                    ORDER BY cvss_score DESC
                    """,
                    (severity.upper(), status),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT finding_id, scan_id, host_ip, title, severity, cve_id,
                           cvss_score, status, created_at
                    FROM qc_live_findings
                    WHERE status=%s
                    ORDER BY cvss_score DESC
                    """,
                    (status,),
                ).fetchall()
        return [dict(row) for row in rows]

    def get_baselines(self) -> List[Dict]:
        with self._connect_pg() as conn:
            rows = conn.execute(
                """
                SELECT host_ip, open_ports, services, os_guess, first_seen, last_seen, scan_count
                FROM qc_live_baselines ORDER BY last_seen DESC
                """
            ).fetchall()
        return [
            {
                "host_ip": row["host_ip"],
                "open_ports": json.loads(row["open_ports"]),
                "services": json.loads(row["services"]),
                "os_guess": row["os_guess"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "scan_count": row["scan_count"],
            }
            for row in rows
        ]

    def mark_remediated(self, finding_id: str) -> bool:
        with self._connect_pg() as conn:
            row = conn.execute(
                """
                UPDATE qc_live_findings
                SET status='remediated', remediated_at=%s
                WHERE finding_id=%s
                RETURNING finding_id
                """,
                (datetime.now(timezone.utc).isoformat(), finding_id),
            ).fetchone()
        return bool(row)

    def get_status(self) -> Dict[str, Any]:
        with self._connect_pg() as conn:
            scans = int(conn.execute("SELECT COUNT(*) AS n FROM qc_live_scans").fetchone()["n"])
            findings = int(conn.execute("SELECT COUNT(*) AS n FROM qc_live_findings").fetchone()["n"])
            critical = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM qc_live_findings WHERE severity='CRITICAL' AND status='open'"
                ).fetchone()["n"]
            )
            high = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM qc_live_findings WHERE severity='HIGH' AND status='open'"
                ).fetchone()["n"]
            )
            baselines = int(conn.execute("SELECT COUNT(*) AS n FROM qc_live_baselines").fetchone()["n"])
        return {
            "engine": "LiveScanner",
            "version": "3.1",
            "mode": self.scan_mode,
            "max_threads": self.max_threads,
            "quantum_audit": True,
            "drift_detection": True,
            "learning": True,
            "storage_backend": self.storage_backend,
            "scans_completed": scans,
            "total_findings": findings,
            "open_critical": critical,
            "open_high": high,
            "hosts_baselined": baselines,
        }


def build_vulnerability_engine(config: Optional[Dict[str, Any]] = None) -> VulnerabilityEngine:
    """Choose Celery/Redis job authority for production/distributed scan mode."""
    distributed = os.environ.get("QC_USE_CELERY", "0").strip() == "1"
    production = os.environ.get("QC_PRODUCTION", "0").strip() == "1"
    if production and not distributed:
        raise RuntimeError("QC_PRODUCTION=1 requires QC_USE_CELERY=1 for vulnerability scan jobs")
    cls = CeleryVulnerabilityEngine if distributed else VulnerabilityEngine
    return cls(config=config)


def build_live_scanner(config: Optional[Dict[str, Any]] = None) -> LiveScanner:
    """Select the canonical live-scanner persistence backend.

    Production requires PostgreSQL. Local/non-production SQLite remains
    supported, but its writable path can be externalized through
    QC_LIVE_SCANNER_DB_PATH or the broader QC_DB_PATH runtime-state root.
    """
    resolved_config = dict(config or {})

    if database_backend() == "postgresql":
        return PostgresLiveScanner(config=resolved_config)

    if os.environ.get("QC_PRODUCTION", "0").strip() == "1":
        raise RuntimeError(
            "QC_PRODUCTION=1 requires PostgreSQL for live-scanner state"
        )

    external_db_path = (
        os.environ.get("QC_LIVE_SCANNER_DB_PATH", "").strip()
        or os.environ.get("QC_DB_PATH", "").strip()
    )
    if external_db_path and not resolved_config.get("db_path"):
        resolved_config["db_path"] = external_db_path

    return LiveScanner(config=resolved_config)
