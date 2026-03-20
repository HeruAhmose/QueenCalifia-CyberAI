"""
QueenCalifia CyberAI — Autonomous Evolution Engine
=====================================================
Self-Healing • Self-Learning • Self-Evolving

This engine gives Queen Califia the ability to:

    1. SELF-HEAL: Detect degraded components and auto-repair them.
       - Mesh node health monitoring with automatic re-scanning
       - Detection rule false-positive tracking with auto-tuning
       - Service watchdog with automatic restart recommendations
       - Database integrity verification and self-repair

    2. SELF-LEARN: Build intelligence from every scan and event.
       - Network baseline learning (normal vs anomalous)
       - Attack pattern recognition from incident history
       - Service fingerprint library (auto-expanding)
       - Threat actor TTP correlation (evolving profiles)
       - Scan strategy optimization (port priority, timing)

    3. SELF-EVOLVE: Generate new capabilities from observations.
       - Auto-generate detection rules from novel findings
       - Adapt scan profiles based on discovered services
       - Evolve remediation playbooks from successful fixes
       - Update quantum risk models as crypto landscape shifts
       - Priority re-ranking based on real-world exploit data

Spider Web Architecture:
    The evolution engine sits at the center of the mesh.
    Every engine feeds observations into it.
    It radiates improvements back out to all engines.
    The web grows stronger with every interaction.

Biomimetic Inspiration:
    Mycelium networks in forests share nutrients and threat signals
    between trees. This engine is the mycelium of Queen Califia —
    it connects all engines into a single learning organism.
"""

import os
import json
import time
import uuid
import hashlib
import logging
import sqlite3
import threading
import statistics
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger("queencalifia.evolution")


# ─── Constants ───────────────────────────────────────────────────────────────

EVOLUTION_DB = os.environ.get("QC_EVOLUTION_DB", "qc_evolution.db")
HEALTH_CHECK_INTERVAL = int(os.environ.get("QC_HEALTH_INTERVAL", "60"))
LEARNING_BATCH_SIZE = int(os.environ.get("QC_LEARNING_BATCH", "100"))
MAX_RULES_AUTO_GENERATED = int(os.environ.get("QC_MAX_AUTO_RULES", "500"))
BASELINE_CONFIDENCE_THRESHOLD = float(os.environ.get("QC_BASELINE_CONFIDENCE", "0.85"))
FALSE_POSITIVE_THRESHOLD = int(os.environ.get("QC_FP_THRESHOLD", "5"))


# ─── Data Models ─────────────────────────────────────────────────────────────

class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"


class LearningType(str, Enum):
    BASELINE = "baseline"
    PATTERN = "pattern"
    FINGERPRINT = "fingerprint"
    TTP = "ttp"
    SCAN_STRATEGY = "scan_strategy"
    REMEDIATION = "remediation"


class EvolutionType(str, Enum):
    DETECTION_RULE = "detection_rule"
    SCAN_PROFILE = "scan_profile"
    REMEDIATION_PLAYBOOK = "remediation_playbook"
    QUANTUM_MODEL = "quantum_model"
    PRIORITY_RANKING = "priority_ranking"
    THRESHOLD_ADJUSTMENT = "threshold_adjustment"


@dataclass
class ComponentHealth:
    component_id: str
    component_name: str
    status: HealthStatus
    last_check: str
    uptime_seconds: float = 0
    error_count: int = 0
    last_error: Optional[str] = None
    auto_healed: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class LearnedPattern:
    pattern_id: str
    learning_type: LearningType
    source_engine: str
    pattern_data: Dict[str, Any]
    confidence: float
    observations: int
    first_seen: str
    last_seen: str
    applied: bool = False

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["learning_type"] = self.learning_type.value
        return d


@dataclass
class EvolutionEvent:
    evolution_id: str
    evolution_type: EvolutionType
    description: str
    payload: Dict[str, Any]
    source_patterns: List[str]
    created_at: str
    applied: bool = False
    success: Optional[bool] = None
    impact_score: float = 0.0

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["evolution_type"] = self.evolution_type.value
        return d


# ─── Evolution Engine ────────────────────────────────────────────────────────

class EvolutionEngine:
    """
    The autonomous brain of Queen Califia.

    Monitors all engine health, learns from every scan and event,
    and evolves the platform's capabilities over time.
    """

    VERSION = "4.0.0"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.db_path = os.path.abspath(self.config.get("db_path", EVOLUTION_DB))
        default_backup_dir = os.path.join(os.path.dirname(self.db_path) or ".", "memory-backups")
        self.backup_dir = os.path.abspath(
            self.config.get("backup_dir", os.environ.get("QC_MEMORY_BACKUP_DIR", default_backup_dir))
        )
        self._lock = threading.Lock()

        # Component registry
        self._components: Dict[str, ComponentHealth] = {}
        self._component_checks: Dict[str, Any] = {}
        self._component_recoveries: Dict[str, List[Any]] = defaultdict(list)
        self._start_time = datetime.now(timezone.utc).isoformat()

        # Learning state
        self._patterns: Dict[str, LearnedPattern] = {}
        self._observations: List[Dict[str, Any]] = []
        self._network_baselines: Dict[str, Dict[str, Any]] = {}

        # Evolution state
        self._evolutions: Dict[str, EvolutionEvent] = {}
        self._auto_rules_generated: int = 0
        self._scan_optimizations: int = 0
        self._remediation_improvements: int = 0

        # False positive tracking
        self._fp_tracker: Dict[str, int] = defaultdict(int)
        self._suppressed_rules: Set[str] = set()
        self._processed_scan_ids: Set[str] = set()

        # Self-healing state
        self._healing_actions: List[Dict[str, Any]] = []
        self._watchdog_running = False

        # Initialize database
        self._init_db()
        self._load_persisted_state()

        logger.info("Evolution Engine v%s initialized — self-healing + learning + evolving", self.VERSION)

    # ─── Database ────────────────────────────────────────────────────────

    def _init_db(self):
        """Create evolution tracking tables."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS health_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    healed INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS learned_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    learning_type TEXT NOT NULL,
                    source_engine TEXT NOT NULL,
                    pattern_json TEXT NOT NULL,
                    confidence REAL DEFAULT 0,
                    observations INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    applied INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS evolutions (
                    evolution_id TEXT PRIMARY KEY,
                    evolution_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    source_patterns TEXT,
                    created_at TEXT NOT NULL,
                    applied INTEGER DEFAULT 0,
                    success INTEGER,
                    impact_score REAL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scan_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_ip TEXT NOT NULL,
                    port INTEGER,
                    service TEXT,
                    version TEXT,
                    finding_type TEXT,
                    severity TEXT,
                    scan_time TEXT NOT NULL,
                    remediated INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS false_positives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    finding_hash TEXT NOT NULL,
                    marked_by TEXT DEFAULT 'operator',
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS network_baselines (
                    baseline_key TEXT PRIMARY KEY,
                    baseline_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS processed_scan_learning (
                    scan_id TEXT PRIMARY KEY,
                    learned_at TEXT NOT NULL,
                    source TEXT,
                    learning_json TEXT,
                    evolution_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_health_component ON health_log(component_id);
                CREATE INDEX IF NOT EXISTS idx_patterns_type ON learned_patterns(learning_type);
                CREATE INDEX IF NOT EXISTS idx_scan_intel_host ON scan_intelligence(host_ip);
                CREATE INDEX IF NOT EXISTS idx_evolutions_type ON evolutions(evolution_type);
            """)
        self._secure_file_permissions(self.db_path)

    def _secure_file_permissions(self, path: str):
        """Best-effort privacy hardening for local files."""
        try:
            if os.path.exists(path):
                os.chmod(path, 0o600)
        except Exception:
            # Windows and some hosted environments may not honor POSIX perms.
            pass

    def _sha256_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _is_persistent_path(self, path: str) -> bool:
        normalized = os.path.abspath(path).replace("\\", "/")
        return normalized.startswith("/var/data/") or normalized.startswith("/data/")

    def _backup_metadata(self, path: str) -> Dict[str, Any]:
        st = os.stat(path)
        return {
            "name": os.path.basename(path),
            "path": path,
            "size_bytes": st.st_size,
            "sha256": self._sha256_file(path),
            "created_at": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        }

    def _load_persisted_state(self):
        """Hydrate durable learning/evolution state after process restarts."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                pattern_rows = conn.execute(
                    """SELECT pattern_id, learning_type, source_engine, pattern_json,
                              confidence, observations, first_seen, last_seen, applied
                       FROM learned_patterns"""
                ).fetchall()
                for row in pattern_rows:
                    try:
                        learning_type = LearningType(row["learning_type"])
                    except Exception:
                        continue
                    self._patterns[row["pattern_id"]] = LearnedPattern(
                        pattern_id=row["pattern_id"],
                        learning_type=learning_type,
                        source_engine=row["source_engine"],
                        pattern_data=json.loads(row["pattern_json"] or "{}"),
                        confidence=float(row["confidence"] or 0),
                        observations=int(row["observations"] or 0),
                        first_seen=row["first_seen"],
                        last_seen=row["last_seen"],
                        applied=bool(row["applied"]),
                    )

                baseline_rows = conn.execute(
                    "SELECT baseline_key, baseline_json FROM network_baselines"
                ).fetchall()
                for row in baseline_rows:
                    self._network_baselines[row["baseline_key"]] = json.loads(row["baseline_json"] or "{}")

                evo_rows = conn.execute(
                    """SELECT evolution_id, evolution_type, description, payload_json,
                              source_patterns, created_at, applied, success, impact_score
                       FROM evolutions"""
                ).fetchall()
                for row in evo_rows:
                    try:
                        evo_type = EvolutionType(row["evolution_type"])
                    except Exception:
                        continue
                    self._evolutions[row["evolution_id"]] = EvolutionEvent(
                        evolution_id=row["evolution_id"],
                        evolution_type=evo_type,
                        description=row["description"],
                        payload=json.loads(row["payload_json"] or "{}"),
                        source_patterns=json.loads(row["source_patterns"] or "[]"),
                        created_at=row["created_at"],
                        applied=bool(row["applied"]),
                        success=row["success"],
                        impact_score=float(row["impact_score"] or 0),
                    )

                fp_rows = conn.execute(
                    "SELECT rule_id, COUNT(*) AS cnt FROM false_positives GROUP BY rule_id"
                ).fetchall()
                for row in fp_rows:
                    count = int(row["cnt"] or 0)
                    self._fp_tracker[row["rule_id"]] = count
                    if count >= FALSE_POSITIVE_THRESHOLD:
                        self._suppressed_rules.add(row["rule_id"])

                processed_rows = conn.execute(
                    "SELECT scan_id FROM processed_scan_learning"
                ).fetchall()
                self._processed_scan_ids = {row["scan_id"] for row in processed_rows if row["scan_id"]}

                self._auto_rules_generated = sum(
                    1 for evo in self._evolutions.values()
                    if evo.evolution_type == EvolutionType.DETECTION_RULE
                )
                self._scan_optimizations = sum(
                    1 for evo in self._evolutions.values()
                    if evo.evolution_type == EvolutionType.SCAN_PROFILE
                )
                self._remediation_improvements = sum(
                    1 for evo in self._evolutions.values()
                    if evo.evolution_type == EvolutionType.REMEDIATION_PLAYBOOK
                )
        except Exception as exc:
            logger.warning("Failed to reload persisted evolution state: %s", exc)

    # ═════════════════════════════════════════════════════════════════════
    #  SELF-HEALING
    # ═════════════════════════════════════════════════════════════════════

    def register_component(self, component_id: str, name: str) -> ComponentHealth:
        """Register an engine component for health monitoring."""
        health = ComponentHealth(
            component_id=component_id,
            component_name=name,
            status=HealthStatus.HEALTHY,
            last_check=datetime.now(timezone.utc).isoformat(),
        )
        self._components[component_id] = health
        return health

    def register_component_probe(self, component_id: str, check_fn) -> None:
        """Register a real health probe for verified recovery checks."""
        self._component_checks[component_id] = check_fn

    def register_component_recovery(self, component_id: str, recovery_fn) -> None:
        """Register a real recovery callback for a component."""
        self._component_recoveries[component_id].append(recovery_fn)

    def check_health(self, component_id: str, check_fn=None) -> ComponentHealth:
        """Check health of a registered component. Optionally run a check function."""
        health = self._components.get(component_id)
        if not health:
            health = self.register_component(component_id, component_id)
        check_fn = check_fn or self._component_checks.get(component_id)

        now = datetime.now(timezone.utc)
        health.last_check = now.isoformat()

        if check_fn:
            try:
                result = check_fn()
                if result.get("healthy", True):
                    if health.status in (HealthStatus.DEGRADED, HealthStatus.CRITICAL):
                        health.status = HealthStatus.RECOVERING
                        health.auto_healed += 1
                        self._log_healing(component_id, "verified_recovery", "Component recovered via health probe")
                    else:
                        health.status = HealthStatus.HEALTHY
                    health.metrics = result.get("metrics", {})
                else:
                    health.status = HealthStatus.DEGRADED
                    health.error_count += 1
                    health.last_error = result.get("error", "Health check failed")
                    self._attempt_heal(component_id, health)
            except Exception as e:
                health.status = HealthStatus.CRITICAL
                health.error_count += 1
                health.last_error = str(e)
                self._attempt_heal(component_id, health)

        # Log to DB
        self._log_health(health)
        return health

    def check_all_health(self) -> Dict[str, ComponentHealth]:
        """Run health checks on all registered components."""
        results = {}
        for cid in list(self._components.keys()):
            results[cid] = self.check_health(cid)
        return results

    def _attempt_heal(self, component_id: str, health: ComponentHealth):
        """Attempt automatic healing of a degraded/critical component."""
        action = {
            "component_id": component_id,
            "action": "auto_heal",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status_before": health.status.value,
            "attempts": 0,
            "success": False,
        }

        probe_fn = self._component_checks.get(component_id)
        if probe_fn is None:
            action["reason"] = "no_probe_registered"
            self._healing_actions.append(action)
            self._log_healing(component_id, "skipped", "No verified probe registered")
            return

        # Healing strategies based on component type
        strategies = self._get_healing_strategies(component_id)

        for strategy in strategies:
            action["attempts"] += 1
            try:
                result = strategy(component_id)
                if result.get("healed"):
                    probe_result = probe_fn()
                    if not probe_result.get("healthy", False):
                        action["last_probe_error"] = probe_result.get("error", "post_recovery_probe_failed")
                        continue
                    health.status = HealthStatus.RECOVERING
                    health.auto_healed += 1
                    action["success"] = True
                    action["strategy"] = result.get("strategy", "unknown")
                    health.metrics = probe_result.get("metrics", {})
                    logger.info("Auto-healed component %s using %s", component_id, action["strategy"])
                    break
            except Exception as e:
                logger.warning("Healing strategy failed for %s: %s", component_id, e)

        self._healing_actions.append(action)
        self._log_healing(component_id, "attempt", json.dumps(action, default=str))

    def _get_healing_strategies(self, component_id: str) -> list:
        """Return ordered list of healing strategies for a component."""
        strategies = []
        for idx, recovery_fn in enumerate(self._component_recoveries.get(component_id, [])):
            def _strategy(cid, fn=recovery_fn, i=idx):
                result = fn(cid)
                if isinstance(result, dict):
                    return {
                        "healed": bool(result.get("healed", False)),
                        "strategy": result.get("strategy", f"recovery_{i}"),
                    }
                return {"healed": bool(result), "strategy": f"recovery_{i}"}
            strategies.append(_strategy)
        return strategies

    def _log_health(self, health: ComponentHealth):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO health_log (component_id, status, error, timestamp) VALUES (?, ?, ?, ?)",
                    (health.component_id, health.status.value, health.last_error,
                     datetime.now(timezone.utc).isoformat()),
                )
        except Exception as e:
            logger.warning("Failed to log health: %s", e)

    def _log_healing(self, component_id: str, action: str, detail: str):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO health_log (component_id, status, error, healed, timestamp) VALUES (?, ?, ?, 1, ?)",
                    (component_id, "healing", f"{action}: {detail}",
                     datetime.now(timezone.utc).isoformat()),
                )
        except Exception as e:
            logger.warning("Failed to log healing: %s", e)

    # ═════════════════════════════════════════════════════════════════════
    #  SELF-LEARNING
    # ═════════════════════════════════════════════════════════════════════

    def learn_from_scan(self, scan_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest a scan report and extract learnable intelligence.

        Returns summary of what was learned.
        """
        learned = {
            "new_baselines": 0,
            "updated_baselines": 0,
            "new_patterns": 0,
            "service_fingerprints": 0,
            "scan_optimizations": 0,
        }

        hosts = scan_report.get("hosts", [])
        for host in hosts:
            ip = host.get("ip", "")
            if not ip:
                continue

            # Learn network baseline
            baseline_key = f"baseline:{ip}"
            existing = self._network_baselines.get(baseline_key)

            services = host.get("services", {})
            open_ports = host.get("open_ports", [])
            os_guess = host.get("os_guess", "")

            if existing:
                # Update existing baseline
                existing["scan_count"] = existing.get("scan_count", 0) + 1
                existing["last_seen"] = datetime.now(timezone.utc).isoformat()
                existing["port_history"].append(sorted(open_ports))
                existing["os_history"].append(os_guess)

                # Calculate baseline stability
                port_sets = [frozenset(p) for p in existing["port_history"][-10:]]
                if port_sets:
                    most_common = Counter(port_sets).most_common(1)[0]
                    existing["stability"] = most_common[1] / len(port_sets)

                learned["updated_baselines"] += 1
            else:
                # New baseline
                self._network_baselines[baseline_key] = {
                    "host_ip": ip,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "scan_count": 1,
                    "open_ports": sorted(open_ports),
                    "services": services,
                    "os_guess": os_guess,
                    "port_history": [sorted(open_ports)],
                    "os_history": [os_guess],
                    "stability": 1.0,
                }
                learned["new_baselines"] += 1

            # Learn service fingerprints
            for port, svc in services.items():
                fp_id = f"fp:{svc.get('service', '')}:{svc.get('version', '')}"
                self._record_pattern(
                    pattern_id=fp_id,
                    learning_type=LearningType.FINGERPRINT,
                    source="live_scanner",
                    data={"port": port, "service": svc.get("service"), "version": svc.get("version"),
                          "banner_snippet": svc.get("banner", "")[:200]},
                )
                learned["service_fingerprints"] += 1

            # Learn from findings — extract attack patterns
            findings = host.get("findings", [])
            for finding in findings:
                pattern_key = f"vuln:{finding.get('category', '')}:{finding.get('title', '')[:50]}"
                self._record_pattern(
                    pattern_id=hashlib.sha256(pattern_key.encode()).hexdigest()[:16],
                    learning_type=LearningType.PATTERN,
                    source="live_scanner",
                    data={
                        "finding_type": finding.get("category"),
                        "severity": finding.get("severity"),
                        "title": finding.get("title"),
                        "port": finding.get("port"),
                        "service": finding.get("service"),
                        "remediation": finding.get("remediation"),
                    },
                )
                learned["new_patterns"] += 1

                # Record to scan intelligence DB
                self._record_scan_intel(ip, finding)

        # Optimize scan strategy based on learning
        optimizations = self._optimize_scan_strategy()
        learned["scan_optimizations"] = len(optimizations)

        self._persist_patterns()
        self._persist_baselines()
        return learned

    def learn_from_completed_scan(self, scan_report: Dict[str, Any], source: str = "scan_status") -> Dict[str, Any]:
        """
        Silently learn from a completed scan result exactly once.

        This path is safe to call from polling/status routes because it is
        idempotent on scan_id and persists completion markers in the DB.
        """
        scan_id = str(scan_report.get("scan_id") or "").strip()
        if scan_id and scan_id in self._processed_scan_ids:
            return {"scan_id": scan_id, "already_processed": True}

        if scan_report.get("hosts"):
            learning = self.learn_from_scan(scan_report)
        else:
            learning = self._learn_from_scan_summary(scan_report)

        evolution = self.evolve()

        if scan_id:
            learned_at = datetime.now(timezone.utc).isoformat()
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        """INSERT OR REPLACE INTO processed_scan_learning
                           (scan_id, learned_at, source, learning_json, evolution_json)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            scan_id,
                            learned_at,
                            source,
                            json.dumps(learning, default=str),
                            json.dumps(evolution, default=str),
                        ),
                    )
                self._processed_scan_ids.add(scan_id)
            except Exception as exc:
                logger.warning("Failed to persist processed scan learning marker for %s: %s", scan_id, exc)

        return {
            "scan_id": scan_id or None,
            "already_processed": False,
            "learning": learning,
            "evolution": evolution,
        }

    def learn_from_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Extract TTP patterns from incident data."""
        learned = {"ttp_patterns": 0, "ioc_patterns": 0}

        # Extract MITRE techniques
        techniques = incident.get("mitre_techniques", [])
        for tech in techniques:
            self._record_pattern(
                pattern_id=f"ttp:{tech}:{incident.get('category', '')}",
                learning_type=LearningType.TTP,
                source="incident_response",
                data={
                    "technique": tech,
                    "category": incident.get("category"),
                    "severity": incident.get("severity"),
                    "affected_assets": incident.get("affected_assets", []),
                },
            )
            learned["ttp_patterns"] += 1

        # Extract IOCs
        iocs = incident.get("iocs", [])
        for ioc in iocs:
            self._record_pattern(
                pattern_id=f"ioc:{ioc.get('type', '')}:{ioc.get('value', '')[:32]}",
                learning_type=LearningType.PATTERN,
                source="incident_response",
                data=ioc,
            )
            learned["ioc_patterns"] += 1

        return learned

    def learn_from_remediation(self, plan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Learn which remediation strategies work."""
        learned = {"playbook_improvements": 0}

        actions = plan_result.get("actions", [])
        for action in actions:
            success = action.get("status") == "completed"
            self._record_pattern(
                pattern_id=f"fix:{action.get('category', '')}:{action.get('title', '')[:30]}",
                learning_type=LearningType.REMEDIATION,
                source="auto_remediation",
                data={
                    "category": action.get("category"),
                    "title": action.get("title"),
                    "commands": action.get("commands", []),
                    "success": success,
                    "risk_level": action.get("risk_level"),
                    "execution_time": action.get("execution_time"),
                },
            )
            if success:
                learned["playbook_improvements"] += 1

        return learned

    def _record_pattern(self, pattern_id: str, learning_type: LearningType,
                        source: str, data: Dict[str, Any]):
        """Record or update a learned pattern."""
        now = datetime.now(timezone.utc).isoformat()

        existing = self._patterns.get(pattern_id)
        if existing:
            existing.observations += 1
            existing.last_seen = now
            existing.confidence = min(1.0, existing.confidence + 0.05)
        else:
            self._patterns[pattern_id] = LearnedPattern(
                pattern_id=pattern_id,
                learning_type=learning_type,
                source_engine=source,
                pattern_data=data,
                confidence=0.5,
                observations=1,
                first_seen=now,
                last_seen=now,
            )

    def _record_scan_intel(self, ip: str, finding: Dict[str, Any]):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT INTO scan_intelligence
                       (host_ip, port, service, version, finding_type, severity, scan_time)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (ip, finding.get("port"), finding.get("service"),
                     finding.get("version"), finding.get("category"),
                     finding.get("severity"), datetime.now(timezone.utc).isoformat()),
                )
        except Exception as e:
            logger.warning("Failed to record scan intel: %s", e)

    def _learn_from_scan_summary(self, scan_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Learn from summary-only scan results when detailed host telemetry is
        unavailable from the async scan path.
        """
        learned = {
            "summary_patterns": 0,
            "new_baselines": 0,
            "updated_baselines": 0,
            "new_patterns": 0,
            "service_fingerprints": 0,
            "scan_optimizations": 0,
        }

        target = str(scan_report.get("target") or "").strip()
        scan_type = str(scan_report.get("scan_type") or "full").strip()
        summary_key = hashlib.sha256(
            f"summary:{target}:{scan_type}:{scan_report.get('risk_score', 0)}".encode()
        ).hexdigest()[:16]

        self._record_pattern(
            pattern_id=summary_key,
            learning_type=LearningType.SCAN_STRATEGY,
            source="async_summary",
            data={
                "target": target,
                "scan_type": scan_type,
                "risk_score": scan_report.get("risk_score", 0),
                "critical_count": scan_report.get("critical_count", 0),
                "high_count": scan_report.get("high_count", 0),
                "medium_count": scan_report.get("medium_count", 0),
                "low_count": scan_report.get("low_count", 0),
                "assets_discovered": scan_report.get("assets_discovered", 0),
                "vulnerabilities_found": scan_report.get("vulnerabilities_found", 0),
            },
        )
        learned["summary_patterns"] = 1

        if target and "/" not in target:
            baseline_key = f"baseline:{target}"
            now = datetime.now(timezone.utc).isoformat()
            existing = self._network_baselines.get(baseline_key)
            if existing:
                existing["scan_count"] = existing.get("scan_count", 0) + 1
                existing["last_seen"] = now
                existing["last_risk_score"] = scan_report.get("risk_score", 0)
                existing["last_summary"] = {
                    "critical_count": scan_report.get("critical_count", 0),
                    "high_count": scan_report.get("high_count", 0),
                    "medium_count": scan_report.get("medium_count", 0),
                    "low_count": scan_report.get("low_count", 0),
                    "assets_discovered": scan_report.get("assets_discovered", 0),
                }
                learned["updated_baselines"] += 1
            else:
                self._network_baselines[baseline_key] = {
                    "host_ip": target,
                    "first_seen": now,
                    "last_seen": now,
                    "scan_count": 1,
                    "open_ports": [],
                    "services": {},
                    "os_guess": "",
                    "port_history": [],
                    "os_history": [],
                    "stability": 1.0,
                    "last_risk_score": scan_report.get("risk_score", 0),
                    "last_summary": {
                        "critical_count": scan_report.get("critical_count", 0),
                        "high_count": scan_report.get("high_count", 0),
                        "medium_count": scan_report.get("medium_count", 0),
                        "low_count": scan_report.get("low_count", 0),
                        "assets_discovered": scan_report.get("assets_discovered", 0),
                    },
                }
                learned["new_baselines"] += 1

        optimizations = self._optimize_scan_strategy()
        learned["scan_optimizations"] = len(optimizations)
        self._persist_patterns()
        self._persist_baselines()
        return learned

    def _optimize_scan_strategy(self) -> List[Dict[str, Any]]:
        """Analyze learned data to optimize future scan parameters."""
        optimizations = []

        # Find most commonly vulnerable ports
        port_vulns: Dict[int, int] = defaultdict(int)
        for pattern in self._patterns.values():
            if pattern.learning_type == LearningType.PATTERN:
                port = pattern.pattern_data.get("port")
                if port:
                    port_vulns[int(port)] += pattern.observations

        # Generate priority port list
        if port_vulns:
            sorted_ports = sorted(port_vulns.items(), key=lambda x: x[1], reverse=True)
            priority_ports = [p for p, _ in sorted_ports[:30]]
            optimizations.append({
                "type": "port_priority",
                "ports": priority_ports,
                "reason": "Most frequently vulnerable ports from scan history",
            })
            self._scan_optimizations += 1

        # Find services with most vulnerabilities
        svc_vulns: Dict[str, int] = defaultdict(int)
        for pattern in self._patterns.values():
            if pattern.learning_type == LearningType.FINGERPRINT:
                svc = pattern.pattern_data.get("service", "")
                if svc:
                    svc_vulns[svc] += pattern.observations

        if svc_vulns:
            high_risk_services = [s for s, c in svc_vulns.items() if c >= 3]
            if high_risk_services:
                optimizations.append({
                    "type": "service_focus",
                    "services": high_risk_services,
                    "reason": "Services with recurring vulnerabilities",
                })

        return optimizations

    def _persist_patterns(self):
        """Write patterns to DB."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                for p in self._patterns.values():
                    conn.execute(
                        """INSERT OR REPLACE INTO learned_patterns
                           (pattern_id, learning_type, source_engine, pattern_json,
                            confidence, observations, first_seen, last_seen, applied)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (p.pattern_id, p.learning_type.value, p.source_engine,
                         json.dumps(p.pattern_data, default=str), p.confidence,
                         p.observations, p.first_seen, p.last_seen, int(p.applied)),
                    )
        except Exception as e:
            logger.warning("Failed to persist patterns: %s", e)

    def _persist_baselines(self):
        """Write network baselines to DB so restarts preserve scan history."""
        try:
            now = datetime.now(timezone.utc).isoformat()
            with sqlite3.connect(self.db_path) as conn:
                for key, baseline in self._network_baselines.items():
                    conn.execute(
                        """INSERT OR REPLACE INTO network_baselines
                           (baseline_key, baseline_json, updated_at)
                           VALUES (?, ?, ?)""",
                        (key, json.dumps(baseline, default=str), now),
                    )
        except Exception as e:
            logger.warning("Failed to persist baselines: %s", e)

    # ═════════════════════════════════════════════════════════════════════
    #  SELF-EVOLVING
    # ═════════════════════════════════════════════════════════════════════

    def evolve(self) -> Dict[str, Any]:
        """
        Run the evolution cycle. Analyzes all learned patterns and
        generates new capabilities.

        Returns summary of evolutions created.
        """
        evolutions = {
            "new_detection_rules": 0,
            "scan_profile_updates": 0,
            "remediation_playbook_updates": 0,
            "threshold_adjustments": 0,
            "total_patterns_analyzed": len(self._patterns),
        }

        # 1. Generate detection rules from patterns
        rules = self._evolve_detection_rules()
        evolutions["new_detection_rules"] = len(rules)

        # 2. Update scan profiles
        profiles = self._evolve_scan_profiles()
        evolutions["scan_profile_updates"] = len(profiles)

        # 3. Improve remediation playbooks
        playbooks = self._evolve_remediation_playbooks()
        evolutions["remediation_playbook_updates"] = len(playbooks)

        # 4. Adjust detection thresholds
        thresholds = self._evolve_thresholds()
        evolutions["threshold_adjustments"] = len(thresholds)

        self._persist_evolutions()
        return evolutions

    def _evolve_detection_rules(self) -> List[EvolutionEvent]:
        """Generate new detection rules from attack patterns."""
        new_rules = []

        if self._auto_rules_generated >= MAX_RULES_AUTO_GENERATED:
            return new_rules

        # Find high-confidence vulnerability patterns
        for pattern in self._patterns.values():
            if (pattern.learning_type in (LearningType.PATTERN, LearningType.TTP)
                    and pattern.confidence >= BASELINE_CONFIDENCE_THRESHOLD
                    and pattern.observations >= 3
                    and not pattern.applied):

                data = pattern.pattern_data
                severity = data.get("severity", "MEDIUM")

                # Generate Sigma-compatible detection rule
                rule_payload = {
                    "rule_type": "sigma",
                    "title": f"QC-AUTO: {data.get('title', data.get('technique', 'Unknown'))}",
                    "description": f"Auto-generated from {pattern.observations} observations",
                    "severity": severity,
                    "mitre_technique": data.get("technique", ""),
                    "detection": {
                        "service": data.get("service", "*"),
                        "port": data.get("port"),
                        "category": data.get("finding_type", data.get("category", "")),
                    },
                    "confidence": pattern.confidence,
                    "auto_generated": True,
                    "source_pattern": pattern.pattern_id,
                }

                evolution = EvolutionEvent(
                    evolution_id=f"rule-{uuid.uuid4().hex[:12]}",
                    evolution_type=EvolutionType.DETECTION_RULE,
                    description=f"New detection rule from {pattern.observations} observations of {data.get('title', 'pattern')}",
                    payload=rule_payload,
                    source_patterns=[pattern.pattern_id],
                    created_at=datetime.now(timezone.utc).isoformat(),
                )

                self._evolutions[evolution.evolution_id] = evolution
                new_rules.append(evolution)
                pattern.applied = True
                self._auto_rules_generated += 1

        return new_rules

    def _evolve_scan_profiles(self) -> List[EvolutionEvent]:
        """Optimize scan profiles based on learned network behavior."""
        profiles = []

        # Analyze baseline stability
        stable_hosts = []
        volatile_hosts = []

        for key, baseline in self._network_baselines.items():
            stability = baseline.get("stability", 0)
            if stability >= 0.9 and baseline.get("scan_count", 0) >= 5:
                stable_hosts.append(baseline["host_ip"])
            elif stability < 0.5:
                volatile_hosts.append(baseline["host_ip"])

        if volatile_hosts:
            evolution = EvolutionEvent(
                evolution_id=f"profile-{uuid.uuid4().hex[:12]}",
                evolution_type=EvolutionType.SCAN_PROFILE,
                description=f"Increase scan frequency for {len(volatile_hosts)} volatile hosts",
                payload={
                    "action": "increase_frequency",
                    "hosts": volatile_hosts[:50],
                    "recommended_interval_minutes": 5,
                    "reason": "Network configuration instability detected",
                },
                source_patterns=[],
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._evolutions[evolution.evolution_id] = evolution
            profiles.append(evolution)

        if stable_hosts and len(stable_hosts) >= 5:
            evolution = EvolutionEvent(
                evolution_id=f"profile-{uuid.uuid4().hex[:12]}",
                evolution_type=EvolutionType.SCAN_PROFILE,
                description=f"Reduce scan frequency for {len(stable_hosts)} stable hosts",
                payload={
                    "action": "decrease_frequency",
                    "hosts": stable_hosts[:50],
                    "recommended_interval_minutes": 30,
                    "reason": "Consistent baseline over multiple scans",
                },
                source_patterns=[],
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._evolutions[evolution.evolution_id] = evolution
            profiles.append(evolution)

        return profiles

    def _evolve_remediation_playbooks(self) -> List[EvolutionEvent]:
        """Improve remediation playbooks from success/failure history."""
        playbooks = []

        # Find successful remediation patterns
        successful_fixes = {}
        failed_fixes = {}

        for pattern in self._patterns.values():
            if pattern.learning_type == LearningType.REMEDIATION:
                category = pattern.pattern_data.get("category", "")
                if pattern.pattern_data.get("success"):
                    if category not in successful_fixes:
                        successful_fixes[category] = []
                    successful_fixes[category].append(pattern)
                else:
                    if category not in failed_fixes:
                        failed_fixes[category] = []
                    failed_fixes[category].append(pattern)

        # Generate improved playbooks for categories with both successes and failures
        for category in set(successful_fixes.keys()) & set(failed_fixes.keys()):
            good = successful_fixes[category]
            bad = failed_fixes[category]

            if len(good) >= 2:
                # Extract common commands from successful fixes
                good_commands = [p.pattern_data.get("commands", []) for p in good]

                evolution = EvolutionEvent(
                    evolution_id=f"playbook-{uuid.uuid4().hex[:12]}",
                    evolution_type=EvolutionType.REMEDIATION_PLAYBOOK,
                    description=f"Improved playbook for {category} ({len(good)} successes, {len(bad)} failures)",
                    payload={
                        "category": category,
                        "success_rate": len(good) / (len(good) + len(bad)),
                        "recommended_commands": good_commands[0] if good_commands else [],
                        "avoid_patterns": [p.pattern_data.get("title") for p in bad[:5]],
                    },
                    source_patterns=[p.pattern_id for p in good[:5]],
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                self._evolutions[evolution.evolution_id] = evolution
                playbooks.append(evolution)
                self._remediation_improvements += 1

        return playbooks

    def _evolve_thresholds(self) -> List[EvolutionEvent]:
        """Adjust detection thresholds based on false positive tracking."""
        adjustments = []

        for rule_id, fp_count in self._fp_tracker.items():
            if fp_count >= FALSE_POSITIVE_THRESHOLD and rule_id not in self._suppressed_rules:
                evolution = EvolutionEvent(
                    evolution_id=f"threshold-{uuid.uuid4().hex[:12]}",
                    evolution_type=EvolutionType.THRESHOLD_ADJUSTMENT,
                    description=f"Suppress rule {rule_id} — {fp_count} false positives",
                    payload={
                        "rule_id": rule_id,
                        "false_positives": fp_count,
                        "action": "suppress",
                        "reason": f"Exceeded FP threshold ({FALSE_POSITIVE_THRESHOLD})",
                    },
                    source_patterns=[],
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                self._evolutions[evolution.evolution_id] = evolution
                self._suppressed_rules.add(rule_id)
                adjustments.append(evolution)

        return adjustments

    def mark_false_positive(self, rule_id: str, finding_hash: str,
                            marked_by: str = "operator") -> Dict[str, Any]:
        """Mark a finding as a false positive. Used by the dashboard one-click FP button."""
        self._fp_tracker[rule_id] += 1

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO false_positives (rule_id, finding_hash, marked_by, timestamp) VALUES (?, ?, ?, ?)",
                    (rule_id, finding_hash, marked_by, datetime.now(timezone.utc).isoformat()),
                )
        except Exception:
            pass

        suppressed = self._fp_tracker[rule_id] >= FALSE_POSITIVE_THRESHOLD
        if suppressed:
            self._suppressed_rules.add(rule_id)

        return {
            "rule_id": rule_id,
            "total_fps": self._fp_tracker[rule_id],
            "suppressed": suppressed,
            "threshold": FALSE_POSITIVE_THRESHOLD,
        }

    def _persist_evolutions(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                for e in self._evolutions.values():
                    conn.execute(
                        """INSERT OR REPLACE INTO evolutions
                           (evolution_id, evolution_type, description, payload_json,
                            source_patterns, created_at, applied, success, impact_score)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (e.evolution_id, e.evolution_type.value, e.description,
                         json.dumps(e.payload, default=str),
                         json.dumps(e.source_patterns), e.created_at,
                         int(e.applied), e.success, e.impact_score),
                    )
        except Exception as ex:
            logger.warning("Failed to persist evolutions: %s", ex)

    # ═════════════════════════════════════════════════════════════════════
    #  ONE-CLICK OPERATIONS
    # ═════════════════════════════════════════════════════════════════════

    def one_click_scan_and_fix(self, target: str, auto_approve: bool = False,
                               scan_type: str = "full") -> Dict[str, Any]:
        """
        THE ONE-COMMAND OPERATION.

        1. Scan the target network
        2. Analyze all findings
        3. Feed everything to zero-day predictor
        4. Generate remediation plan
        5. Auto-learn from results
        6. Evolve detection capabilities
        7. Optionally execute fixes

        Returns complete operation report.
        """
        from engines.live_scanner import LiveScanner
        from engines.auto_remediation import AutoRemediation

        operation_id = f"op-{uuid.uuid4().hex[:12]}"
        start_time = time.time()

        report = {
            "operation_id": operation_id,
            "target": target,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "phases": {},
        }

        # Phase 1: Scan
        logger.info("[%s] Phase 1: Scanning %s", operation_id, target)
        scanner = LiveScanner(self.config)
        scan_result = scanner.scan(target, scan_type=scan_type)
        scan_dict = scan_result.to_dict() if hasattr(scan_result, "to_dict") else scan_result

        report["phases"]["scan"] = {
            "scan_id": scan_dict.get("scan_id"),
            "hosts_alive": scan_dict.get("total_hosts_alive", 0),
            "total_findings": scan_dict.get("total_findings", 0),
            "critical": scan_dict.get("critical_findings", 0),
            "high": scan_dict.get("high_findings", 0),
            "overall_risk": scan_dict.get("overall_risk", 0),
            "quantum_risk": scan_dict.get("quantum_risk_summary", ""),
        }

        # Phase 2: Learn from scan
        logger.info("[%s] Phase 2: Learning from scan results", operation_id)
        learning = self.learn_from_scan(scan_dict)
        report["phases"]["learning"] = learning

        # Phase 3: Zero-day prediction
        logger.info("[%s] Phase 3: Zero-day prediction analysis", operation_id)
        try:
            from engines.zero_day_predictor import ZeroDayPredictor
            predictor = ZeroDayPredictor()
            predictions = []
            for host in scan_dict.get("hosts", []):
                for finding in host.get("findings", []):
                    pred = predictor.analyze_event({
                        "type": "vulnerability",
                        "source": host.get("ip"),
                        "data": finding,
                    })
                    if pred.get("risk_score", 0) >= 0.7:
                        predictions.append(pred)
            report["phases"]["zero_day"] = {
                "predictions_generated": len(predictions),
                "high_risk_predictions": len([p for p in predictions if p.get("risk_score", 0) >= 0.85]),
            }
        except Exception as e:
            report["phases"]["zero_day"] = {"error": str(e)}

        # Phase 4: Remediation plan
        logger.info("[%s] Phase 4: Generating remediation plan", operation_id)
        all_findings = []
        for host in scan_dict.get("hosts", []):
            for f in host.get("findings", []):
                fd = f if isinstance(f, dict) else (asdict(f) if hasattr(f, '__dataclass_fields__') else {})
                all_findings.append(fd)

        remediator = AutoRemediation({"allow_execute": auto_approve})
        if all_findings:
            plan = remediator.generate_plan(all_findings, target_host=target)
            plan_dict = plan.to_dict() if hasattr(plan, "to_dict") else plan
            priority_actions = []
            for idx, action in enumerate(plan_dict.get("actions", [])):
                priority_actions.append({
                    "priority": idx + 1,
                    "action_id": action.get("action_id"),
                    "vuln_id": action.get("finding_id") or action.get("action_id"),
                    "cve_id": "",
                    "title": action.get("title") or f"Remediation action {idx + 1}",
                    "severity": str(action.get("risk_level", "low")).upper(),
                    "cvss_score": None,
                    "affected_asset": plan_dict.get("target_host") or target,
                    "remediation": action.get("description") or " ; ".join(action.get("commands", [])[:2]),
                    "category": action.get("category", "other"),
                    "commands": action.get("commands", []),
                    "rollback_commands": action.get("rollback_commands", []),
                })

            report["phases"]["remediation"] = {
                "plan_id": plan_dict.get("plan_id"),
                "total_actions": plan_dict.get("total_actions", 0),
                "target_host": plan_dict.get("target_host") or target,
                "categories": {},
                "actions": plan_dict.get("actions", []),
                "priority_actions": priority_actions,
            }

            # Categorize actions
            for action in plan_dict.get("actions", []):
                cat = action.get("category", "other")
                if cat not in report["phases"]["remediation"]["categories"]:
                    report["phases"]["remediation"]["categories"][cat] = 0
                report["phases"]["remediation"]["categories"][cat] += 1

            # Phase 5: Execute if approved
            if auto_approve and all_findings:
                logger.info("[%s] Phase 5: Executing remediation (auto-approved)", operation_id)
                exec_result = remediator.execute_plan(plan_dict.get("plan_id", ""))
                report["phases"]["execution"] = exec_result

                # Learn from remediation
                self.learn_from_remediation(exec_result)
        else:
            report["phases"]["remediation"] = {"total_actions": 0, "message": "No findings to remediate"}

        # Phase 6: Evolve
        logger.info("[%s] Phase 6: Evolution cycle", operation_id)
        evolution = self.evolve()
        report["phases"]["evolution"] = evolution

        # Final summary
        elapsed = time.time() - start_time
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["duration_seconds"] = round(elapsed, 2)
        report["status"] = "completed"

        # Risk assessment
        risk = report["phases"]["scan"].get("overall_risk", 0)
        if risk >= 8:
            report["risk_level"] = "CRITICAL"
            report["recommendation"] = "Immediate action required. Execute remediation plan."
        elif risk >= 6:
            report["risk_level"] = "HIGH"
            report["recommendation"] = "Review and execute remediation within 24 hours."
        elif risk >= 4:
            report["risk_level"] = "MEDIUM"
            report["recommendation"] = "Schedule remediation within one week."
        else:
            report["risk_level"] = "LOW"
            report["recommendation"] = "Network posture is good. Continue monitoring."

        return report

    # ═════════════════════════════════════════════════════════════════════
    #  STATUS & REPORTING
    # ═════════════════════════════════════════════════════════════════════

    def get_status(self) -> Dict[str, Any]:
        """Complete evolution engine status."""
        return {
            "version": self.VERSION,
            "status": "operational",
            "uptime_since": self._start_time,
            "components": {
                cid: h.to_dict() for cid, h in self._components.items()
            },
            "learning": {
                "total_patterns": len(self._patterns),
                "baselines": len(self._network_baselines),
                "pattern_types": dict(Counter(
                    p.learning_type.value for p in self._patterns.values()
                )),
                "avg_confidence": (
                    statistics.mean(p.confidence for p in self._patterns.values())
                    if self._patterns else 0
                ),
            },
            "evolution": {
                "total_evolutions": len(self._evolutions),
                "auto_rules_generated": self._auto_rules_generated,
                "scan_optimizations": self._scan_optimizations,
                "remediation_improvements": self._remediation_improvements,
                "suppressed_rules": len(self._suppressed_rules),
            },
            "self_healing": {
                "healing_actions": len(self._healing_actions),
                "total_auto_heals": sum(h.auto_healed for h in self._components.values()),
            },
        }

    def get_intelligence_report(self) -> Dict[str, Any]:
        """Generate a comprehensive intelligence report."""
        # Top vulnerability patterns
        vuln_patterns = sorted(
            [p for p in self._patterns.values() if p.learning_type == LearningType.PATTERN],
            key=lambda p: p.observations,
            reverse=True,
        )[:20]

        # TTP patterns
        ttp_patterns = sorted(
            [p for p in self._patterns.values() if p.learning_type == LearningType.TTP],
            key=lambda p: p.confidence,
            reverse=True,
        )[:10]

        # Baseline summary
        baseline_summary = {
            "total_hosts": len(self._network_baselines),
            "stable_hosts": sum(1 for b in self._network_baselines.values() if b.get("stability", 0) >= 0.9),
            "volatile_hosts": sum(1 for b in self._network_baselines.values() if b.get("stability", 0) < 0.5),
        }

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "top_vulnerability_patterns": [p.to_dict() for p in vuln_patterns],
            "ttp_patterns": [p.to_dict() for p in ttp_patterns],
            "network_baselines": baseline_summary,
            "evolution_summary": {
                "total_evolutions": len(self._evolutions),
                "by_type": dict(Counter(
                    e.evolution_type.value for e in self._evolutions.values()
                )),
            },
            "false_positive_summary": {
                "total_tracked": sum(self._fp_tracker.values()),
                "rules_suppressed": len(self._suppressed_rules),
            },
        }

    def get_learned_baselines(self) -> List[Dict[str, Any]]:
        """Get all learned network baselines."""
        return [
            {**v, "port_history": v.get("port_history", [])[-5:]}
            for v in self._network_baselines.values()
        ]

    def get_evolutions(self, evolution_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get evolution events, optionally filtered by type."""
        evos = list(self._evolutions.values())
        if evolution_type:
            evos = [e for e in evos if e.evolution_type.value == evolution_type]
        return [e.to_dict() for e in sorted(evos, key=lambda e: e.created_at, reverse=True)]

    def get_storage_status(self) -> Dict[str, Any]:
        """Return safe storage metadata for persistence/backup monitoring."""
        db_exists = os.path.exists(self.db_path)
        backup_dir_exists = os.path.isdir(self.backup_dir)
        backup_count = 0
        if backup_dir_exists:
            backup_count = len([p for p in os.listdir(self.backup_dir) if p.endswith(".sqlite3")])

        return {
            "db_path": self.db_path,
            "db_exists": db_exists,
            "db_size_bytes": os.path.getsize(self.db_path) if db_exists else 0,
            "backup_dir": self.backup_dir,
            "backup_dir_exists": backup_dir_exists,
            "backup_count": backup_count,
            "persistent_db": self._is_persistent_path(self.db_path),
            "persistent_backups": self._is_persistent_path(self.backup_dir),
        }

    def list_backups(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List backup snapshots, newest first."""
        Path(self.backup_dir).mkdir(parents=True, exist_ok=True)
        backups = []
        for entry in Path(self.backup_dir).glob("*.sqlite3"):
            if entry.is_file():
                backups.append((entry.stat().st_mtime, str(entry)))
        backups.sort(reverse=True)
        return [self._backup_metadata(path) for _, path in backups[: max(1, min(int(limit), 100))]]

    def create_backup(self, label: Optional[str] = None) -> Dict[str, Any]:
        """Create a point-in-time SQLite backup for memory persistence."""
        Path(self.backup_dir).mkdir(parents=True, exist_ok=True)
        safe_label = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(label or "")).strip("-")[:48]
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"qc_evolution_{ts}"
        if safe_label:
            name += f"_{safe_label}"
        backup_path = os.path.join(self.backup_dir, f"{name}.sqlite3")

        with sqlite3.connect(self.db_path) as src, sqlite3.connect(backup_path) as dest:
            src.backup(dest)

        self._secure_file_permissions(backup_path)
        return {
            "success": True,
            "backup": self._backup_metadata(backup_path),
        }
