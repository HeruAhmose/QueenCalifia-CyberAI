"""
engines.blue_team_tactics — Detection, Hunting & Automated Defense
===================================================================

Defensive operations engine for QueenCalifia CyberAI.

Capabilities:
  - Detection rule management (Sigma-compatible structure)
  - Threat hunting query execution
  - IOC correlation engine
  - Automated response playbooks (SOAR integration)
  - Detection coverage mapping against MITRE ATT&CK
  - Alert enrichment pipeline
  - Defense gap analysis

Architecture:
  All defensive actions route through SovereigntyExecutor.
  Detection rules are versioned and audited.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("engines.blue_team")


# ─── Detection Rule Engine ──────────────────────────────────────────────────

class RuleSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    DISABLED = "disabled"
    RETIRED = "retired"


@dataclass
class DetectionRule:
    """Sigma-compatible detection rule structure."""
    rule_id: str
    name: str
    description: str
    severity: RuleSeverity
    status: RuleStatus = RuleStatus.DRAFT
    mitre_techniques: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection_logic: str = ""           # Sigma/KQL/SPL query
    false_positive_notes: List[str] = field(default_factory=list)
    author: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    version: int = 1
    tags: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def rule_hash(self) -> str:
        return hashlib.sha256(
            f"{self.rule_id}:{self.detection_logic}:{self.version}".encode()
        ).hexdigest()[:16]


class DetectionRuleEngine:
    """Manages detection rule lifecycle — create, test, deploy, retire."""

    def __init__(self):
        self._lock = threading.RLock()
        self._rules: Dict[str, DetectionRule] = {}
        self._alert_counts: Dict[str, int] = {}

    def add_rule(self, rule: DetectionRule) -> str:
        with self._lock:
            self._rules[rule.rule_id] = rule
            logger.info("blue_team.rule_added: id=%s name=%s severity=%s",
                        rule.rule_id, rule.name, rule.severity.value)
            return rule.rule_id

    def activate_rule(self, rule_id: str) -> bool:
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                return False
            rule.status = RuleStatus.ACTIVE
            rule.updated_at = time.time()
            return True

    def disable_rule(self, rule_id: str) -> bool:
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                return False
            rule.status = RuleStatus.DISABLED
            rule.updated_at = time.time()
            return True

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def get_active_rules(self) -> List[DetectionRule]:
        with self._lock:
            return [r for r in self._rules.values() if r.status == RuleStatus.ACTIVE]

    def evaluate_against_event(self, event: Dict[str, Any]) -> List[str]:
        """Evaluate all active rules against an event. Returns matching rule IDs."""
        matches = []
        with self._lock:
            for rule in self._rules.values():
                if rule.status != RuleStatus.ACTIVE:
                    continue
                if self._matches_rule(rule, event):
                    matches.append(rule.rule_id)
                    self._alert_counts[rule.rule_id] = self._alert_counts.get(rule.rule_id, 0) + 1
        return matches

    @staticmethod
    def _matches_rule(rule: DetectionRule, event: Dict) -> bool:
        """Simple pattern matching (production: Sigma compiler)."""
        logic = rule.detection_logic
        if not logic:
            return False
        event_str = str(event).lower()
        # Split on AND (case-insensitive) and check all keywords present
        import re
        keywords = [kw.strip().lower() for kw in re.split(r'\bAND\b', logic, flags=re.IGNORECASE) if kw.strip()]
        return all(kw in event_str for kw in keywords)

    def coverage_by_technique(self) -> Dict[str, int]:
        """Map MITRE technique IDs to count of active detection rules."""
        coverage = {}
        with self._lock:
            for rule in self._rules.values():
                if rule.status == RuleStatus.ACTIVE:
                    for tid in rule.mitre_techniques:
                        coverage[tid] = coverage.get(tid, 0) + 1
        return coverage

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._rules)


# ─── IOC Correlation Engine ─────────────────────────────────────────────────

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"
    USER_AGENT = "user_agent"
    FILE_PATH = "file_path"
    CERTIFICATE_SHA1 = "cert_sha1"
    JA3 = "ja3"
    JA3S = "ja3s"


@dataclass
class IOCEntry:
    value: str
    ioc_type: IOCType
    source: str
    confidence: float = 0.0
    severity: RuleSeverity = RuleSeverity.MEDIUM
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    active: bool = True

    @property
    def ioc_id(self) -> str:
        return hashlib.sha256(f"{self.ioc_type.value}:{self.value}".encode()).hexdigest()[:16]


class IOCCorrelationEngine:
    """Correlate indicators across events, alerts, and threat feeds."""

    def __init__(self):
        self._lock = threading.RLock()
        self._iocs: Dict[str, IOCEntry] = {}
        self._correlations: List[Dict] = []

    def ingest(self, ioc: IOCEntry) -> str:
        with self._lock:
            existing = self._iocs.get(ioc.ioc_id)
            if existing:
                existing.last_seen = max(existing.last_seen, ioc.last_seen)
                existing.confidence = max(existing.confidence, ioc.confidence)
                if ioc.source not in existing.tags:
                    existing.tags.append(ioc.source)
            else:
                self._iocs[ioc.ioc_id] = ioc
            return ioc.ioc_id

    def search(self, value: str) -> List[IOCEntry]:
        with self._lock:
            return [e for e in self._iocs.values() if value.lower() in e.value.lower() and e.active]

    def search_by_type(self, ioc_type: IOCType) -> List[IOCEntry]:
        with self._lock:
            return [e for e in self._iocs.values() if e.ioc_type == ioc_type and e.active]

    def correlate_event(self, event: Dict[str, Any]) -> List[IOCEntry]:
        """Find IOCs matching fields in an event."""
        hits = []
        event_values = set()
        self._extract_values(event, event_values)
        with self._lock:
            for ioc in self._iocs.values():
                if not ioc.active:
                    continue
                if ioc.value in event_values:
                    hits.append(ioc)
                    self._correlations.append({
                        "ioc_id": ioc.ioc_id, "ioc_value": ioc.value,
                        "ioc_type": ioc.ioc_type.value, "timestamp": time.time(),
                    })
        return hits

    @staticmethod
    def _extract_values(obj: Any, values: Set[str], depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(obj, str):
            values.add(obj)
            values.add(obj.lower())
        elif isinstance(obj, dict):
            for v in obj.values():
                IOCCorrelationEngine._extract_values(v, values, depth + 1)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                IOCCorrelationEngine._extract_values(v, values, depth + 1)

    @property
    def ioc_count(self) -> int:
        with self._lock:
            return len(self._iocs)

    @property
    def correlation_count(self) -> int:
        with self._lock:
            return len(self._correlations)


# ─── Threat Hunt Query Framework ────────────────────────────────────────────

@dataclass
class HuntQuery:
    """Structured threat hunting query."""
    query_id: str
    name: str
    hypothesis: str
    query_text: str              # KQL, SPL, SQL
    data_sources: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    author: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class HuntResult:
    query_id: str
    hits: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    executed_at: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    success: bool = True


class ThreatHuntEngine:
    """Execute and manage threat hunting campaigns."""

    def __init__(self):
        self._lock = threading.RLock()
        self._queries: Dict[str, HuntQuery] = {}
        self._results: List[HuntResult] = []

    def register_query(self, query: HuntQuery) -> str:
        with self._lock:
            self._queries[query.query_id] = query
            return query.query_id

    def execute_hunt(self, query_id: str, data: List[Dict]) -> HuntResult:
        """Execute hunt query against provided data."""
        start = time.monotonic()
        query = self._queries.get(query_id)
        if not query:
            return HuntResult(query_id=query_id, success=False)

        # Simple keyword-based hunt (production: actual SIEM integration)
        keywords = [kw.strip().lower() for kw in query.query_text.split() if len(kw.strip()) > 2]
        findings = []
        for record in data:
            record_str = str(record).lower()
            if any(kw in record_str for kw in keywords):
                findings.append(record)

        elapsed = (time.monotonic() - start) * 1000
        result = HuntResult(
            query_id=query_id, hits=len(findings),
            findings=findings[:100], duration_ms=elapsed,
        )
        with self._lock:
            self._results.append(result)
        return result

    @property
    def query_count(self) -> int:
        with self._lock:
            return len(self._queries)

    @property
    def total_hunts(self) -> int:
        with self._lock:
            return len(self._results)


# ─── Automated Response Playbooks ───────────────────────────────────────────

class PlaybookAction(str, Enum):
    ALERT = "alert"
    CONTAIN = "contain"
    BLOCK = "block"
    ISOLATE = "isolate"
    ENRICH = "enrich"
    ESCALATE = "escalate"
    NOTIFY = "notify"
    LOG_ONLY = "log_only"


@dataclass
class PlaybookStep:
    action: PlaybookAction
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    condition: str = ""         # When to execute
    timeout_sec: int = 300


@dataclass
class ResponsePlaybook:
    playbook_id: str
    name: str
    trigger_rules: List[str]    # Detection rule IDs that trigger this
    steps: List[PlaybookStep] = field(default_factory=list)
    enabled: bool = True
    requires_approval: bool = True
    author: str = ""


class SOAREngine:
    """Lightweight SOAR — orchestrate detection → response workflows."""

    def __init__(self):
        self._lock = threading.RLock()
        self._playbooks: Dict[str, ResponsePlaybook] = {}
        self._execution_log: List[Dict] = []

    def register_playbook(self, pb: ResponsePlaybook) -> str:
        with self._lock:
            self._playbooks[pb.playbook_id] = pb
            return pb.playbook_id

    def get_triggered_playbooks(self, rule_ids: List[str]) -> List[ResponsePlaybook]:
        with self._lock:
            triggered = []
            for pb in self._playbooks.values():
                if not pb.enabled:
                    continue
                if any(rid in pb.trigger_rules for rid in rule_ids):
                    triggered.append(pb)
            return triggered

    def execute_playbook(self, playbook_id: str, context: Dict) -> List[Dict]:
        """Execute playbook steps (dry-run; real execution via SovereigntyExecutor)."""
        pb = self._playbooks.get(playbook_id)
        if not pb:
            return [{"error": "Playbook not found"}]

        results = []
        for i, step in enumerate(pb.steps):
            result = {
                "step": i, "action": step.action.value,
                "target": step.target, "status": "simulated",
                "timestamp": time.time(),
            }
            results.append(result)

        with self._lock:
            self._execution_log.append({
                "playbook_id": playbook_id, "steps": len(results),
                "context": context, "timestamp": time.time(),
            })
        return results

    @property
    def playbook_count(self) -> int:
        with self._lock:
            return len(self._playbooks)
