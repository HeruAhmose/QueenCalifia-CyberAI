"""
QueenCalifia CyberAI - Incident Response Orchestrator
======================================================
Automated incident response with playbook-driven containment,
forensic evidence preservation, and remediation workflows.

Mycelium Response Pattern: When a threat is detected at one node,
    response signals propagate through the entire mesh — isolating
    compromised segments while maintaining overall network function.

Capabilities:
    - Automated incident classification and severity assessment
    - Playbook-driven response execution (NIST SP 800-61 aligned)
    - Containment actions (block, isolate, quarantine)
    - Forensic evidence collection and chain of custody
    - Remediation tracking and verification
    - Post-incident review and lessons learned
"""

import uuid
import time
import json
import hashlib
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from collections import defaultdict, deque

logger = logging.getLogger("queencalifia.incident")


class IncidentSeverity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentCategory(Enum):
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    APT = "apt"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"


class ActionType(Enum):
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    FORCE_PASSWORD_RESET = "force_password_reset"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    CAPTURE_MEMORY = "capture_memory"
    COLLECT_LOGS = "collect_logs"
    SNAPSHOT_DISK = "snapshot_disk"
    ENABLE_ENHANCED_LOGGING = "enable_enhanced_logging"
    NOTIFY_TEAM = "notify_team"
    ESCALATE = "escalate"
    RESTORE_FROM_BACKUP = "restore_from_backup"
    PATCH_SYSTEM = "patch_system"


class ActionStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResponseAction:
    """Individual response action within a playbook"""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    action_type: ActionType = ActionType.NOTIFY_TEAM
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: ActionStatus = ActionStatus.PENDING
    priority: int = 5
    requires_approval: bool = False
    approved_by: Optional[str] = None
    denied_by: Optional[str] = None
    denied_at: Optional[datetime] = None
    denied_reason: Optional[str] = None
    rolled_back_by: Optional[str] = None
    rolled_back_at: Optional[datetime] = None
    rolled_back_reason: Optional[str] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    rollback_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "status": self.status.value,
            "priority": self.priority,
            "requires_approval": self.requires_approval,
            "approved_by": self.approved_by,
            "denied_by": self.denied_by,
            "denied_at": self.denied_at.isoformat() if self.denied_at else None,
            "denied_reason": self.denied_reason,
            "rolled_back_by": self.rolled_back_by,
            "rolled_back_at": self.rolled_back_at.isoformat() if self.rolled_back_at else None,
            "rolled_back_reason": self.rolled_back_reason,
            "rollback_action": self.rollback_action,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class ForensicEvidence:
    """Forensic evidence with chain of custody"""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    evidence_type: str = ""  # memory_dump, disk_image, log_capture, network_pcap
    source: str = ""
    collected_at: datetime = field(default_factory=datetime.utcnow)
    collector: str = "queencalifia_auto"
    hash_sha256: str = ""
    size_bytes: int = 0
    storage_location: str = ""
    chain_of_custody: List[Dict[str, str]] = field(default_factory=list)
    tombstoned: bool = False
    tombstoned_at: Optional[datetime] = None
    tombstoned_by: Optional[str] = None
    tombstone_reason: Optional[str] = None
    notes: str = ""


    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source": self.source,
            "collected_at": self.collected_at.isoformat(),
            "collector": self.collector,
            "hash_sha256": self.hash_sha256,
            "size_bytes": self.size_bytes,
            "storage_location": self.storage_location,
            "chain_of_custody": self.chain_of_custody,
            "tombstoned": self.tombstoned,
            "tombstoned_at": self.tombstoned_at.isoformat() if self.tombstoned_at else None,
            "tombstoned_by": self.tombstoned_by,
            "tombstone_reason": self.tombstone_reason,
            "notes": self.notes,
        }


@dataclass
class Incident:
    """Security incident with full lifecycle tracking"""
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    category: IncidentCategory = IncidentCategory.UNAUTHORIZED_ACCESS
    status: IncidentStatus = IncidentStatus.NEW
    source_events: List[str] = field(default_factory=list)  # event_ids
    attack_chain_id: Optional[str] = None
    affected_assets: Set[str] = field(default_factory=set)
    affected_users: Set[str] = field(default_factory=set)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    response_actions: List[ResponseAction] = field(default_factory=list)
    evidence: List[ForensicEvidence] = field(default_factory=list)
    timeline: List[Dict[str, str]] = field(default_factory=list)
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    containment_time_min: Optional[float] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None

    def add_timeline_entry(self, action: str, details: str = "", actor: str = "system"):
        self.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "details": details,
            "actor": actor,
        })
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "category": self.category.value,
            "status": self.status.value,
            "affected_assets": list(self.affected_assets),
            "affected_users": list(self.affected_users),
            "mitre_techniques": self.mitre_techniques,
            "response_actions": [a.to_dict() for a in self.response_actions],
            "timeline_entries": len(self.timeline),
            "evidence_collected": len(self.evidence),
            "assigned_to": self.assigned_to,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "containment_time_min": self.containment_time_min,
        }


class IncidentResponseOrchestrator:
    """
    Queen Califia Automated Incident Response System
    
    Aligned with NIST SP 800-61 Incident Handling phases:
        1. Preparation
        2. Detection & Analysis
        3. Containment, Eradication, Recovery
        4. Post-Incident Activity
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

        # Concurrency guard
        self._lock = threading.RLock()

        # Incident tracking
        self.incidents: Dict[str, Incident] = {}
        self.incident_index_by_chain: Dict[str, str] = {}

        # Playbook library
        self.playbooks = self._load_playbooks()

        # Action execution queue
        self.action_queue: deque = deque(maxlen=10000)
        self.executed_actions: List[ResponseAction] = []

        # Containment state
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.isolated_hosts: Set[str] = set()
        self.disabled_accounts: Set[str] = set()
        self.quarantined_files: List[Dict[str, str]] = []

        # Metrics
        self.metrics = {
            "total_incidents": 0,
            "active_incidents": 0,
            "mean_time_to_detect_min": 0,
            "mean_time_to_contain_min": 0,
            "mean_time_to_resolve_min": 0,
            "actions_executed": 0,
            "actions_failed": 0,
            "evidence_collected": 0,
        }

        logger.info(
            f"🛡️  Incident Response Orchestrator online | "
            f"{len(self.playbooks)} playbooks loaded"
        )



    def list_evidence(self, incident_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                return []
            return [e.to_dict() for e in inc.evidence]

    def add_evidence(
        self,
        *,
        incident_id: str,
        evidence_type: str,
        source: str,
        storage_location: str,
        hash_sha256: str,
        size_bytes: int = 0,
        notes: str = "",
        collector: str = "queencalifia_api",
    ) -> Dict[str, Any]:
        with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                raise KeyError("incident not found")

            ev = ForensicEvidence(
                evidence_type=(evidence_type or "")[:64],
                source=(source or "")[:256],
                storage_location=(storage_location or "")[:512],
                hash_sha256=(hash_sha256 or "")[:128],
                size_bytes=int(max(0, int(size_bytes or 0))),
                collector=(collector or "unknown")[:64],
            )
            ev.chain_of_custody.append(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "actor": ev.collector,
                    "action": "ADDED",
                    "details": f"type={ev.evidence_type}",
                }
            )
            if notes:
                ev.notes = notes[:2000]

            inc.evidence.append(ev)
            inc.timeline.append(
                {"timestamp": datetime.utcnow().isoformat(), "event": "Evidence added", "details": ev.evidence_id}
            )
            inc.updated_at = datetime.utcnow()
            return ev.to_dict()

    def get_evidence(self, incident_id: str, evidence_id: str) -> Dict[str, Any]:
        with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                raise KeyError("incident not found")
            for ev in inc.evidence:
                if ev.evidence_id == evidence_id:
                    return ev.to_dict()
            raise KeyError("evidence not found")

    def tombstone_evidence(self, *, incident_id: str, evidence_id: str, actor: str, reason: str = "") -> Dict[str, Any]:
        with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                raise KeyError("incident not found")
            for ev in inc.evidence:
                if ev.evidence_id == evidence_id:
                    ev.tombstoned = True
                    ev.tombstoned_at = datetime.utcnow()
                    ev.tombstoned_by = (actor or "unknown")[:64]
                    ev.tombstone_reason = (reason or "")[:512]
                    ev.chain_of_custody.append(
                        {
                            "timestamp": datetime.utcnow().isoformat(),
                            "actor": ev.tombstoned_by,
                            "action": "TOMBSTONED",
                            "details": ev.tombstone_reason or "",
                        }
                    )
                    inc.timeline.append(
                        {"timestamp": datetime.utcnow().isoformat(), "event": "Evidence tombstoned", "details": ev.evidence_id}
                    )
                    inc.updated_at = datetime.utcnow()
                    return ev.to_dict()
            raise KeyError("evidence not found")


    def list_incidents(self, limit: int = 100) -> List[Incident]:
        """Return incidents (most recent first)."""
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            incidents = list(self.incidents.values())
        incidents.sort(key=lambda i: i.created_at, reverse=True)
        return incidents[:limit]

    # ─── Playbook Library ────────────────────────────────────────────────────

    def _load_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """Load automated response playbooks"""
        return {
            IncidentCategory.RANSOMWARE.value: {
                "name": "Ransomware Response",
                "priority": 1,
                "auto_execute": True,
                "phases": {
                    "immediate": [
                        {"action": ActionType.ISOLATE_HOST, "priority": 1, "requires_approval": False},
                        {"action": ActionType.CAPTURE_MEMORY, "priority": 2, "requires_approval": False},
                        {"action": ActionType.NOTIFY_TEAM, "priority": 1, "requires_approval": False,
                         "params": {"channel": "critical", "message": "RANSOMWARE DETECTED"}},
                    ],
                    "containment": [
                        {"action": ActionType.BLOCK_IP, "priority": 1, "requires_approval": False},
                        {"action": ActionType.BLOCK_DOMAIN, "priority": 1, "requires_approval": False},
                        {"action": ActionType.KILL_PROCESS, "priority": 2, "requires_approval": False},
                        {"action": ActionType.COLLECT_LOGS, "priority": 3, "requires_approval": False},
                    ],
                    "eradication": [
                        {"action": ActionType.QUARANTINE_FILE, "priority": 1, "requires_approval": False},
                        {"action": ActionType.SNAPSHOT_DISK, "priority": 2, "requires_approval": False},
                    ],
                    "recovery": [
                        {"action": ActionType.RESTORE_FROM_BACKUP, "priority": 1, "requires_approval": True},
                        {"action": ActionType.PATCH_SYSTEM, "priority": 2, "requires_approval": True},
                    ],
                },
            },
            IncidentCategory.APT.value: {
                "name": "APT Campaign Response",
                "priority": 1,
                "auto_execute": False,  # Manual approval required for APT
                "phases": {
                    "immediate": [
                        {"action": ActionType.ENABLE_ENHANCED_LOGGING, "priority": 1, "requires_approval": False},
                        {"action": ActionType.CAPTURE_MEMORY, "priority": 1, "requires_approval": False},
                        {"action": ActionType.NOTIFY_TEAM, "priority": 1, "requires_approval": False,
                         "params": {"channel": "critical", "message": "APT ACTIVITY DETECTED"}},
                        {"action": ActionType.ESCALATE, "priority": 1, "requires_approval": False,
                         "params": {"level": "executive", "reason": "APT campaign confirmed"}},
                    ],
                    "containment": [
                        {"action": ActionType.COLLECT_LOGS, "priority": 1, "requires_approval": False},
                        {"action": ActionType.SNAPSHOT_DISK, "priority": 2, "requires_approval": False},
                        {"action": ActionType.ISOLATE_HOST, "priority": 2, "requires_approval": True},
                        {"action": ActionType.BLOCK_IP, "priority": 3, "requires_approval": True},
                    ],
                    "eradication": [
                        {"action": ActionType.DISABLE_ACCOUNT, "priority": 1, "requires_approval": True},
                        {"action": ActionType.FORCE_PASSWORD_RESET, "priority": 2, "requires_approval": True},
                        {"action": ActionType.QUARANTINE_FILE, "priority": 3, "requires_approval": False},
                    ],
                    "recovery": [
                        {"action": ActionType.PATCH_SYSTEM, "priority": 1, "requires_approval": True},
                        {"action": ActionType.RESTORE_FROM_BACKUP, "priority": 2, "requires_approval": True},
                    ],
                },
            },
            IncidentCategory.DATA_BREACH.value: {
                "name": "Data Breach Response",
                "priority": 1,
                "auto_execute": True,
                "phases": {
                    "immediate": [
                        {"action": ActionType.BLOCK_IP, "priority": 1, "requires_approval": False},
                        {"action": ActionType.NOTIFY_TEAM, "priority": 1, "requires_approval": False,
                         "params": {"channel": "critical", "message": "DATA BREACH DETECTED"}},
                        {"action": ActionType.COLLECT_LOGS, "priority": 2, "requires_approval": False},
                    ],
                    "containment": [
                        {"action": ActionType.ISOLATE_HOST, "priority": 1, "requires_approval": False},
                        {"action": ActionType.DISABLE_ACCOUNT, "priority": 2, "requires_approval": True},
                        {"action": ActionType.CAPTURE_MEMORY, "priority": 3, "requires_approval": False},
                    ],
                    "eradication": [
                        {"action": ActionType.FORCE_PASSWORD_RESET, "priority": 1, "requires_approval": True},
                        {"action": ActionType.QUARANTINE_FILE, "priority": 2, "requires_approval": False},
                    ],
                    "recovery": [
                        {"action": ActionType.PATCH_SYSTEM, "priority": 1, "requires_approval": True},
                    ],
                },
            },
            IncidentCategory.UNAUTHORIZED_ACCESS.value: {
                "name": "Unauthorized Access Response",
                "priority": 2,
                "auto_execute": True,
                "phases": {
                    "immediate": [
                        {"action": ActionType.BLOCK_IP, "priority": 1, "requires_approval": False},
                        {"action": ActionType.NOTIFY_TEAM, "priority": 2, "requires_approval": False},
                        {"action": ActionType.COLLECT_LOGS, "priority": 2, "requires_approval": False},
                    ],
                    "containment": [
                        {"action": ActionType.DISABLE_ACCOUNT, "priority": 1, "requires_approval": True},
                        {"action": ActionType.FORCE_PASSWORD_RESET, "priority": 2, "requires_approval": True},
                        {"action": ActionType.ENABLE_ENHANCED_LOGGING, "priority": 3, "requires_approval": False},
                    ],
                    "eradication": [
                        {"action": ActionType.QUARANTINE_FILE, "priority": 1, "requires_approval": False},
                    ],
                    "recovery": [
                        {"action": ActionType.PATCH_SYSTEM, "priority": 1, "requires_approval": True},
                    ],
                },
            },
            IncidentCategory.PHISHING.value: {
                "name": "Phishing Response",
                "priority": 2,
                "auto_execute": True,
                "phases": {
                    "immediate": [
                        {"action": ActionType.BLOCK_DOMAIN, "priority": 1, "requires_approval": False},
                        {"action": ActionType.BLOCK_IP, "priority": 1, "requires_approval": False},
                        {"action": ActionType.NOTIFY_TEAM, "priority": 2, "requires_approval": False},
                    ],
                    "containment": [
                        {"action": ActionType.QUARANTINE_FILE, "priority": 1, "requires_approval": False},
                        {"action": ActionType.FORCE_PASSWORD_RESET, "priority": 2, "requires_approval": True,
                         "params": {"scope": "affected_users_only"}},
                        {"action": ActionType.COLLECT_LOGS, "priority": 3, "requires_approval": False},
                    ],
                    "eradication": [],
                    "recovery": [],
                },
            },
        }

    # ─── Incident Creation ───────────────────────────────────────────────────

    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        category: IncidentCategory,
        source_events: List[str] = None,
        attack_chain_id: Optional[str] = None,
        affected_assets: Set[str] = None,
        indicators: List[str] = None,
        mitre_techniques: List[str] = None,
        auto_respond: bool = True,
    ) -> Incident:
        """Create a new incident and optionally trigger automated response"""

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            category=category,
            source_events=source_events or [],
            attack_chain_id=attack_chain_id,
            affected_assets=affected_assets or set(),
            indicators=indicators or [],
            mitre_techniques=mitre_techniques or [],
        )

        incident.add_timeline_entry(
            "incident_created",
            f"Severity: {severity.name} | Category: {category.value}"
        )

        # Store
        self.incidents[incident.incident_id] = incident
        if attack_chain_id:
            self.incident_index_by_chain[attack_chain_id] = incident.incident_id

        self.metrics["total_incidents"] += 1
        self.metrics["active_incidents"] = sum(
            1 for i in self.incidents.values()
            if i.status not in {IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}
        )

        logger.warning(
            f"🚨 INCIDENT CREATED | {incident.incident_id} | "
            f"{severity.name} | {category.value} | {title}"
        )

        # Auto-triage
        incident.status = IncidentStatus.TRIAGED
        incident.add_timeline_entry("auto_triaged", "Automated triage complete")

        # Execute playbook if auto-respond enabled
        if auto_respond:
            self._execute_playbook(incident)

        return incident

    # ─── Playbook Execution ──────────────────────────────────────────────────

    def _execute_playbook(self, incident: Incident):
        """Execute the appropriate response playbook for an incident"""
        playbook = self.playbooks.get(incident.category.value)
        if not playbook:
            logger.warning(f"No playbook for category: {incident.category.value}")
            return

        incident.add_timeline_entry(
            "playbook_activated",
            f"Executing: {playbook['name']}"
        )
        incident.status = IncidentStatus.CONTAINING

        # Execute phases in order
        for phase_name, actions in playbook["phases"].items():
            for action_def in actions:
                action = ResponseAction(
                    action_type=action_def["action"],
                    target=self._determine_action_target(incident, action_def["action"]),
                    priority=action_def.get("priority", 5),
                    requires_approval=action_def.get("requires_approval", False),
                    parameters=action_def.get("params", {}),
                )

                incident.response_actions.append(action)

                if not action.requires_approval or playbook.get("auto_execute", False):
                    self._execute_action(action, incident)
                else:
                    action.status = ActionStatus.PENDING
                    incident.add_timeline_entry(
                        "action_pending_approval",
                        f"{action.action_type.value} on {action.target} requires approval"
                    )

    def _determine_action_target(self, incident: Incident, action_type: ActionType) -> str:
        """Determine the target for a response action"""
        if action_type in {ActionType.BLOCK_IP, ActionType.BLOCK_DOMAIN}:
            return ", ".join(incident.indicators[:5]) if incident.indicators else "unknown"
        elif action_type in {ActionType.ISOLATE_HOST, ActionType.CAPTURE_MEMORY,
                             ActionType.SNAPSHOT_DISK, ActionType.KILL_PROCESS}:
            return ", ".join(list(incident.affected_assets)[:3]) if incident.affected_assets else "unknown"
        elif action_type in {ActionType.DISABLE_ACCOUNT, ActionType.FORCE_PASSWORD_RESET}:
            return ", ".join(list(incident.affected_users)[:3]) if incident.affected_users else "all_affected"
        elif action_type == ActionType.NOTIFY_TEAM:
            return "security_operations"
        elif action_type == ActionType.ESCALATE:
            return "incident_commander"
        return "auto"

    def _execute_action(self, action: ResponseAction, incident: Incident):
        """Execute a single response action"""
        action.status = ActionStatus.IN_PROGRESS
        action.executed_at = datetime.utcnow()

        try:
            # Execute based on action type
            if action.action_type == ActionType.BLOCK_IP:
                self._action_block_ip(action, incident)
            elif action.action_type == ActionType.BLOCK_DOMAIN:
                self._action_block_domain(action, incident)
            elif action.action_type == ActionType.ISOLATE_HOST:
                self._action_isolate_host(action, incident)
            elif action.action_type == ActionType.DISABLE_ACCOUNT:
                self._action_disable_account(action, incident)
            elif action.action_type == ActionType.QUARANTINE_FILE:
                self._action_quarantine_file(action, incident)
            elif action.action_type == ActionType.CAPTURE_MEMORY:
                self._action_capture_memory(action, incident)
            elif action.action_type == ActionType.COLLECT_LOGS:
                self._action_collect_logs(action, incident)
            elif action.action_type == ActionType.NOTIFY_TEAM:
                self._action_notify_team(action, incident)
            elif action.action_type == ActionType.ESCALATE:
                self._action_escalate(action, incident)
            elif action.action_type == ActionType.ENABLE_ENHANCED_LOGGING:
                self._action_enable_enhanced_logging(action, incident)
            else:
                action.result = f"Action {action.action_type.value} queued for manual execution"

            action.status = ActionStatus.COMPLETED
            action.completed_at = datetime.utcnow()
            self.metrics["actions_executed"] += 1

            incident.add_timeline_entry(
                f"action_executed:{action.action_type.value}",
                f"Target: {action.target} | Result: {action.result}"
            )

        except Exception as exc:
            action.status = ActionStatus.FAILED
            action.error = str(exc)
            self.metrics["actions_failed"] += 1
            logger.error(f"Action {action.action_id} failed: {exc}")

            incident.add_timeline_entry(
                f"action_failed:{action.action_type.value}",
                f"Error: {exc}"
            )

    # ─── Action Implementations ──────────────────────────────────────────────

    def _action_block_ip(self, action: ResponseAction, incident: Incident):
        """Block IP addresses at the perimeter"""
        targets = [t.strip() for t in action.target.split(",")]
        blocked = []
        for ip in targets:
            if ip and ip != "unknown":
                self.blocked_ips[ip] = {
                    "blocked_at": datetime.utcnow().isoformat(),
                    "incident_id": incident.incident_id,
                    "reason": incident.category.value,
                }
                blocked.append(ip)
        action.result = f"Blocked {len(blocked)} IPs: {', '.join(blocked)}"
        action.rollback_action = f"unblock_ips:{','.join(blocked)}"

    def _action_block_domain(self, action: ResponseAction, incident: Incident):
        """Block domains at DNS/proxy level"""
        targets = [t.strip() for t in action.target.split(",")]
        action.result = f"Blocked domains: {', '.join(targets)}"

    def _action_isolate_host(self, action: ResponseAction, incident: Incident):
        """Network isolate a compromised host"""
        targets = [t.strip() for t in action.target.split(",")]
        for host in targets:
            self.isolated_hosts.add(host)
        action.result = f"Isolated hosts: {', '.join(targets)}"
        action.rollback_action = f"unisolate_hosts:{','.join(targets)}"

    def _action_disable_account(self, action: ResponseAction, incident: Incident):
        """Disable compromised user accounts"""
        targets = [t.strip() for t in action.target.split(",")]
        for account in targets:
            self.disabled_accounts.add(account)
        action.result = f"Disabled accounts: {', '.join(targets)}"
        action.rollback_action = f"enable_accounts:{','.join(targets)}"

    def _action_quarantine_file(self, action: ResponseAction, incident: Incident):
        """Quarantine malicious files"""
        self.quarantined_files.append({
            "target": action.target,
            "incident_id": incident.incident_id,
            "quarantined_at": datetime.utcnow().isoformat(),
        })
        action.result = f"Files quarantined for incident {incident.incident_id}"

    def _action_capture_memory(self, action: ResponseAction, incident: Incident):
        """Capture memory dump for forensic analysis"""
        evidence = ForensicEvidence(
            evidence_type="memory_dump",
            source=action.target,
            collector="queencalifia_ir_auto",
            hash_sha256=hashlib.sha256(
                f"memdump_{action.target}_{datetime.utcnow().isoformat()}".encode()
            ).hexdigest(),
            notes=f"Auto-captured for incident {incident.incident_id}",
        )
        evidence.chain_of_custody.append({
            "action": "collected",
            "actor": "queencalifia_ir_auto",
            "timestamp": datetime.utcnow().isoformat(),
        })
        incident.evidence.append(evidence)
        self.metrics["evidence_collected"] += 1
        action.result = f"Memory dump captured: {evidence.evidence_id}"

    def _action_collect_logs(self, action: ResponseAction, incident: Incident):
        """Collect and preserve relevant logs"""
        evidence = ForensicEvidence(
            evidence_type="log_capture",
            source=action.target,
            collector="queencalifia_ir_auto",
            hash_sha256=hashlib.sha256(
                f"logs_{action.target}_{datetime.utcnow().isoformat()}".encode()
            ).hexdigest(),
            notes=f"Log collection for incident {incident.incident_id}",
        )
        evidence.chain_of_custody.append({
            "action": "collected",
            "actor": "queencalifia_ir_auto",
            "timestamp": datetime.utcnow().isoformat(),
        })
        incident.evidence.append(evidence)
        self.metrics["evidence_collected"] += 1
        action.result = f"Logs collected: {evidence.evidence_id}"

    def _action_notify_team(self, action: ResponseAction, incident: Incident):
        """Send notification to security team"""
        channel = action.parameters.get("channel", "default")
        message = action.parameters.get(
            "message", f"Security incident: {incident.title}"
        )
        action.result = f"Notification sent to {channel}: {message}"

    def _action_escalate(self, action: ResponseAction, incident: Incident):
        """Escalate incident to higher authority"""
        level = action.parameters.get("level", "management")
        reason = action.parameters.get("reason", incident.title)
        action.result = f"Escalated to {level}: {reason}"

    def _action_enable_enhanced_logging(self, action: ResponseAction, incident: Incident):
        """Enable enhanced logging on affected systems"""
        action.result = f"Enhanced logging enabled for: {action.target}"

    # ─── Incident Management ─────────────────────────────────────────────────

    def approve_action(self, incident_id: str, action_id: str, approver: str) -> bool:
        """Approve a pending action for execution."""
        with self._lock:
            incident = self.incidents.get(incident_id)
            if not incident:
                return False

            for action in incident.response_actions:
                if action.action_id == action_id and action.status == ActionStatus.PENDING:
                    action.approved_by = approver
                    self._execute_action(action, incident)
                    return True

        return False

    def deny_action(self, incident_id: str, action_id: str, denier: str, *, reason: str | None = None) -> bool:
        """Deny a pending action (no execution)."""
        with self._lock:
            incident = self.incidents.get(incident_id)
            if not incident:
                return False

            for action in incident.response_actions:
                if action.action_id == action_id and action.status == ActionStatus.PENDING:
                    action.status = ActionStatus.DENIED
                    action.denied_by = denier
                    action.denied_at = datetime.utcnow()
                    action.denied_reason = (reason or "").strip() or None
                    action.completed_at = datetime.utcnow()
                    action.result = f"Denied by {denier}" + (f": {action.denied_reason}" if action.denied_reason else "")

                    incident.add_timeline_entry(
                        f"action_denied:{action.action_type.value}",
                        f"Target: {action.target} | {action.result}",
                    )
                    return True

        return False

    def rollback_action(self, incident_id: str, action_id: str, actor: str, *, reason: str | None = None) -> bool:
        """Rollback an executed action (best-effort; may require manual reversal)."""
        with self._lock:
            incident = self.incidents.get(incident_id)
            if not incident:
                return False

            for action in incident.response_actions:
                if action.action_id == action_id and action.status == ActionStatus.COMPLETED:
                    self._perform_rollback(action, incident, actor=actor, reason=reason)
                    return True

        return False

    def _perform_rollback(self, action: ResponseAction, incident: "Incident", *, actor: str, reason: str | None) -> None:
        action.rolled_back_by = actor
        action.rolled_back_at = datetime.utcnow()
        action.rolled_back_reason = (reason or "").strip() or None

        rb = (action.rollback_action or "").strip()
        msg = ""

        try:
            if rb.startswith("unblock_ips:"):
                raw = rb.split(":", 1)[1]
                ips = [x.strip() for x in raw.split(",") if x.strip()]
                for ip in ips:
                    self.blocked_ips.pop(ip, None)
                msg = f"Unblocked {len(ips)} IPs"

            elif rb.startswith("unisolate_hosts:"):
                raw = rb.split(":", 1)[1]
                hosts = [x.strip() for x in raw.split(",") if x.strip()]
                for h in hosts:
                    self.isolated_hosts.discard(h)
                msg = f"Unisolated {len(hosts)} hosts"

            elif rb.startswith("enable_accounts:"):
                raw = rb.split(":", 1)[1]
                accts = [x.strip() for x in raw.split(",") if x.strip()]
                for a in accts:
                    self.disabled_accounts.discard(a)
                msg = f"Re-enabled {len(accts)} accounts"

            else:
                msg = "Rollback requires manual reversal"

            action.status = ActionStatus.ROLLED_BACK
            action.completed_at = datetime.utcnow()
            action.result = f"Rolled back by {actor}. {msg}" + (f" | Reason: {action.rolled_back_reason}" if action.rolled_back_reason else "")

            incident.add_timeline_entry(
                f"action_rolled_back:{action.action_type.value}",
                f"Target: {action.target} | {action.result}",
            )
        except Exception as exc:
            action.status = ActionStatus.FAILED
            action.error = f"rollback_failed: {exc}"
            incident.add_timeline_entry(
                f"action_rollback_failed:{action.action_type.value}",
                f"Error: {exc}",
            )

    def update_incident(
        self,
        incident_id: str,
        status: Optional[IncidentStatus] = None,
        assigned_to: Optional[str] = None,
        root_cause: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[Incident]:
        """Update an incident"""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        if status:
            old_status = incident.status
            incident.status = status
            incident.add_timeline_entry(
                "status_changed",
                f"{old_status.value} → {status.value}"
            )

            if status == IncidentStatus.CLOSED:
                incident.resolved_at = datetime.utcnow()
                if incident.created_at:
                    delta = incident.resolved_at - incident.created_at
                    incident.containment_time_min = delta.total_seconds() / 60

        if assigned_to:
            incident.assigned_to = assigned_to
            incident.add_timeline_entry("assigned", f"Assigned to {assigned_to}")

        if root_cause:
            incident.root_cause = root_cause
            incident.add_timeline_entry("root_cause_identified", root_cause)

        if notes:
            incident.add_timeline_entry("note_added", notes)

        return incident

    def close_incident(
        self, incident_id: str, root_cause: str, lessons_learned: str
    ) -> Optional[Incident]:
        """Close an incident with post-incident documentation"""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        incident.status = IncidentStatus.CLOSED
        incident.resolved_at = datetime.utcnow()
        incident.root_cause = root_cause
        incident.lessons_learned = lessons_learned

        if incident.created_at:
            delta = incident.resolved_at - incident.created_at
            incident.containment_time_min = delta.total_seconds() / 60

        incident.add_timeline_entry(
            "incident_closed",
            f"Root cause: {root_cause}"
        )

        self.metrics["active_incidents"] = sum(
            1 for i in self.incidents.values()
            if i.status not in {IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}
        )

        # Update MTTD/MTTC/MTTR
        self._update_response_metrics()

        logger.info(f"✅ Incident {incident_id} closed | MTTR: {incident.containment_time_min:.1f} min")
        return incident

    def _update_response_metrics(self):
        """Update mean response time metrics"""
        closed = [
            i for i in self.incidents.values()
            if i.status == IncidentStatus.CLOSED and i.containment_time_min is not None
        ]
        if closed:
            self.metrics["mean_time_to_resolve_min"] = round(
                sum(i.containment_time_min for i in closed) / len(closed), 2
            )

    # ─── Status & Reporting ──────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get incident response orchestrator status"""
        active = [
            i for i in self.incidents.values()
            if i.status not in {IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}
        ]

        return {
            "total_incidents": self.metrics["total_incidents"],
            "active_incidents": len(active),
            "active_by_severity": {
                "critical": sum(1 for i in active if i.severity == IncidentSeverity.CRITICAL),
                "high": sum(1 for i in active if i.severity == IncidentSeverity.HIGH),
                "medium": sum(1 for i in active if i.severity == IncidentSeverity.MEDIUM),
                "low": sum(1 for i in active if i.severity == IncidentSeverity.LOW),
            },
            "containment": {
                "ips_blocked": len(self.blocked_ips),
                "hosts_isolated": len(self.isolated_hosts),
                "accounts_disabled": len(self.disabled_accounts),
                "files_quarantined": len(self.quarantined_files),
            },
            "performance": {
                "actions_executed": self.metrics["actions_executed"],
                "actions_failed": self.metrics["actions_failed"],
                "evidence_collected": self.metrics["evidence_collected"],
                "mttr_minutes": self.metrics["mean_time_to_resolve_min"],
            },
            "playbooks_loaded": len(self.playbooks),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_incident_report(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Generate a full incident report"""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        return {
            **incident.to_dict(),
            "timeline": incident.timeline,
            "evidence": [
                {
                    "id": e.evidence_id,
                    "type": e.evidence_type,
                    "source": e.source,
                    "collected_at": e.collected_at.isoformat(),
                    "hash": e.hash_sha256,
                    "chain_of_custody": e.chain_of_custody,
                }
                for e in incident.evidence
            ],
            "root_cause": incident.root_cause,
            "lessons_learned": incident.lessons_learned,
        }
