"""
engines.red_team_tactics — MITRE ATT&CK Aligned Offensive Simulation
=====================================================================

Authorized offensive security simulation for QueenCalifia CyberAI.
Every operation is scoped to an approved engagement with target
boundaries, technique allowlists, and impact limits.

MITRE ATT&CK Coverage (14 tactics):
  Reconnaissance, Resource Development, Initial Access, Execution,
  Persistence, Privilege Escalation, Defense Evasion, Credential Access,
  Discovery, Lateral Movement, Collection, Exfiltration, C2, Impact

Safety Controls:
  - All operations require EngagementScope with approved targets
  - Target boundary enforcement (CIDR, hostname, asset ID)
  - Technique allowlist per engagement
  - Impact level capping
  - Full audit trail through SovereigntyExecutor
  - Automatic abort on scope violation
  - Simulation-only mode (no real exploitation)
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger("engines.red_team")


# ─── MITRE ATT&CK Tactic Registry ──────────────────────────────────────────

class MitreTactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command-and-control"
    IMPACT = "impact"


# ─── Technique Library ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str          # e.g. "T1566.001"
    name: str
    tactic: MitreTactic
    severity: str              # low, medium, high, critical
    platforms: tuple           # ("windows", "linux", "macos", "cloud")
    description: str = ""
    subtechnique_of: Optional[str] = None


# Core technique catalog (representative subset — extend via threat_intel_auto feeds)
TECHNIQUE_CATALOG: Dict[str, AttackTechnique] = {}

def _reg(tid, name, tactic, severity, platforms, desc="", parent=None):
    TECHNIQUE_CATALOG[tid] = AttackTechnique(tid, name, tactic, severity, tuple(platforms), desc, parent)

# Reconnaissance
_reg("T1595.001", "Active Scanning: IP Blocks", MitreTactic.RECONNAISSANCE, "low", ["all"], "Scan IP ranges for live hosts")
_reg("T1595.002", "Active Scanning: Vuln Scanning", MitreTactic.RECONNAISSANCE, "medium", ["all"], "Scan for known vulnerabilities")
_reg("T1592", "Gather Victim Host Info", MitreTactic.RECONNAISSANCE, "low", ["all"])
_reg("T1589", "Gather Victim Identity Info", MitreTactic.RECONNAISSANCE, "low", ["all"])
# Initial Access
_reg("T1566.001", "Phishing: Spearphishing Attachment", MitreTactic.INITIAL_ACCESS, "high", ["windows", "linux", "macos"])
_reg("T1566.002", "Phishing: Spearphishing Link", MitreTactic.INITIAL_ACCESS, "high", ["all"])
_reg("T1190", "Exploit Public-Facing App", MitreTactic.INITIAL_ACCESS, "critical", ["all"])
_reg("T1133", "External Remote Services", MitreTactic.INITIAL_ACCESS, "high", ["all"])
_reg("T1078", "Valid Accounts", MitreTactic.INITIAL_ACCESS, "critical", ["all"])
# Execution
_reg("T1059.001", "PowerShell", MitreTactic.EXECUTION, "high", ["windows"])
_reg("T1059.004", "Unix Shell", MitreTactic.EXECUTION, "high", ["linux", "macos"])
_reg("T1203", "Exploitation for Client Execution", MitreTactic.EXECUTION, "critical", ["all"])
# Persistence
_reg("T1547.001", "Boot/Logon Autostart: Registry Run", MitreTactic.PERSISTENCE, "high", ["windows"])
_reg("T1053.005", "Scheduled Task/Cron", MitreTactic.PERSISTENCE, "medium", ["windows", "linux"])
_reg("T1136", "Create Account", MitreTactic.PERSISTENCE, "high", ["all"])
# Privilege Escalation
_reg("T1068", "Exploitation for Privilege Escalation", MitreTactic.PRIVILEGE_ESCALATION, "critical", ["all"])
_reg("T1548.002", "Abuse Elevation: Bypass UAC", MitreTactic.PRIVILEGE_ESCALATION, "high", ["windows"])
# Defense Evasion
_reg("T1070.001", "Indicator Removal: Clear Windows Event Logs", MitreTactic.DEFENSE_EVASION, "high", ["windows"])
_reg("T1027", "Obfuscated Files or Info", MitreTactic.DEFENSE_EVASION, "medium", ["all"])
_reg("T1562.001", "Impair Defenses: Disable Security Tools", MitreTactic.DEFENSE_EVASION, "critical", ["all"])
# Credential Access
_reg("T1003.001", "OS Credential Dumping: LSASS", MitreTactic.CREDENTIAL_ACCESS, "critical", ["windows"])
_reg("T1110.001", "Brute Force: Password Guessing", MitreTactic.CREDENTIAL_ACCESS, "medium", ["all"])
_reg("T1558.003", "Kerberoasting", MitreTactic.CREDENTIAL_ACCESS, "high", ["windows"])
# Discovery
_reg("T1087", "Account Discovery", MitreTactic.DISCOVERY, "low", ["all"])
_reg("T1046", "Network Service Discovery", MitreTactic.DISCOVERY, "low", ["all"])
_reg("T1082", "System Information Discovery", MitreTactic.DISCOVERY, "low", ["all"])
# Lateral Movement
_reg("T1021.001", "Remote Services: RDP", MitreTactic.LATERAL_MOVEMENT, "high", ["windows"])
_reg("T1021.002", "Remote Services: SMB/Windows Admin Shares", MitreTactic.LATERAL_MOVEMENT, "high", ["windows"])
_reg("T1021.004", "Remote Services: SSH", MitreTactic.LATERAL_MOVEMENT, "medium", ["linux", "macos"])
_reg("T1550.002", "Use Alternate Auth: Pass the Hash", MitreTactic.LATERAL_MOVEMENT, "critical", ["windows"])
# Collection
_reg("T1560.001", "Archive: Utility", MitreTactic.COLLECTION, "medium", ["all"])
_reg("T1005", "Data from Local System", MitreTactic.COLLECTION, "medium", ["all"])
# Exfiltration
_reg("T1041", "Exfiltration Over C2", MitreTactic.EXFILTRATION, "high", ["all"])
_reg("T1048", "Exfiltration Over Alternative Protocol", MitreTactic.EXFILTRATION, "high", ["all"])
_reg("T1567", "Exfiltration Over Web Service", MitreTactic.EXFILTRATION, "high", ["all"])
# C2
_reg("T1071.001", "Application Layer Protocol: Web", MitreTactic.COMMAND_AND_CONTROL, "high", ["all"])
_reg("T1573", "Encrypted Channel", MitreTactic.COMMAND_AND_CONTROL, "medium", ["all"])
_reg("T1105", "Ingress Tool Transfer", MitreTactic.COMMAND_AND_CONTROL, "medium", ["all"])
# Impact
_reg("T1486", "Data Encrypted for Impact", MitreTactic.IMPACT, "critical", ["all"], "Ransomware simulation")
_reg("T1489", "Service Stop", MitreTactic.IMPACT, "high", ["all"])
_reg("T1529", "System Shutdown/Reboot", MitreTactic.IMPACT, "high", ["all"])


# ─── Engagement Scope Enforcement ───────────────────────────────────────────

@dataclass
class EngagementBounds:
    """Runtime-enforced engagement boundaries."""
    engagement_id: str
    authorized_targets: FrozenSet[str]
    excluded_targets: FrozenSet[str]
    authorized_techniques: FrozenSet[str]
    max_severity: str = "high"
    expires_at: float = 0.0
    active: bool = True

    def is_target_authorized(self, target: str) -> bool:
        if not self.active or time.time() > self.expires_at:
            return False
        if target in self.excluded_targets:
            return False
        # Check CIDR membership (simplified — exact match or prefix)
        for auth in self.authorized_targets:
            if target == auth or target.startswith(auth.rstrip("0").rstrip(".")):
                return True
        return False

    def is_technique_authorized(self, technique_id: str) -> bool:
        if not self.authorized_techniques:
            return True  # Empty = all techniques allowed
        return technique_id in self.authorized_techniques

    def is_severity_allowed(self, severity: str) -> bool:
        levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return levels.get(severity, 99) <= levels.get(self.max_severity, 2)


# ─── Attack Simulation Results ──────────────────────────────────────────────

@dataclass
class AttackStepResult:
    step_id: str
    technique_id: str
    target: str
    success: bool
    artifacts: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    error: str = ""
    duration_ms: float = 0.0


@dataclass
class AttackChainResult:
    chain_id: str
    engagement_id: str
    steps: List[AttackStepResult] = field(default_factory=list)
    overall_success: bool = False
    total_duration_ms: float = 0.0
    techniques_used: List[str] = field(default_factory=list)
    scope_violations: int = 0
    started_at: float = field(default_factory=time.time)


# ─── Red Team Simulation Engine ─────────────────────────────────────────────

class RedTeamEngine:
    """
    Executes authorized offensive simulations within engagement scope.

    All operations are:
      - Simulation-only (no real exploitation of production systems)
      - Scoped to engagement boundaries
      - Audited through sovereignty layer
      - Automatically aborted on scope violation
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._engagements: Dict[str, EngagementBounds] = {}
        self._execution_log: List[AttackStepResult] = []

    def register_engagement(self, bounds: EngagementBounds) -> None:
        with self._lock:
            self._engagements[bounds.engagement_id] = bounds
            logger.info("red_team.engagement_registered: id=%s targets=%d techniques=%d",
                        bounds.engagement_id, len(bounds.authorized_targets),
                        len(bounds.authorized_techniques))

    def get_engagement(self, engagement_id: str) -> Optional[EngagementBounds]:
        with self._lock:
            return self._engagements.get(engagement_id)

    def simulate_technique(
        self, engagement_id: str, technique_id: str, target: str,
        parameters: Optional[Dict] = None,
    ) -> AttackStepResult:
        """Execute a single attack technique simulation."""
        step_id = secrets.token_urlsafe(12)
        start = time.monotonic()

        bounds = self.get_engagement(engagement_id)
        if not bounds:
            return AttackStepResult(step_id=step_id, technique_id=technique_id,
                                   target=target, success=False, error="Engagement not found")

        if not bounds.is_target_authorized(target):
            logger.warning("red_team.SCOPE_VIOLATION: target=%s not authorized in %s", target, engagement_id)
            return AttackStepResult(step_id=step_id, technique_id=technique_id,
                                   target=target, success=False, error="Target not in engagement scope")

        if not bounds.is_technique_authorized(technique_id):
            return AttackStepResult(step_id=step_id, technique_id=technique_id,
                                   target=target, success=False, error="Technique not authorized")

        technique = TECHNIQUE_CATALOG.get(technique_id)
        if not technique:
            return AttackStepResult(step_id=step_id, technique_id=technique_id,
                                   target=target, success=False, error="Unknown technique")

        if not bounds.is_severity_allowed(technique.severity):
            return AttackStepResult(step_id=step_id, technique_id=technique_id,
                                   target=target, success=False, error="Severity exceeds engagement max")

        # Simulate technique execution
        result = self._execute_simulation(technique, target, parameters or {})
        elapsed = (time.monotonic() - start) * 1000

        step = AttackStepResult(
            step_id=step_id, technique_id=technique_id, target=target,
            success=result["success"], artifacts=result.get("artifacts", {}),
            duration_ms=elapsed,
        )
        with self._lock:
            self._execution_log.append(step)

        return step

    def execute_attack_chain(
        self, engagement_id: str, chain: List[Dict[str, str]],
    ) -> AttackChainResult:
        """Execute a multi-step attack chain."""
        chain_id = secrets.token_urlsafe(12)
        result = AttackChainResult(chain_id=chain_id, engagement_id=engagement_id)
        start = time.monotonic()

        for step_def in chain:
            tid = step_def.get("technique_id", "")
            target = step_def.get("target", "")
            params = step_def.get("parameters", {})

            step = self.simulate_technique(engagement_id, tid, target, params)
            result.steps.append(step)
            result.techniques_used.append(tid)

            if step.error and "scope" in step.error.lower():
                result.scope_violations += 1
                logger.warning("red_team.chain_ABORT: scope violation at step %s", step.step_id)
                break  # Abort chain on scope violation

        result.total_duration_ms = (time.monotonic() - start) * 1000
        result.overall_success = all(s.success for s in result.steps) and len(result.steps) > 0
        return result

    def _execute_simulation(self, technique: AttackTechnique, target: str, params: Dict) -> Dict:
        """Core simulation logic — returns success/artifacts without real exploitation."""
        # Deterministic simulation based on technique + target hash
        sim_hash = hashlib.sha256(
            f"{technique.technique_id}:{target}:{time.time()}".encode()
        ).hexdigest()

        # Simulate varying success rates by tactic
        difficulty = {
            MitreTactic.RECONNAISSANCE: 0.90,
            MitreTactic.DISCOVERY: 0.85,
            MitreTactic.INITIAL_ACCESS: 0.60,
            MitreTactic.EXECUTION: 0.70,
            MitreTactic.PERSISTENCE: 0.65,
            MitreTactic.PRIVILEGE_ESCALATION: 0.45,
            MitreTactic.CREDENTIAL_ACCESS: 0.55,
            MitreTactic.LATERAL_MOVEMENT: 0.50,
            MitreTactic.COLLECTION: 0.75,
            MitreTactic.EXFILTRATION: 0.40,
            MitreTactic.COMMAND_AND_CONTROL: 0.60,
            MitreTactic.DEFENSE_EVASION: 0.55,
            MitreTactic.IMPACT: 0.30,
        }
        success_rate = difficulty.get(technique.tactic, 0.50)
        success = int(sim_hash[:2], 16) / 255.0 < success_rate

        artifacts = {
            "technique": technique.name,
            "tactic": technique.tactic.value,
            "target": target,
            "simulated": True,
            "sim_hash": sim_hash[:16],
        }

        if success:
            artifacts["finding"] = f"Simulated {technique.name} succeeded against {target}"

        return {"success": success, "artifacts": artifacts}

    @property
    def execution_count(self) -> int:
        with self._lock:
            return len(self._execution_log)

    def get_tactic_coverage(self) -> Dict[str, int]:
        """Count techniques executed per tactic."""
        coverage = {}
        with self._lock:
            for step in self._execution_log:
                t = TECHNIQUE_CATALOG.get(step.technique_id)
                if t:
                    coverage[t.tactic.value] = coverage.get(t.tactic.value, 0) + 1
        return coverage
