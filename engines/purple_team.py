"""
engines.purple_team — Combined Offensive + Defensive Assessment Engine
=======================================================================

Queen Califia's purple team capability — the fusion of red team attack
simulation with blue team detection validation, producing actionable
gap analysis and coverage scores.

Capabilities:
  - Attack replay with simultaneous detection validation
  - MITRE ATT&CK coverage heat map
  - Detection gap identification + prioritization
  - Tabletop exercise (TTX) scenario generation
  - Automated validate-and-remediate loops
  - Continuous security posture scoring
  - Campaign simulation (multi-stage APT chains)

Architecture:
  PurpleTeamOrchestrator coordinates:
    RedTeamEngine → executes attack techniques
    DetectionRuleEngine → evaluates detection coverage
    IOCCorrelationEngine → validates indicator detection
    → Produces PurpleTeamAssessment with actionable gaps
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from engines.red_team_tactics import (
    AttackChainResult,
    AttackTechnique,
    EngagementBounds,
    MitreTactic,
    RedTeamEngine,
    TECHNIQUE_CATALOG,
)
from engines.blue_team_tactics import (
    DetectionRule,
    DetectionRuleEngine,
    IOCCorrelationEngine,
    IOCEntry,
    RuleSeverity,
)

logger = logging.getLogger("engines.purple_team")


# ─── Coverage Models ────────────────────────────────────────────────────────

class CoverageLevel(str, Enum):
    NONE = "none"              # No detection
    MINIMAL = "minimal"        # <25% detection probability
    PARTIAL = "partial"        # 25-75%
    GOOD = "good"              # 75-90%
    EXCELLENT = "excellent"    # >90%


@dataclass
class TechniqueCoverage:
    """Detection coverage for a single MITRE technique."""
    technique_id: str
    technique_name: str
    tactic: str
    detection_rules: List[str] = field(default_factory=list)
    detection_count: int = 0
    simulated: bool = False
    attack_succeeded: bool = False
    detection_fired: bool = False
    detection_latency_ms: float = 0.0
    coverage_level: CoverageLevel = CoverageLevel.NONE
    gap_priority: str = "low"


@dataclass
class PurpleTeamAssessment:
    """Comprehensive purple team assessment result."""
    assessment_id: str
    engagement_id: str
    timestamp: float = field(default_factory=time.time)
    # Scores
    overall_score: float = 0.0          # 0-100
    detection_score: float = 0.0
    prevention_score: float = 0.0
    response_score: float = 0.0
    # Coverage
    techniques_tested: int = 0
    techniques_detected: int = 0
    techniques_missed: int = 0
    # Gaps
    critical_gaps: List[TechniqueCoverage] = field(default_factory=list)
    coverage_map: Dict[str, TechniqueCoverage] = field(default_factory=dict)
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    # Campaign results
    attack_chains_executed: int = 0
    attack_chains_detected: int = 0


# ─── Tabletop Exercise Models ───────────────────────────────────────────────

@dataclass
class TTXScenario:
    """Tabletop exercise scenario."""
    scenario_id: str
    name: str
    description: str
    threat_actor: str
    objectives: List[str] = field(default_factory=list)
    attack_chain: List[str] = field(default_factory=list)   # Technique IDs
    expected_detections: List[str] = field(default_factory=list)
    expected_responses: List[str] = field(default_factory=list)
    difficulty: str = "medium"
    industry_vertical: str = "general"


# ─── Pre-built APT Scenarios ────────────────────────────────────────────────

APT_SCENARIOS = {
    "apt29_cozy_bear": TTXScenario(
        scenario_id="apt29", name="APT29 (Cozy Bear) Emulation",
        description="Russian SVR-linked actor — supply chain + spearphishing + C2",
        threat_actor="APT29", difficulty="hard",
        objectives=["Initial access via spearphishing", "Establish persistence",
                     "Credential harvesting", "Lateral movement to DC", "Data exfiltration"],
        attack_chain=["T1566.001", "T1059.001", "T1053.005", "T1003.001",
                       "T1021.002", "T1560.001", "T1041"],
        expected_detections=["phishing_attachment", "powershell_suspicious",
                              "scheduled_task_creation", "lsass_access", "smb_lateral"],
    ),
    "apt41_double_dragon": TTXScenario(
        scenario_id="apt41", name="APT41 (Double Dragon) Emulation",
        description="China-linked dual espionage/cybercrime actor",
        threat_actor="APT41", difficulty="hard",
        objectives=["Exploit public-facing app", "Deploy web shell",
                     "Privilege escalation", "Kerberoasting", "Exfil over web"],
        attack_chain=["T1190", "T1059.004", "T1068", "T1558.003",
                       "T1005", "T1567"],
        expected_detections=["web_exploit_attempt", "webshell_detection",
                              "kernel_exploit", "kerberoast_attempt"],
    ),
    "ransomware_generic": TTXScenario(
        scenario_id="ransomware", name="Ransomware Operator Playbook",
        description="Generic big-game hunting ransomware operator",
        threat_actor="Ransomware Operator", difficulty="critical",
        objectives=["Initial access via RDP/VPN", "Credential dumping",
                     "Lateral movement", "Disable defenses", "Deploy ransomware"],
        attack_chain=["T1133", "T1078", "T1003.001", "T1021.001",
                       "T1562.001", "T1486"],
        expected_detections=["rdp_bruteforce", "credential_dump",
                              "lateral_rdp", "av_tamper", "mass_file_encrypt"],
    ),
    "insider_threat": TTXScenario(
        scenario_id="insider", name="Malicious Insider",
        description="Privileged insider conducting data theft",
        threat_actor="Insider", difficulty="medium",
        objectives=["Abuse valid credentials", "Discovery of sensitive data",
                     "Archive and exfiltrate", "Cover tracks"],
        attack_chain=["T1078", "T1087", "T1082", "T1005", "T1560.001",
                       "T1048", "T1070.001"],
        expected_detections=["anomalous_access", "mass_file_access",
                              "archive_creation", "data_exfil_alt_protocol"],
    ),
}


# ─── Purple Team Orchestrator ───────────────────────────────────────────────

class PurpleTeamOrchestrator:
    """
    Core purple team engine — coordinates attack simulation with
    detection validation to produce gap analysis.
    """

    def __init__(
        self,
        red_engine: Optional[RedTeamEngine] = None,
        detection_engine: Optional[DetectionRuleEngine] = None,
        ioc_engine: Optional[IOCCorrelationEngine] = None,
    ):
        self._lock = threading.RLock()
        self.red = red_engine or RedTeamEngine()
        self.detection = detection_engine or DetectionRuleEngine()
        self.ioc = ioc_engine or IOCCorrelationEngine()
        self._assessments: List[PurpleTeamAssessment] = []

    def run_assessment(
        self, engagement_id: str, techniques: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
    ) -> PurpleTeamAssessment:
        """
        Execute full purple team assessment:
          1. For each technique, run red team simulation
          2. Check if blue team detection rules fire
          3. Score coverage gaps
          4. Generate prioritized recommendations
        """
        assessment_id = secrets.token_urlsafe(12)
        assessment = PurpleTeamAssessment(
            assessment_id=assessment_id, engagement_id=engagement_id,
        )

        # Default to full catalog
        technique_ids = techniques or list(TECHNIQUE_CATALOG.keys())
        default_target = (targets or ["10.0.0.1"])[0]

        detection_coverage = self.detection.coverage_by_technique()
        tested = 0
        detected = 0

        for tid in technique_ids:
            tech = TECHNIQUE_CATALOG.get(tid)
            if not tech:
                continue

            tested += 1
            # Simulate attack
            step = self.red.simulate_technique(engagement_id, tid, default_target)

            # Check detection coverage
            rule_count = detection_coverage.get(tid, 0)
            has_detection = rule_count > 0

            # Simulate detection evaluation
            if step.success and has_detection:
                detection_fired = True
                detected += 1
            elif step.success:
                detection_fired = False
            else:
                detection_fired = has_detection  # Attack failed, detection presence counts

            # Coverage level
            if rule_count == 0:
                level = CoverageLevel.NONE
            elif rule_count == 1:
                level = CoverageLevel.MINIMAL
            elif rule_count <= 3:
                level = CoverageLevel.PARTIAL
            elif rule_count <= 5:
                level = CoverageLevel.GOOD
            else:
                level = CoverageLevel.EXCELLENT

            # Gap priority
            severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            tech_sev = severity_map.get(tech.severity, 1)
            if not has_detection and tech_sev >= 2:
                gap_priority = "critical"
            elif not has_detection:
                gap_priority = "high"
            elif step.success and not detection_fired:
                gap_priority = "medium"
            else:
                gap_priority = "low"

            cov = TechniqueCoverage(
                technique_id=tid, technique_name=tech.name,
                tactic=tech.tactic.value, detection_count=rule_count,
                simulated=True, attack_succeeded=step.success,
                detection_fired=detection_fired, coverage_level=level,
                gap_priority=gap_priority,
            )
            assessment.coverage_map[tid] = cov

            if gap_priority in ("critical", "high"):
                assessment.critical_gaps.append(cov)

        assessment.techniques_tested = tested
        assessment.techniques_detected = detected
        assessment.techniques_missed = tested - detected

        # Score calculation
        if tested > 0:
            assessment.detection_score = (detected / tested) * 100
            assessment.prevention_score = min(assessment.detection_score * 1.1, 100)
            assessment.response_score = min(
                len(self.detection.get_active_rules()) * 2.5, 100
            )
            assessment.overall_score = (
                assessment.detection_score * 0.5 +
                assessment.prevention_score * 0.3 +
                assessment.response_score * 0.2
            )

        # Generate recommendations
        assessment.recommendations = self._generate_recommendations(assessment)

        with self._lock:
            self._assessments.append(assessment)

        return assessment

    def run_ttx_scenario(self, scenario_id: str, engagement_id: str, target: str = "10.0.0.1") -> PurpleTeamAssessment:
        """Execute a pre-built tabletop exercise scenario."""
        scenario = APT_SCENARIOS.get(scenario_id)
        if not scenario:
            raise ValueError(f"Unknown scenario: {scenario_id}")
        return self.run_assessment(
            engagement_id=engagement_id,
            techniques=scenario.attack_chain,
            targets=[target],
        )

    def get_mitre_heatmap(self) -> Dict[str, Dict[str, int]]:
        """Generate MITRE ATT&CK coverage heatmap by tactic."""
        heatmap: Dict[str, Dict[str, int]] = {}
        coverage = self.detection.coverage_by_technique()

        for tid, tech in TECHNIQUE_CATALOG.items():
            tactic = tech.tactic.value
            if tactic not in heatmap:
                heatmap[tactic] = {"covered": 0, "uncovered": 0, "total": 0}
            heatmap[tactic]["total"] += 1
            if coverage.get(tid, 0) > 0:
                heatmap[tactic]["covered"] += 1
            else:
                heatmap[tactic]["uncovered"] += 1

        return heatmap

    def validate_detection_rule(
        self, rule_id: str, engagement_id: str, target: str = "10.0.0.1",
    ) -> Dict[str, Any]:
        """Validate a detection rule by simulating its MITRE techniques."""
        rule = self.detection.get_rule(rule_id)
        if not rule:
            return {"error": "Rule not found", "validated": False}

        results = []
        for tid in rule.mitre_techniques:
            step = self.red.simulate_technique(engagement_id, tid, target)
            results.append({
                "technique": tid, "attack_success": step.success,
                "detection_expected": True,
            })

        return {
            "rule_id": rule_id, "techniques_tested": len(results),
            "results": results, "validated": True,
        }

    def _generate_recommendations(self, assessment: PurpleTeamAssessment) -> List[str]:
        recs = []
        if assessment.overall_score < 50:
            recs.append("CRITICAL: Overall security posture below 50% — prioritize detection engineering")

        # Group gaps by tactic
        tactic_gaps: Dict[str, int] = {}
        for gap in assessment.critical_gaps:
            tactic_gaps[gap.tactic] = tactic_gaps.get(gap.tactic, 0) + 1

        for tactic, count in sorted(tactic_gaps.items(), key=lambda x: -x[1]):
            recs.append(f"Deploy {count} detection rules for '{tactic}' tactic")

        if assessment.techniques_missed > assessment.techniques_tested * 0.3:
            recs.append("Significant detection blind spots — consider MSSP/MDR partnership")

        if assessment.detection_score < 70:
            recs.append("Increase detection rule coverage to >70% before next assessment")

        return recs

    @property
    def assessment_count(self) -> int:
        with self._lock:
            return len(self._assessments)

    def get_latest_assessment(self) -> Optional[PurpleTeamAssessment]:
        with self._lock:
            return self._assessments[-1] if self._assessments else None


# ─── Continuous Auto-Validation ─────────────────────────────────────────────

class ContinuousValidator:
    """
    Automated continuous validation — periodically replays attack techniques
    to ensure detection rules remain effective after environment changes.
    """

    def __init__(self, orchestrator: PurpleTeamOrchestrator):
        self.orchestrator = orchestrator
        self._validation_history: List[Dict] = []

    def validate_coverage(self, engagement_id: str, techniques: Optional[List[str]] = None) -> Dict:
        """Run validation pass and compare with previous."""
        assessment = self.orchestrator.run_assessment(engagement_id, techniques)
        result = {
            "assessment_id": assessment.assessment_id,
            "score": assessment.overall_score,
            "tested": assessment.techniques_tested,
            "detected": assessment.techniques_detected,
            "gaps": len(assessment.critical_gaps),
            "timestamp": time.time(),
        }

        # Regression detection
        if self._validation_history:
            prev = self._validation_history[-1]
            result["score_delta"] = result["score"] - prev["score"]
            result["gap_delta"] = result["gaps"] - prev["gaps"]
            if result["score_delta"] < -5:
                result["regression"] = True
                logger.warning("purple_team.REGRESSION: score dropped %.1f points", abs(result["score_delta"]))

        self._validation_history.append(result)
        return result

    @property
    def validation_count(self) -> int:
        return len(self._validation_history)
