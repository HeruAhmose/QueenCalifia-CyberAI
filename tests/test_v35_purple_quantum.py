"""
tests/test_v35_purple_quantum.py — v3.5 Purple Team & Quantum Tests
=====================================================================
Tests for:
  - Quantum engine: entropy, lattice keys, vault, readiness
  - Red team: engagement scope, technique simulation, attack chains
  - Blue team: detection rules, IOC correlation, hunting, SOAR
  - Purple team: orchestration, gap analysis, TTX, continuous validation
  - Threat intel: feeds, indicators, CVEs, attribution, auto-decay
  - Policy: new action categories, engagement requirements
"""
import time
import pytest

from sovereignty.schemas import (
    ActionRequest, ModelDecision, ProposedAction, RiskLevel,
    EngagementScope, MitreTechnique, PurpleTeamResult, QuantumKeySpec,
    SignatureAlg,
)
from sovereignty.action_policy import ActionPolicy
from sovereignty.executor import SovereigntyExecutor, SovereigntyError


# ═══════════════════════════════════════════════════════════════════════════════
# QUANTUM ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TestQuantumEntropy:

    def test_random_bytes_length(self):
        from engines.quantum_engine import quantum_random_bytes
        for n in (16, 32, 64, 256):
            assert len(quantum_random_bytes(n)) == n

    def test_random_bytes_unique(self):
        from engines.quantum_engine import quantum_random_bytes
        samples = [quantum_random_bytes(32) for _ in range(10)]
        assert len(set(samples)) == 10  # All unique

    def test_random_int_range(self):
        from engines.quantum_engine import quantum_random_int
        for _ in range(50):
            val = quantum_random_int(0, 100)
            assert 0 <= val < 100

    def test_entropy_pool_health(self):
        from engines.quantum_engine import EntropyPool
        pool = EntropyPool()
        pool._health_check()
        assert pool.healthy

    def test_entropy_mix_count_increments(self):
        from engines.quantum_engine import EntropyPool
        pool = EntropyPool()
        initial = pool.mix_count
        pool.extract(32)
        assert pool.mix_count > initial


class TestQuantumLatticeKeys:

    def test_generate_dilithium3(self):
        from engines.quantum_engine import LatticeKeyGenerator, LatticeAlgorithm
        gen = LatticeKeyGenerator()
        kp = gen.generate_keypair(LatticeAlgorithm.DILITHIUM_3)
        assert len(kp.public_key) == 1952
        assert kp.algorithm == LatticeAlgorithm.DILITHIUM_3
        assert kp.key_id

    def test_generate_kyber768(self):
        from engines.quantum_engine import LatticeKeyGenerator, LatticeAlgorithm
        gen = LatticeKeyGenerator()
        kp = gen.generate_keypair(LatticeAlgorithm.KYBER_768, purpose="kem")
        assert len(kp.public_key) == 1184
        assert kp.purpose == "kem"

    def test_generate_falcon512(self):
        from engines.quantum_engine import LatticeKeyGenerator, LatticeAlgorithm
        kp = LatticeKeyGenerator().generate_keypair(LatticeAlgorithm.FALCON_512)
        assert len(kp.public_key) == 897

    def test_kem_encapsulation(self):
        from engines.quantum_engine import LatticeKeyGenerator, LatticeAlgorithm
        gen = LatticeKeyGenerator()
        kp = gen.generate_keypair(LatticeAlgorithm.KYBER_768)
        result = gen.generate_kem_encapsulation(LatticeAlgorithm.KYBER_768, kp.public_key)
        assert len(result.shared_secret) == 32
        assert len(result.ciphertext) == 1088

    def test_key_ttl(self):
        from engines.quantum_engine import LatticeKeyGenerator, LatticeAlgorithm
        kp = LatticeKeyGenerator().generate_keypair(LatticeAlgorithm.DILITHIUM_3, ttl_hours=1)
        assert kp.expires_at > kp.created_at
        assert kp.expires_at - kp.created_at == pytest.approx(3600, abs=2)


class TestQuantumKeyVault:

    def test_generate_and_store(self):
        from engines.quantum_engine import QuantumKeyVault, LatticeAlgorithm
        vault = QuantumKeyVault()
        kid = vault.generate_and_store(LatticeAlgorithm.DILITHIUM_5)
        assert vault.key_count == 1
        assert vault.get_public_key(kid) is not None

    def test_rotate_key(self):
        from engines.quantum_engine import QuantumKeyVault, LatticeAlgorithm
        vault = QuantumKeyVault()
        old = vault.generate_and_store(LatticeAlgorithm.DILITHIUM_3)
        new = vault.rotate_key(old)
        assert new is not None and new != old
        assert vault.key_count == 2
        assert len(vault.rotation_history) == 1

    def test_revoke(self):
        from engines.quantum_engine import QuantumKeyVault, LatticeAlgorithm
        vault = QuantumKeyVault()
        kid = vault.generate_and_store(LatticeAlgorithm.KYBER_768)
        assert vault.revoke(kid)
        assert vault.key_count == 0

    def test_nonexistent_key(self):
        from engines.quantum_engine import QuantumKeyVault
        assert QuantumKeyVault().get_public_key("nope") is None


class TestQuantumReadiness:

    def test_basic_assessment(self):
        from engines.quantum_engine import assess_quantum_readiness
        report = assess_quantum_readiness()
        assert 0.0 <= report.score <= 1.0
        assert report.entropy_health
        assert len(report.pq_algorithms_available) >= 4

    def test_assessment_with_vault(self):
        from engines.quantum_engine import assess_quantum_readiness, QuantumKeyVault, LatticeAlgorithm
        vault = QuantumKeyVault()
        vault.generate_and_store(LatticeAlgorithm.DILITHIUM_3)
        report = assess_quantum_readiness(vault=vault, hybrid_enabled=True)
        assert report.score > 0.5
        assert report.hybrid_mode_enabled

    def test_quantum_hash(self):
        from engines.quantum_engine import quantum_hash
        h = quantum_hash(b"test data")
        assert len(h) == 64  # sha3_256 hex

    def test_quantum_hash_chain(self):
        from engines.quantum_engine import quantum_hash_chain
        h = quantum_hash_chain([b"a", b"b", b"c"])
        assert len(h) == 64


# ═══════════════════════════════════════════════════════════════════════════════
# RED TEAM ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedTeamEngagement:

    def test_register_engagement(self):
        from engines.red_team_tactics import RedTeamEngine, EngagementBounds
        engine = RedTeamEngine()
        bounds = EngagementBounds(
            engagement_id="eng-1",
            authorized_targets=frozenset({"10.0.0.1", "10.0.0.2"}),
            excluded_targets=frozenset({"10.0.0.99"}),
            authorized_techniques=frozenset({"T1595.001", "T1046"}),
            expires_at=time.time() + 3600,
        )
        engine.register_engagement(bounds)
        assert engine.get_engagement("eng-1") is not None

    def test_target_authorization(self):
        from engines.red_team_tactics import EngagementBounds
        bounds = EngagementBounds(
            engagement_id="eng-1",
            authorized_targets=frozenset({"10.0.0.1"}),
            excluded_targets=frozenset({"10.0.0.99"}),
            authorized_techniques=frozenset(), expires_at=time.time() + 3600,
        )
        assert bounds.is_target_authorized("10.0.0.1")
        assert not bounds.is_target_authorized("10.0.0.99")
        assert not bounds.is_target_authorized("192.168.1.1")

    def test_expired_engagement_blocks(self):
        from engines.red_team_tactics import EngagementBounds
        bounds = EngagementBounds(
            engagement_id="eng-1",
            authorized_targets=frozenset({"10.0.0.1"}),
            excluded_targets=frozenset(),
            authorized_techniques=frozenset(), expires_at=time.time() - 1,
        )
        assert not bounds.is_target_authorized("10.0.0.1")


class TestRedTeamSimulation:

    def _engine_with_engagement(self):
        from engines.red_team_tactics import RedTeamEngine, EngagementBounds
        engine = RedTeamEngine()
        engine.register_engagement(EngagementBounds(
            engagement_id="test-eng",
            authorized_targets=frozenset({"10.0.0.1", "10.0.0.2"}),
            excluded_targets=frozenset(),
            authorized_techniques=frozenset(),
            expires_at=time.time() + 3600, max_severity="critical",
        ))
        return engine

    def test_simulate_recon(self):
        engine = self._engine_with_engagement()
        result = engine.simulate_technique("test-eng", "T1595.001", "10.0.0.1")
        assert result.technique_id == "T1595.001"
        assert result.error == ""

    def test_scope_violation_blocks(self):
        engine = self._engine_with_engagement()
        result = engine.simulate_technique("test-eng", "T1595.001", "192.168.99.1")
        assert not result.success and "scope" in result.error.lower()

    def test_unknown_engagement_fails(self):
        from engines.red_team_tactics import RedTeamEngine
        result = RedTeamEngine().simulate_technique("nope", "T1595.001", "10.0.0.1")
        assert not result.success

    def test_attack_chain(self):
        engine = self._engine_with_engagement()
        chain = [
            {"technique_id": "T1595.001", "target": "10.0.0.1"},
            {"technique_id": "T1046", "target": "10.0.0.1"},
            {"technique_id": "T1087", "target": "10.0.0.1"},
        ]
        result = engine.execute_attack_chain("test-eng", chain)
        assert len(result.steps) == 3
        assert result.scope_violations == 0

    def test_chain_aborts_on_scope_violation(self):
        engine = self._engine_with_engagement()
        chain = [
            {"technique_id": "T1595.001", "target": "10.0.0.1"},
            {"technique_id": "T1046", "target": "UNAUTHORIZED_HOST"},
            {"technique_id": "T1087", "target": "10.0.0.1"},
        ]
        result = engine.execute_attack_chain("test-eng", chain)
        assert result.scope_violations > 0
        assert len(result.steps) == 2  # Aborted after violation

    def test_technique_catalog_populated(self):
        from engines.red_team_tactics import TECHNIQUE_CATALOG
        assert len(TECHNIQUE_CATALOG) >= 30

    def test_tactic_coverage_tracking(self):
        engine = self._engine_with_engagement()
        engine.simulate_technique("test-eng", "T1595.001", "10.0.0.1")
        engine.simulate_technique("test-eng", "T1046", "10.0.0.1")
        cov = engine.get_tactic_coverage()
        assert "reconnaissance" in cov or "discovery" in cov


# ═══════════════════════════════════════════════════════════════════════════════
# BLUE TEAM ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectionRules:

    def test_add_and_activate(self):
        from engines.blue_team_tactics import DetectionRuleEngine, DetectionRule, RuleSeverity, RuleStatus
        engine = DetectionRuleEngine()
        rule = DetectionRule(rule_id="r1", name="Test Rule", description="Test",
                            severity=RuleSeverity.HIGH, detection_logic="powershell AND encoded")
        engine.add_rule(rule)
        engine.activate_rule("r1")
        assert engine.get_rule("r1").status == RuleStatus.ACTIVE

    def test_evaluate_event_match(self):
        from engines.blue_team_tactics import DetectionRuleEngine, DetectionRule, RuleSeverity, RuleStatus
        engine = DetectionRuleEngine()
        rule = DetectionRule(rule_id="r1", name="PS Detection", description="",
                            severity=RuleSeverity.HIGH, detection_logic="powershell AND encoded",
                            status=RuleStatus.ACTIVE)
        engine.add_rule(rule)
        matches = engine.evaluate_against_event({"command": "powershell -encoded abc123"})
        assert "r1" in matches

    def test_evaluate_event_no_match(self):
        from engines.blue_team_tactics import DetectionRuleEngine, DetectionRule, RuleSeverity, RuleStatus
        engine = DetectionRuleEngine()
        rule = DetectionRule(rule_id="r1", name="PS Detection", description="",
                            severity=RuleSeverity.HIGH, detection_logic="mimikatz",
                            status=RuleStatus.ACTIVE)
        engine.add_rule(rule)
        assert engine.evaluate_against_event({"command": "dir /s"}) == []

    def test_coverage_by_technique(self):
        from engines.blue_team_tactics import DetectionRuleEngine, DetectionRule, RuleSeverity, RuleStatus
        engine = DetectionRuleEngine()
        engine.add_rule(DetectionRule(
            rule_id="r1", name="T", description="", severity=RuleSeverity.HIGH,
            detection_logic="test", mitre_techniques=["T1059.001", "T1566.001"],
            status=RuleStatus.ACTIVE,
        ))
        cov = engine.coverage_by_technique()
        assert cov["T1059.001"] == 1 and cov["T1566.001"] == 1


class TestIOCCorrelation:

    def test_ingest_and_search(self):
        from engines.blue_team_tactics import IOCCorrelationEngine, IOCEntry, IOCType
        engine = IOCCorrelationEngine()
        ioc = IOCEntry(value="evil.com", ioc_type=IOCType.DOMAIN, source="feed1", confidence=0.9)
        engine.ingest(ioc)
        assert engine.ioc_count == 1
        results = engine.search("evil")
        assert len(results) == 1

    def test_correlate_event(self):
        from engines.blue_team_tactics import IOCCorrelationEngine, IOCEntry, IOCType
        engine = IOCCorrelationEngine()
        engine.ingest(IOCEntry(value="1.2.3.4", ioc_type=IOCType.IP, source="f", confidence=0.8))
        hits = engine.correlate_event({"src_ip": "1.2.3.4", "action": "connect"})
        assert len(hits) == 1 and engine.correlation_count == 1

    def test_dedup_on_reingest(self):
        from engines.blue_team_tactics import IOCCorrelationEngine, IOCEntry, IOCType
        engine = IOCCorrelationEngine()
        engine.ingest(IOCEntry(value="bad.com", ioc_type=IOCType.DOMAIN, source="f1", confidence=0.5))
        engine.ingest(IOCEntry(value="bad.com", ioc_type=IOCType.DOMAIN, source="f2", confidence=0.9))
        assert engine.ioc_count == 1
        results = engine.search("bad.com")
        assert results[0].confidence == 0.9  # Max kept


class TestThreatHunting:

    def test_register_and_execute(self):
        from engines.blue_team_tactics import ThreatHuntEngine, HuntQuery
        engine = ThreatHuntEngine()
        engine.register_query(HuntQuery(
            query_id="h1", name="Find Mimikatz", hypothesis="Credential dumping",
            query_text="mimikatz lsass",
        ))
        data = [
            {"process": "mimikatz.exe", "target": "lsass.exe"},
            {"process": "notepad.exe", "target": "document.txt"},
        ]
        result = engine.execute_hunt(engine._queries["h1"].query_id, data)
        assert result.hits == 1


class TestSOAR:

    def test_playbook_lifecycle(self):
        from engines.blue_team_tactics import SOAREngine, ResponsePlaybook, PlaybookStep, PlaybookAction
        engine = SOAREngine()
        pb = ResponsePlaybook(
            playbook_id="pb1", name="Contain Malware",
            trigger_rules=["r1", "r2"],
            steps=[
                PlaybookStep(action=PlaybookAction.CONTAIN, target="host"),
                PlaybookStep(action=PlaybookAction.NOTIFY, target="soc"),
            ],
        )
        engine.register_playbook(pb)
        triggered = engine.get_triggered_playbooks(["r1"])
        assert len(triggered) == 1

    def test_playbook_execution(self):
        from engines.blue_team_tactics import SOAREngine, ResponsePlaybook, PlaybookStep, PlaybookAction
        engine = SOAREngine()
        engine.register_playbook(ResponsePlaybook(
            playbook_id="pb1", name="T", trigger_rules=["r1"],
            steps=[PlaybookStep(action=PlaybookAction.BLOCK)],
        ))
        results = engine.execute_playbook("pb1", {"alert": "test"})
        assert len(results) == 1 and results[0]["status"] == "simulated"


# ═══════════════════════════════════════════════════════════════════════════════
# PURPLE TEAM ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestPurpleTeamOrchestrator:

    def _setup(self):
        from engines.red_team_tactics import RedTeamEngine, EngagementBounds
        from engines.blue_team_tactics import DetectionRuleEngine, DetectionRule, RuleSeverity, RuleStatus, IOCCorrelationEngine
        from engines.purple_team import PurpleTeamOrchestrator

        red = RedTeamEngine()
        red.register_engagement(EngagementBounds(
            engagement_id="purple-eng",
            authorized_targets=frozenset({"10.0.0.1"}),
            excluded_targets=frozenset(),
            authorized_techniques=frozenset(),
            expires_at=time.time() + 3600, max_severity="critical",
        ))
        detection = DetectionRuleEngine()
        # Add some detection rules
        for tid, name in [("T1566.001", "phishing"), ("T1059.001", "powershell"), ("T1003.001", "cred_dump")]:
            detection.add_rule(DetectionRule(
                rule_id=f"det-{tid}", name=name, description="",
                severity=RuleSeverity.HIGH, detection_logic=name,
                mitre_techniques=[tid], status=RuleStatus.ACTIVE,
            ))
        return PurpleTeamOrchestrator(red_engine=red, detection_engine=detection)

    def test_run_assessment(self):
        orch = self._setup()
        assessment = orch.run_assessment(
            "purple-eng",
            techniques=["T1566.001", "T1059.001", "T1003.001", "T1046", "T1087"],
        )
        assert assessment.techniques_tested == 5
        assert assessment.techniques_detected >= 1
        assert 0.0 <= assessment.overall_score <= 100.0
        assert len(assessment.coverage_map) == 5

    def test_gap_identification(self):
        orch = self._setup()
        assessment = orch.run_assessment(
            "purple-eng",
            techniques=["T1190", "T1068", "T1486"],  # No detection rules for these
        )
        assert assessment.techniques_missed >= 1
        assert len(assessment.critical_gaps) >= 1

    def test_ttx_scenario_apt29(self):
        orch = self._setup()
        assessment = orch.run_ttx_scenario("apt29_cozy_bear", "purple-eng")
        assert assessment.techniques_tested > 0
        assert assessment.assessment_id

    def test_ttx_scenario_ransomware(self):
        orch = self._setup()
        assessment = orch.run_ttx_scenario("ransomware_generic", "purple-eng")
        assert assessment.techniques_tested > 0

    def test_ttx_unknown_raises(self):
        orch = self._setup()
        with pytest.raises(ValueError, match="Unknown scenario"):
            orch.run_ttx_scenario("nonexistent", "purple-eng")

    def test_mitre_heatmap(self):
        orch = self._setup()
        heatmap = orch.get_mitre_heatmap()
        assert "initial-access" in heatmap
        assert heatmap["initial-access"]["total"] > 0

    def test_validate_detection_rule(self):
        orch = self._setup()
        result = orch.validate_detection_rule("det-T1566.001", "purple-eng")
        assert result["validated"]
        assert result["techniques_tested"] >= 1

    def test_recommendations_generated(self):
        orch = self._setup()
        assessment = orch.run_assessment("purple-eng", techniques=list(
            __import__("engines.red_team_tactics", fromlist=["TECHNIQUE_CATALOG"]).TECHNIQUE_CATALOG.keys()
        )[:10])
        assert isinstance(assessment.recommendations, list)


class TestContinuousValidation:

    def test_validate_and_track(self):
        from engines.red_team_tactics import RedTeamEngine, EngagementBounds
        from engines.blue_team_tactics import DetectionRuleEngine, IOCCorrelationEngine
        from engines.purple_team import PurpleTeamOrchestrator, ContinuousValidator

        red = RedTeamEngine()
        red.register_engagement(EngagementBounds(
            engagement_id="cv-eng",
            authorized_targets=frozenset({"10.0.0.1"}),
            excluded_targets=frozenset(),
            authorized_techniques=frozenset(),
            expires_at=time.time() + 3600, max_severity="critical",
        ))
        orch = PurpleTeamOrchestrator(red_engine=red)
        cv = ContinuousValidator(orch)
        r1 = cv.validate_coverage("cv-eng", ["T1595.001", "T1046"])
        r2 = cv.validate_coverage("cv-eng", ["T1595.001", "T1046"])
        assert cv.validation_count == 2
        assert "score_delta" in r2


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTEL AUTO-UPDATE
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatIntelFeeds:

    def test_register_feed(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatFeed, FeedFormat
        engine = ThreatIntelEngine()
        engine.register_feed(ThreatFeed(
            feed_id="f1", name="Test Feed", source_url="https://example.com/feed",
            feed_format=FeedFormat.STIX_TAXII, update_interval_sec=60,
        ))
        assert engine.feed_count == 1

    def test_feed_due_for_sync(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatFeed, FeedFormat
        engine = ThreatIntelEngine()
        engine.register_feed(ThreatFeed(
            feed_id="f1", name="T", source_url="x", feed_format=FeedFormat.CSV,
            update_interval_sec=1, last_sync=time.time() - 10,
        ))
        due = engine.get_feeds_due_for_sync()
        assert len(due) == 1

    def test_record_sync(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatFeed, FeedFormat
        engine = ThreatIntelEngine()
        engine.register_feed(ThreatFeed(feed_id="f1", name="T", source_url="x", feed_format=FeedFormat.JSON))
        engine.record_sync("f1", success=True, iocs_ingested=42)
        assert engine.get_feed("f1").ioc_count == 42


class TestThreatIntelIndicators:

    def test_ingest_and_search(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatIndicator
        engine = ThreatIntelEngine()
        engine.ingest_indicator(ThreatIndicator(
            indicator_id="i1", value="evil.com", indicator_type="domain",
            confidence=0.9, sources=["feed1"],
        ))
        assert engine.indicator_count == 1
        results = engine.search_indicators("evil")
        assert len(results) == 1

    def test_bulk_ingest(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatIndicator
        engine = ThreatIntelEngine()
        indicators = [
            ThreatIndicator(indicator_id=f"i{i}", value=f"{i}.2.3.4",
                            indicator_type="ip", confidence=0.8)
            for i in range(10)
        ]
        count = engine.bulk_ingest(indicators)
        assert count == 10 and engine.indicator_count == 10

    def test_confidence_decay(self):
        from engines.threat_intel_auto import ThreatIndicator
        ind = ThreatIndicator(
            indicator_id="i1", value="test", indicator_type="ip",
            confidence=0.5, last_seen=time.time() - 86400 * 30,  # 30 days ago
            decay_rate=0.02,
        )
        ind.apply_decay()
        assert ind.confidence < 0.5
        assert not ind.active  # Should be expired after 30 days decay

    def test_high_confidence_filter(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatIndicator
        engine = ThreatIntelEngine()
        engine.ingest_indicator(ThreatIndicator(indicator_id="hi", value="hi", indicator_type="ip", confidence=0.95))
        engine.ingest_indicator(ThreatIndicator(indicator_id="lo", value="lo", indicator_type="ip", confidence=0.2))
        high = engine.get_high_confidence_indicators(0.7)
        assert len(high) == 1


class TestCVETracking:

    def test_ingest_and_priority(self):
        from engines.threat_intel_auto import ThreatIntelEngine, CVERecord
        engine = ThreatIntelEngine()
        engine.ingest_cve(CVERecord(
            cve_id="CVE-2024-1234", description="Critical RCE",
            cvss_score=9.8, exploit_available=True, in_the_wild=True,
        ))
        critical = engine.get_critical_cves(min_priority=70)
        assert len(critical) == 1
        assert critical[0].priority_score > 80

    def test_exploitable_filter(self):
        from engines.threat_intel_auto import ThreatIntelEngine, CVERecord
        engine = ThreatIntelEngine()
        engine.ingest_cve(CVERecord(cve_id="CVE-1", description="T", cvss_score=5.0, exploit_available=True))
        engine.ingest_cve(CVERecord(cve_id="CVE-2", description="T", cvss_score=5.0))
        assert len(engine.get_exploitable_cves()) == 1


class TestThreatAttribution:

    def test_register_and_search(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatActorProfile
        engine = ThreatIntelEngine()
        engine.register_actor(ThreatActorProfile(
            actor_id="apt29", name="APT29", aliases=["Cozy Bear"],
            nation_state="Russia", known_techniques=["T1566.001"],
        ))
        results = engine.search_actors("cozy")
        assert len(results) == 1

    def test_stats(self):
        from engines.threat_intel_auto import ThreatIntelEngine, ThreatFeed, FeedFormat, ThreatIndicator
        engine = ThreatIntelEngine()
        engine.register_feed(ThreatFeed(feed_id="f1", name="T", source_url="x", feed_format=FeedFormat.JSON))
        engine.ingest_indicator(ThreatIndicator(indicator_id="i1", value="t", indicator_type="ip"))
        stats = engine.get_stats()
        assert stats["feeds"] == 1 and stats["indicators_total"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY — NEW ACTION CATEGORIES
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyPurpleTeamActions:

    def _policy_req(self, action, role="admin", env="prod", confidence=0.95, context=None):
        return ActionRequest(
            decision=ModelDecision(action=action, confidence=confidence, summary="T", rationale="T"),
            actor_id="user-1", actor_role=role, environment=env, tenant_id="t1",
            context=context or {},
        )

    def test_recon_passive_analyst_ok(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.recon_passive, "analyst", "dev", 0.7))
        assert result.allowed

    def test_red_team_requires_admin(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.simulate_exploit, "analyst", "prod", 0.95))
        assert not result.allowed and "insufficient" in result.reason.lower()

    def test_red_team_prod_requires_engagement(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.simulate_exploit, "admin", "prod", 0.95))
        assert not result.allowed and "engagement" in result.reason.lower()

    def test_red_team_prod_with_engagement(self):
        result = ActionPolicy().evaluate(self._policy_req(
            ProposedAction.simulate_exploit, "admin", "prod", 0.95,
            context={"engagement_id": "eng-1"},
        ))
        assert result.allowed and result.requires_approval

    def test_red_team_dev_no_engagement_needed(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.simulate_exploit, "admin", "dev", 0.7))
        assert result.allowed and not result.requires_approval

    def test_purple_gap_analysis_analyst(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.purple_gap_analysis, "analyst", "dev", 0.5))
        assert result.allowed

    def test_purple_attack_replay_prod_approval(self):
        result = ActionPolicy().evaluate(self._policy_req(
            ProposedAction.purple_attack_replay, "admin", "prod", 0.95,
            context={"engagement_id": "eng-1"},
        ))
        assert result.allowed and result.requires_approval

    def test_quantum_key_gen_admin_only(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.quantum_key_generate, "analyst"))
        assert not result.allowed

    def test_quantum_key_gen_admin_ok(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.quantum_key_generate, "admin", "dev", 0.5))
        assert result.allowed

    def test_intel_feed_sync_analyst(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.intel_feed_sync, "analyst", "dev", 0.3))
        assert result.allowed

    def test_deploy_detection_rule_analyst(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.deploy_detection_rule, "analyst", "prod", 0.7))
        assert result.allowed

    def test_hunt_query_analyst(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.execute_hunt_query, "analyst", "staging", 0.5))
        assert result.allowed

    def test_isolate_segment_admin(self):
        result = ActionPolicy().evaluate(self._policy_req(ProposedAction.isolate_network_segment, "admin", "prod", 0.95))
        assert result.allowed and result.requires_approval


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA — NEW MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class TestNewSchemaModels:

    def test_engagement_scope(self):
        scope = EngagementScope(
            engagement_id="eng-1", name="Test",
            authorized_targets=["10.0.0.0/24"],
            authorized_techniques=["T1566.001"],
        )
        assert scope.active and scope.engagement_id == "eng-1"

    def test_mitre_technique_model(self):
        t = MitreTechnique(technique_id="T1566.001", tactic="initial-access", name="Spearphishing")
        assert t.detection_coverage == 0.0

    def test_purple_team_result(self):
        r = PurpleTeamResult(
            operation_id="op-1", engagement_id="eng-1",
            technique=MitreTechnique(technique_id="T1566.001", tactic="initial-access", name="T"),
            attack_success=True, detection_fired=True, detection_latency_ms=150.0,
        )
        assert r.attack_success and r.detection_fired

    def test_quantum_key_spec(self):
        spec = QuantumKeySpec(algorithm=SignatureAlg.dilithium3, key_size_bits=4000)
        assert spec.purpose == "signing" and spec.rotation_interval_hours == 720

    def test_action_classifiers(self):
        assert ProposedAction.simulate_exploit in ProposedAction.red_team_actions()
        assert ProposedAction.simulate_exploit in ProposedAction.purple_team_actions()
        assert ProposedAction.contain_host in ProposedAction.blue_team_actions()
        assert ProposedAction.quantum_key_generate in ProposedAction.quantum_actions()
        assert ProposedAction.isolate_network_segment in ProposedAction.containment_actions()

    def test_new_signature_algs(self):
        assert SignatureAlg.kyber768.value == "kyber768"
        assert SignatureAlg.sphincs_sha2_256f.value == "sphincs_sha2_256f"
        assert SignatureAlg.falcon512.value == "falcon512"
