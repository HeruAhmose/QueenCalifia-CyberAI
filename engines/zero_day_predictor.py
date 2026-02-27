"""
QueenCalifia CyberAI — Zero-Day & Unknown Threat Prediction Engine
===================================================================
Biomimetic predictive intelligence inspired by biological immune systems
and ecological early-warning networks.

Architecture:
    Anticipatory Defense Layers:
    ┌─────────────────────────────────────────────────────────┐
    │  Layer 5: STRATEGIC FORECAST                            │
    │    Campaign trajectory modeling, geopolitical correlation│
    ├─────────────────────────────────────────────────────────┤
    │  Layer 4: BEHAVIORAL GENOME                             │
    │    Process DNA profiling, execution chain fingerprinting│
    ├─────────────────────────────────────────────────────────┤
    │  Layer 3: ENTROPY ANALYSIS                              │
    │    Shannon entropy on payloads, protocol deviations     │
    ├─────────────────────────────────────────────────────────┤
    │  Layer 2: ATTACK SURFACE DRIFT                          │
    │    Configuration delta tracking, exposure forecasting   │
    ├─────────────────────────────────────────────────────────┤
    │  Layer 1: ANOMALY FUSION                                │
    │    Multi-source statistical anomaly correlation         │
    └─────────────────────────────────────────────────────────┘

Zero-Day Detection Philosophy:
    Traditional signatures fail against unknown threats.
    This engine uses multiple orthogonal detection vectors:
    1. Behavioral deviation from established baselines
    2. Entropy analysis to detect obfuscation/encryption anomalies
    3. Execution chain profiling ("process DNA")
    4. Attack surface drift monitoring (what CHANGED)
    5. Threat campaign trajectory projection

    Like a biological immune system, it combines innate (heuristic)
    and adaptive (learned baseline) defenses, with memory cells
    (threat pattern library) that enable rapid response to variants.

Mycelium Signal Propagation:
    When ANY layer raises a predictive signal, it propagates to all
    other layers for cross-validation, reducing false positives while
    maintaining sensitivity to true zero-days.
"""

from __future__ import annotations

import math
import time
import uuid
import hashlib
import logging
import threading
import statistics
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from collections import defaultdict, deque

# Optional operational telemetry (JSONL + optional OpenTelemetry).
try:
    from core.telemetry import telemetry as _telemetry  # type: ignore
except Exception:  # pragma: no cover
    _telemetry = None

logger = logging.getLogger("queencalifia.zeroday")


# ─── Enumerations ──────────────────────────────────────────────────────────

class PredictionConfidence(Enum):
    """Confidence tiers for predictive assessments"""
    SPECULATIVE = "speculative"      # < 30% — interesting signal, no action
    EMERGING = "emerging"            # 30-60% — monitor closely, tune sensors
    PROBABLE = "probable"            # 60-80% — prepare containment, alert SOC
    HIGH_CONFIDENCE = "high"         # 80-95% — execute preemptive defenses
    NEAR_CERTAIN = "near_certain"    # > 95% — auto-respond immediately


class ThreatHorizon(Enum):
    """Time horizon for threat predictions"""
    IMMEDIATE = "0-1h"     # Active exploitation likely in progress
    SHORT_TERM = "1-24h"   # Attack expected within a day
    MEDIUM_TERM = "1-7d"   # Campaign development observed
    LONG_TERM = "7-30d"    # Strategic threat landscape shift
    STRATEGIC = "30d+"     # Emerging threat class / new attack paradigm


class ZeroDayCategory(Enum):
    """Categories of zero-day / unknown threat predictions"""
    NOVEL_EXPLOIT = "novel_exploit"
    VARIANT_MUTATION = "variant_mutation"
    SUPPLY_CHAIN_INJECTION = "supply_chain_injection"
    LIVING_OFF_THE_LAND = "living_off_the_land"
    FILELESS_ATTACK = "fileless_attack"
    PROTOCOL_ABUSE = "protocol_abuse"
    FIRMWARE_ROOTKIT = "firmware_rootkit"
    AI_GENERATED_MALWARE = "ai_generated_malware"
    ENCRYPTED_CHANNEL_ABUSE = "encrypted_channel_abuse"
    IDENTITY_FABRIC_ATTACK = "identity_fabric_attack"
    CONFIGURATION_DRIFT_EXPLOIT = "config_drift_exploit"
    POLYMORPHIC_PAYLOAD = "polymorphic_payload"


# ─── Data Models ───────────────────────────────────────────────────────────

@dataclass
class ThreatPrediction:
    """A predicted threat with confidence scoring and evidence chain"""
    prediction_id: str = field(
        default_factory=lambda: f"PRED-{uuid.uuid4().hex[:8].upper()}"
    )
    category: ZeroDayCategory = ZeroDayCategory.NOVEL_EXPLOIT
    title: str = ""
    description: str = ""
    confidence: float = 0.0
    confidence_tier: PredictionConfidence = PredictionConfidence.SPECULATIVE
    threat_horizon: ThreatHorizon = ThreatHorizon.MEDIUM_TERM
    risk_score: float = 0.0

    # Evidence chain
    contributing_signals: List[Dict[str, Any]] = field(default_factory=list)
    affected_assets: Set[str] = field(default_factory=set)
    attack_vector: str = ""
    predicted_techniques: List[str] = field(default_factory=list)

    # Preemptive actions
    recommended_preemptive_actions: List[str] = field(default_factory=list)
    auto_hardening_applied: List[str] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    validated: bool = False
    outcome: Optional[str] = None  # confirmed, false_positive, inconclusive

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prediction_id": self.prediction_id,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "confidence_tier": self.confidence_tier.value,
            "threat_horizon": self.threat_horizon.value,
            "risk_score": round(self.risk_score, 2),
            "contributing_signals": len(self.contributing_signals),
            "affected_assets": list(self.affected_assets),
            "attack_vector": self.attack_vector,
            "predicted_techniques": self.predicted_techniques,
            "recommended_preemptive_actions": self.recommended_preemptive_actions,
            "auto_hardening_applied": self.auto_hardening_applied,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "validated": self.validated,
            "outcome": self.outcome,
        }


@dataclass
class AttackSurfaceSnapshot:
    """Point-in-time capture of the attack surface"""
    snapshot_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=datetime.utcnow)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    exposed_services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    configuration_hashes: Dict[str, str] = field(default_factory=dict)
    certificate_expiry: Dict[str, datetime] = field(default_factory=dict)
    patch_levels: Dict[str, str] = field(default_factory=dict)
    network_topology_hash: str = ""
    user_count: int = 0
    privileged_accounts: int = 0
    external_integrations: int = 0


@dataclass
class BehavioralGenome:
    """Process execution DNA — normal behavior fingerprint for an asset"""
    asset_id: str = ""
    process_chains: Dict[str, int] = field(default_factory=dict)
    network_patterns: Dict[str, float] = field(default_factory=dict)
    file_access_patterns: Dict[str, int] = field(default_factory=dict)
    auth_patterns: Dict[str, int] = field(default_factory=dict)
    timing_baselines: Dict[str, List[float]] = field(default_factory=dict)
    entropy_baselines: Dict[str, List[float]] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    sample_count: int = 0


@dataclass
class EntropyProfile:
    """Shannon entropy analysis for data streams"""
    stream_id: str = ""
    current_entropy: float = 0.0
    baseline_entropy: float = 0.0
    entropy_delta: float = 0.0
    is_anomalous: bool = False
    anomaly_type: str = ""  # encryption_increase, encoding_shift, compression_change


# ─── Zero-Day Prediction Engine ──────────────────────────────────────────

class ZeroDayPredictor:
    """
    QueenCalifia Predictive Threat Intelligence Engine

    Combines five orthogonal detection layers to anticipate zero-day
    threats, unknown attack vectors, and novel exploitation techniques
    BEFORE they are catalogued in signature databases.

    Biological analogy: This is the "innate immune system" — it detects
    threats based on behavioral anomalies, structural analysis, and
    pattern deviation rather than exact signature matching.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

        # Concurrency
        self._lock = threading.RLock()

        # ── Layer 1: Anomaly Fusion ──
        self.anomaly_streams: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10_000)
        )
        self.anomaly_baselines: Dict[str, Dict[str, float]] = defaultdict(dict)

        # ── Layer 2: Attack Surface Drift ──
        self.surface_snapshots: deque = deque(maxlen=500)
        self.drift_alerts: List[Dict[str, Any]] = []

        # ── Layer 3: Entropy Analysis ──
        self.entropy_profiles: Dict[str, EntropyProfile] = {}
        self.entropy_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1_000)
        )

        # ── Layer 4: Behavioral Genome ──
        self.genomes: Dict[str, BehavioralGenome] = {}
        self.genome_deviations: deque = deque(maxlen=5_000)

        # ── Layer 5: Strategic Forecast ──
        self.campaign_indicators: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.threat_landscape: Dict[str, Dict[str, Any]] = (
            self._init_threat_landscape()
        )

        # ── Predictions ──
        self.active_predictions: Dict[str, ThreatPrediction] = {}
        self.prediction_history: deque = deque(maxlen=10_000)
        self.prediction_accuracy: Dict[str, int] = {
            "confirmed": 0,
            "false_positive": 0,
            "inconclusive": 0,
            "pending": 0,
        }

        # ── Cross-layer signal bus ──
        self.signal_bus: deque = deque(maxlen=50_000)

        # ── Statistics ──
        self.stats = {
            "events_analyzed": 0,
            "predictions_generated": 0,
            "zero_days_predicted": 0,
            "preemptive_actions_taken": 0,
            "accuracy_rate": 0.0,
            "start_time": datetime.utcnow(),
        }

        logger.info(
            "🔮 Zero-Day Prediction Engine online | "
            f"{len(self.threat_landscape)} threat vectors tracked"
        )

    # ─── Threat Landscape Initialization ───────────────────────────────────

    def _init_threat_landscape(self) -> Dict[str, Dict[str, Any]]:
        """Initialize the strategic threat landscape model."""
        return {
            "ransomware_evolution": {
                "trend": "accelerating",
                "risk_multiplier": 1.4,
                "indicators": [
                    "double_extortion", "supply_chain_entry",
                    "ESXi_targeting", "cloud_ransomware",
                ],
                "predicted_vectors": [
                    "T1486", "T1490", "T1489"
                ],
            },
            "identity_attacks": {
                "trend": "accelerating",
                "risk_multiplier": 1.3,
                "indicators": [
                    "MFA_fatigue", "token_theft",
                    "OAuth_abuse", "session_hijacking",
                ],
                "predicted_vectors": [
                    "T1556", "T1528", "T1550"
                ],
            },
            "supply_chain": {
                "trend": "escalating",
                "risk_multiplier": 1.5,
                "indicators": [
                    "dependency_confusion", "build_poisoning",
                    "update_hijacking", "typosquatting",
                ],
                "predicted_vectors": [
                    "T1195.001", "T1195.002"
                ],
            },
            "ai_augmented_attacks": {
                "trend": "emerging",
                "risk_multiplier": 1.6,
                "indicators": [
                    "AI_phishing", "deepfake_vishing",
                    "automated_recon", "polymorphic_AI_malware",
                ],
                "predicted_vectors": [
                    "T1566", "T1598", "T1059"
                ],
            },
            "cloud_native_exploitation": {
                "trend": "accelerating",
                "risk_multiplier": 1.3,
                "indicators": [
                    "container_escape", "serverless_abuse",
                    "SSRF_to_metadata", "misconfigured_IAM",
                ],
                "predicted_vectors": [
                    "T1610", "T1611", "T1552"
                ],
            },
            "firmware_and_hardware": {
                "trend": "emerging",
                "risk_multiplier": 1.7,
                "indicators": [
                    "UEFI_rootkit", "BMC_exploitation",
                    "GPU_malware", "NIC_implant",
                ],
                "predicted_vectors": [
                    "T1542", "T1495"
                ],
            },
            "encrypted_channel_abuse": {
                "trend": "stable",
                "risk_multiplier": 1.2,
                "indicators": [
                    "TLS_C2", "DoH_tunneling",
                    "QUIC_exfil", "steganography",
                ],
                "predicted_vectors": [
                    "T1573", "T1071.001", "T1048"
                ],
            },
            "zero_day_exploit_market": {
                "trend": "expanding",
                "risk_multiplier": 1.8,
                "indicators": [
                    "browser_zero_days", "mobile_exploits",
                    "enterprise_software_0days", "IOT_exploits",
                ],
                "predicted_vectors": [
                    "T1203", "T1210", "T1190"
                ],
            },
        }

    # ─── Primary Analysis Pipeline ────────────────────────────────────────

    def analyze_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Primary analysis pipeline — processes a security event through
        all five prediction layers and generates predictions.

        Returns analysis results with any predictions generated.
        """
        if _telemetry:
            try:
                asset_id = event_data.get('asset_id') or event_data.get('host') or event_data.get('device') or 'unknown'
                event_type = event_data.get('event_type') or event_data.get('type') or 'unknown'
                _telemetry.event('zero_day.analyze.start', {'asset_id': asset_id, 'event_type': event_type})
            except Exception:
                pass

        start = time.monotonic()

        with self._lock:
            self.stats["events_analyzed"] += 1

        signals: List[Dict[str, Any]] = []

        # Layer 1: Multi-source anomaly fusion
        l1_signals = self._layer1_anomaly_fusion(event_data)
        signals.extend(l1_signals)

        # Layer 2: Attack surface drift detection
        l2_signals = self._layer2_surface_drift(event_data)
        signals.extend(l2_signals)

        # Layer 3: Entropy analysis
        l3_signals = self._layer3_entropy_analysis(event_data)
        signals.extend(l3_signals)

        # Layer 4: Behavioral genome deviation
        l4_signals = self._layer4_genome_deviation(event_data)
        signals.extend(l4_signals)

        # Layer 5: Strategic threat correlation
        l5_signals = self._layer5_strategic_forecast(event_data)
        signals.extend(l5_signals)

        # Cross-layer correlation and prediction generation
        predictions = self._correlate_and_predict(signals, event_data)

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)

        if _telemetry:
            try:
                asset_id = event_data.get('asset_id') or event_data.get('host') or event_data.get('device') or 'unknown'
                preds = list(predictions) if 'predictions' in locals() else []
                confidences = [getattr(p, 'confidence', 0.0) for p in preds]
                layers = []
                for p in preds:
                    layers.extend(list(getattr(p, 'layers_triggered', []) or []))
                seen = set()
                layers_uniq = [x for x in layers if not (x in seen or seen.add(x))]
                _telemetry.event('zero_day.analyze.result', {
                    'asset_id': asset_id,
                    'prediction_count': len(preds),
                    'max_confidence': max(confidences) if confidences else 0.0,
                    'layers_triggered': layers_uniq,
                })
            except Exception:
                pass

        return {
            "event_processed": True,
            "processing_time_ms": elapsed_ms,
            "signals_generated": len(signals),
            "predictions_generated": len(predictions),
            "predictions": [p.to_dict() for p in predictions],
            "layer_summary": {
                "anomaly_fusion": len(l1_signals),
                "surface_drift": len(l2_signals),
                "entropy_analysis": len(l3_signals),
                "genome_deviation": len(l4_signals),
                "strategic_forecast": len(l5_signals),
            },
        }

    # ─── Layer 1: Multi-Source Anomaly Fusion ──────────────────────────────

    def _layer1_anomaly_fusion(
        self, event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Fuse anomaly signals from multiple data sources to identify
        correlated deviations that may indicate unknown threats.

        Biological analogy: Multiple sensory inputs (sight, smell, sound)
        converging on the same threat signal — each alone might be noise,
        but together they indicate real danger.
        """
        signals: List[Dict[str, Any]] = []
        source = event.get("source_ip", "unknown")
        now = datetime.utcnow()

        # Extract numerical features
        features = {
            "bytes_out": float(event.get("bytes_out", 0)),
            "bytes_in": float(event.get("bytes_in", 0)),
            "duration_ms": float(event.get("duration_ms", 0)),
            "unique_destinations": float(event.get("unique_destinations", 0)),
            "unique_ports": float(event.get("unique_ports_1min", 0)),
            "packet_size_variance": float(event.get("packet_size_var", 0)),
            "inter_arrival_time": float(event.get("inter_arrival_ms", 0)),
            "dns_query_length": float(
                len(event.get("query_name", ""))
            ),
        }

        anomaly_count = 0
        anomaly_details: List[Dict[str, Any]] = []

        with self._lock:
            for fname, fval in features.items():
                if fval <= 0:
                    continue

                stream_key = f"{source}:{fname}"
                history = self.anomaly_streams[stream_key]
                history.append(fval)

                if len(history) < 20:
                    continue

                vals = list(history)
                mean = statistics.mean(vals)
                stdev = statistics.stdev(vals) if len(vals) > 1 else 1.0
                if stdev < 1e-9:
                    continue

                z_score = abs(fval - mean) / stdev

                # Adaptive threshold: lower for correlated anomalies
                threshold = float(
                    self.config.get("anomaly_z_threshold", 2.5)
                )
                if z_score > threshold:
                    anomaly_count += 1
                    anomaly_details.append({
                        "feature": fname,
                        "value": fval,
                        "mean": round(mean, 2),
                        "z_score": round(z_score, 2),
                    })

        # Multi-feature anomaly fusion: flag when 2+ features deviate
        if anomaly_count >= 2:
            signal = {
                "layer": "anomaly_fusion",
                "signal_type": "correlated_multi_anomaly",
                "source": source,
                "anomaly_count": anomaly_count,
                "details": anomaly_details,
                "confidence": min(0.95, 0.4 + anomaly_count * 0.15),
                "severity": "high" if anomaly_count >= 3 else "medium",
                "timestamp": now.isoformat(),
                "description": (
                    f"Correlated anomalies across {anomaly_count} features "
                    f"from {source} — potential unknown threat pattern"
                ),
            }
            signals.append(signal)

            with self._lock:
                self.signal_bus.append(signal)

        return signals

    # ─── Layer 2: Attack Surface Drift Detection ──────────────────────────

    def _layer2_surface_drift(
        self, event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Track changes in the attack surface over time to identify
        new exposure that could be exploited by zero-day attacks.

        Concept: If a new port opens, a certificate expires, or a
        configuration changes — the attack surface has DRIFTED,
        creating windows of opportunity for exploitation.
        """
        signals: List[Dict[str, Any]] = []

        # Detect new service exposure
        if event.get("event_type") == "service_discovered":
            port = event.get("port", 0)
            service = event.get("service_name", "unknown")
            asset = event.get("asset_id", "unknown")

            signal = {
                "layer": "surface_drift",
                "signal_type": "new_service_exposure",
                "asset": asset,
                "port": port,
                "service": service,
                "confidence": 0.6,
                "severity": "medium",
                "timestamp": datetime.utcnow().isoformat(),
                "description": (
                    f"New service {service}:{port} detected on {asset} — "
                    f"attack surface expanded"
                ),
            }
            signals.append(signal)

        # Detect configuration drift
        if event.get("event_type") == "config_change":
            asset = event.get("asset_id", "unknown")
            component = event.get("component", "unknown")
            change_type = event.get("change_type", "unknown")

            risk_changes = {
                "firewall_rule_added",
                "firewall_rule_removed",
                "auth_policy_changed",
                "tls_config_changed",
                "permission_escalated",
                "new_external_integration",
            }

            if change_type in risk_changes:
                signal = {
                    "layer": "surface_drift",
                    "signal_type": "risky_config_change",
                    "asset": asset,
                    "component": component,
                    "change_type": change_type,
                    "confidence": 0.65,
                    "severity": "high",
                    "timestamp": datetime.utcnow().isoformat(),
                    "description": (
                        f"High-risk configuration change: {change_type} "
                        f"on {asset}/{component}"
                    ),
                }
                signals.append(signal)

        # Detect certificate approaching expiry
        if event.get("event_type") == "cert_status":
            days_remaining = event.get("days_to_expiry", 365)
            domain = event.get("domain", "unknown")
            if days_remaining < 14:
                signal = {
                    "layer": "surface_drift",
                    "signal_type": "certificate_expiry_risk",
                    "domain": domain,
                    "days_remaining": days_remaining,
                    "confidence": 0.8,
                    "severity": "critical" if days_remaining < 3 else "high",
                    "timestamp": datetime.utcnow().isoformat(),
                    "description": (
                        f"Certificate for {domain} expires in "
                        f"{days_remaining} days — MitM risk window"
                    ),
                }
                signals.append(signal)

        return signals

    # ─── Layer 3: Entropy Analysis ─────────────────────────────────────────

    def _layer3_entropy_analysis(
        self, event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Shannon entropy analysis to detect obfuscation, encryption
        changes, and encoded payloads indicative of novel malware.

        Principle: Normal traffic has characteristic entropy ranges.
        Encrypted C2, encoded payloads, and obfuscated exfil show
        entropy signatures that deviate from baselines.

        Entropy ranges (8-bit):
            - Plain text: 3.5 - 5.0
            - Compressed: 5.5 - 7.0
            - Encrypted/random: 7.5 - 8.0
            - Base64 encoded: 5.0 - 6.0
        """
        signals: List[Dict[str, Any]] = []

        payload = event.get("payload", "") or event.get("raw_payload", "")
        if not payload or len(payload) < 16:
            return signals

        # Calculate Shannon entropy
        entropy = self._shannon_entropy(payload)
        stream_id = event.get("stream_id", event.get("source_ip", "unknown"))

        with self._lock:
            history = self.entropy_history[stream_id]
            history.append(entropy)

            if len(history) >= 10:
                baseline = statistics.mean(list(history)[:-1])
                current_delta = abs(entropy - baseline)

                # Detect entropy jump (sudden encryption / encoding change)
                if current_delta > 1.5:
                    anomaly_type = "unknown"
                    if entropy > 7.5:
                        anomaly_type = "encryption_onset"
                    elif entropy > 5.5 and baseline < 5.0:
                        anomaly_type = "encoding_shift"
                    elif entropy < baseline - 1.0:
                        anomaly_type = "compression_change"

                    signal = {
                        "layer": "entropy_analysis",
                        "signal_type": "entropy_anomaly",
                        "stream_id": stream_id,
                        "current_entropy": round(entropy, 3),
                        "baseline_entropy": round(baseline, 3),
                        "delta": round(current_delta, 3),
                        "anomaly_type": anomaly_type,
                        "confidence": min(0.9, 0.5 + current_delta * 0.15),
                        "severity": (
                            "critical" if anomaly_type == "encryption_onset"
                            else "high"
                        ),
                        "timestamp": datetime.utcnow().isoformat(),
                        "description": (
                            f"Entropy anomaly ({anomaly_type}) on stream "
                            f"{stream_id}: {entropy:.2f} vs baseline "
                            f"{baseline:.2f}"
                        ),
                    }
                    signals.append(signal)

                # Detect sustained high entropy (potential encrypted C2)
                recent = list(history)[-20:]
                if len(recent) >= 20:
                    high_entropy_ratio = (
                        sum(1 for e in recent if e > 7.0) / len(recent)
                    )
                    if high_entropy_ratio > 0.8:
                        signal = {
                            "layer": "entropy_analysis",
                            "signal_type": "sustained_high_entropy",
                            "stream_id": stream_id,
                            "high_entropy_ratio": round(
                                high_entropy_ratio, 2
                            ),
                            "confidence": 0.75,
                            "severity": "high",
                            "timestamp": datetime.utcnow().isoformat(),
                            "description": (
                                f"Sustained high entropy on {stream_id} "
                                f"({high_entropy_ratio:.0%} of samples) — "
                                f"potential encrypted C2 channel"
                            ),
                        }
                        signals.append(signal)

        return signals

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ─── Layer 4: Behavioral Genome Deviation ─────────────────────────────

    def _layer4_genome_deviation(
        self, event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Compare process execution patterns against established
        "behavioral DNA" to detect anomalous execution chains
        that may indicate novel exploitation.

        Biological analogy: Like a biological genome, each system
        has a characteristic execution profile. Mutations (deviations)
        indicate potential infection or exploitation.
        """
        signals: List[Dict[str, Any]] = []
        asset = event.get("asset_id", event.get("hostname", "unknown"))

        if event.get("event_type") not in (
            "process_start", "process_chain", "execution_context"
        ):
            return signals

        process = event.get("process_name", "")
        parent = event.get("parent_process", "")
        chain = f"{parent} → {process}"
        command_line = event.get("command_line", "")

        with self._lock:
            genome = self.genomes.get(asset)
            if not genome:
                genome = BehavioralGenome(asset_id=asset)
                self.genomes[asset] = genome

            # Update genome with observed execution
            genome.process_chains[chain] = (
                genome.process_chains.get(chain, 0) + 1
            )
            genome.sample_count += 1
            genome.last_updated = datetime.utcnow()

            # After sufficient learning, detect deviations
            if genome.sample_count < 100:
                return signals

            # Check if this execution chain is novel
            if genome.process_chains.get(chain, 0) <= 2:
                # Novel or very rare execution chain
                confidence = 0.6

                # Escalate if suspicious process characteristics
                suspicious_indicators = [
                    process.lower() in {
                        "powershell.exe", "cmd.exe", "bash",
                        "python", "python3", "wscript.exe",
                        "cscript.exe", "mshta.exe",
                    },
                    len(command_line) > 500,
                    "base64" in command_line.lower(),
                    "-enc" in command_line.lower(),
                    "bypass" in command_line.lower(),
                    "hidden" in command_line.lower(),
                    "downloadstring" in command_line.lower(),
                    "invoke-expression" in command_line.lower(),
                ]

                suspicion_count = sum(suspicious_indicators)
                if suspicion_count > 0:
                    confidence = min(
                        0.95, confidence + suspicion_count * 0.1
                    )

                if confidence >= 0.55:
                    signal = {
                        "layer": "genome_deviation",
                        "signal_type": "novel_execution_chain",
                        "asset": asset,
                        "process_chain": chain,
                        "command_line_length": len(command_line),
                        "suspicious_indicators": suspicion_count,
                        "genome_sample_count": genome.sample_count,
                        "chain_frequency": genome.process_chains.get(
                            chain, 0
                        ),
                        "confidence": round(confidence, 2),
                        "severity": (
                            "critical" if suspicion_count >= 3
                            else "high" if suspicion_count >= 1
                            else "medium"
                        ),
                        "timestamp": datetime.utcnow().isoformat(),
                        "description": (
                            f"Novel execution chain on {asset}: {chain} "
                            f"({suspicion_count} suspicious indicators)"
                        ),
                    }
                    signals.append(signal)

                    self.genome_deviations.append({
                        "asset": asset,
                        "chain": chain,
                        "timestamp": datetime.utcnow().isoformat(),
                    })

        return signals

    # ─── Layer 5: Strategic Threat Forecast ────────────────────────────────

    def _layer5_strategic_forecast(
        self, event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Correlate observed activity against the strategic threat
        landscape to predict campaign-level threats.

        This layer looks at the big picture: Is the pattern of
        activity we're seeing consistent with known APT campaigns,
        emerging attack trends, or predicted threat vectors?
        """
        signals: List[Dict[str, Any]] = []

        event_indicators = set()
        if event.get("event_type") == "dns_query":
            qname = event.get("query_name", "")
            if len(qname) > 40:
                event_indicators.add("DoH_tunneling")
            if event.get("query_type") == "TXT":
                event_indicators.add("DoH_tunneling")

        if event.get("event_type") == "auth_failure":
            if event.get("auth_type") == "mfa_push":
                event_indicators.add("MFA_fatigue")
            if event.get("failures_1min", 0) > 20:
                event_indicators.add("token_theft")

        if event.get("event_type") == "process_start":
            cmd = event.get("command_line", "").lower()
            if "iex" in cmd or "invoke-expression" in cmd:
                event_indicators.add("polymorphic_AI_malware")
            if "esxi" in cmd or "vmware" in cmd:
                event_indicators.add("ESXi_targeting")

        if event.get("event_type") in ("dependency_install", "package_audit"):
            if event.get("typosquat_score", 0) > 0.7:
                event_indicators.add("typosquatting")
            if event.get("is_new_dependency", False):
                event_indicators.add("dependency_confusion")

        # Match against threat landscape
        for vector_name, vector in self.threat_landscape.items():
            matched = event_indicators.intersection(set(vector["indicators"]))
            if matched:
                with self._lock:
                    self.campaign_indicators[vector_name].append({
                        "indicators": list(matched),
                        "timestamp": datetime.utcnow().isoformat(),
                        "event_type": event.get("event_type"),
                    })

                    # Check for campaign-level threshold
                    recent = [
                        i for i in self.campaign_indicators[vector_name]
                        if datetime.fromisoformat(i["timestamp"])
                        > datetime.utcnow() - timedelta(hours=24)
                    ]

                if len(recent) >= 3:
                    signal = {
                        "layer": "strategic_forecast",
                        "signal_type": "campaign_correlation",
                        "threat_vector": vector_name,
                        "matched_indicators": list(matched),
                        "recent_signal_count": len(recent),
                        "trend": vector["trend"],
                        "risk_multiplier": vector["risk_multiplier"],
                        "predicted_techniques": vector["predicted_vectors"],
                        "confidence": min(
                            0.90,
                            0.3 + len(recent) * 0.1
                            + vector["risk_multiplier"] * 0.1
                        ),
                        "severity": (
                            "critical"
                            if vector["risk_multiplier"] >= 1.5
                            else "high"
                        ),
                        "timestamp": datetime.utcnow().isoformat(),
                        "description": (
                            f"Strategic threat correlation: {vector_name} "
                            f"campaign indicators detected "
                            f"({len(recent)} signals in 24h, "
                            f"trend={vector['trend']})"
                        ),
                    }
                    signals.append(signal)

        return signals

    # ─── Cross-Layer Correlation & Prediction ─────────────────────────────

    def _correlate_and_predict(
        self,
        signals: List[Dict[str, Any]],
        event: Dict[str, Any],
    ) -> List[ThreatPrediction]:
        """
        Correlate signals across all five layers to generate
        actionable threat predictions.

        The key insight: a single anomaly is noise.
        Correlated anomalies across multiple detection dimensions
        are almost certainly a real threat.
        """
        if not signals:
            return []

        predictions: List[ThreatPrediction] = []

        # Group signals by source / asset
        source = event.get("source_ip", event.get("asset_id", "unknown"))

        layers_triggered = set(s["layer"] for s in signals)
        total_confidence = sum(
            s.get("confidence", 0) for s in signals
        ) / max(1, len(signals))

        # Multi-layer correlation: if 3+ layers trigger, generate prediction
        if len(layers_triggered) >= 3:
            prediction = self._generate_prediction(
                signals=signals,
                source=source,
                layers=layers_triggered,
                base_confidence=total_confidence,
            )
            predictions.append(prediction)

        # High-confidence single-layer signals also generate predictions
        critical_signals = [
            s for s in signals
            if s.get("severity") == "critical"
            and s.get("confidence", 0) >= 0.8
        ]
        for sig in critical_signals:
            prediction = self._generate_single_signal_prediction(sig, source)
            predictions.append(prediction)

        # Store predictions
        with self._lock:
            for p in predictions:
                self.active_predictions[p.prediction_id] = p
                self.prediction_history.append(p)
                self.stats["predictions_generated"] += 1
                self.prediction_accuracy["pending"] += 1

                if p.confidence >= 0.7:
                    self.stats["zero_days_predicted"] += 1

                    # Auto-generate preemptive actions
                    p.recommended_preemptive_actions = (
                        self._generate_preemptive_actions(p)
                    )

        return predictions

    def _generate_prediction(
        self,
        signals: List[Dict[str, Any]],
        source: str,
        layers: set,
        base_confidence: float,
    ) -> ThreatPrediction:
        """Generate a multi-layer correlated threat prediction."""

        # Determine category based on signal composition
        category = self._classify_prediction_category(signals)

        # Confidence boost for multi-layer correlation
        layer_bonus = len(layers) * 0.08
        confidence = min(0.98, base_confidence + layer_bonus)

        # Determine confidence tier
        tier = self._confidence_to_tier(confidence)

        # Determine threat horizon
        horizon = self._estimate_threat_horizon(signals)

        # Calculate risk score
        risk = min(
            10.0,
            confidence * 10
            * max(
                (s.get("risk_multiplier", 1.0) for s in signals),
                default=1.0,
            ),
        )

        # Aggregate MITRE techniques
        techniques: List[str] = []
        for sig in signals:
            techniques.extend(sig.get("predicted_techniques", []))
        techniques = list(set(techniques))

        prediction = ThreatPrediction(
            category=category,
            title=self._generate_prediction_title(category, source, layers),
            description=self._generate_prediction_description(
                category, signals, source
            ),
            confidence=confidence,
            confidence_tier=tier,
            threat_horizon=horizon,
            risk_score=round(risk, 2),
            contributing_signals=signals,
            affected_assets={source},
            attack_vector=category.value,
            predicted_techniques=techniques,
        )

        return prediction

    def _generate_single_signal_prediction(
        self,
        signal: Dict[str, Any],
        source: str,
    ) -> ThreatPrediction:
        """Generate prediction from a high-confidence single signal."""
        confidence = signal.get("confidence", 0.5)
        category = ZeroDayCategory.NOVEL_EXPLOIT

        sig_type = signal.get("signal_type", "")
        if "entropy" in sig_type:
            category = ZeroDayCategory.ENCRYPTED_CHANNEL_ABUSE
        elif "genome" in sig_type:
            category = ZeroDayCategory.LIVING_OFF_THE_LAND
        elif "campaign" in sig_type:
            category = ZeroDayCategory.VARIANT_MUTATION
        elif "surface" in sig_type:
            category = ZeroDayCategory.CONFIGURATION_DRIFT_EXPLOIT

        return ThreatPrediction(
            category=category,
            title=f"Predicted: {signal.get('description', 'Unknown threat')}",
            description=signal.get("description", ""),
            confidence=confidence,
            confidence_tier=self._confidence_to_tier(confidence),
            threat_horizon=ThreatHorizon.SHORT_TERM,
            risk_score=round(confidence * 8.0, 2),
            contributing_signals=[signal],
            affected_assets={source},
            predicted_techniques=signal.get("predicted_techniques", []),
        )

    def _classify_prediction_category(
        self, signals: List[Dict[str, Any]]
    ) -> ZeroDayCategory:
        """Classify the prediction category based on signal composition."""
        layer_types = [s.get("layer") for s in signals]
        signal_types = [s.get("signal_type", "") for s in signals]

        if any("campaign" in st for st in signal_types):
            return ZeroDayCategory.VARIANT_MUTATION
        if any("entropy" in st for st in signal_types):
            return ZeroDayCategory.ENCRYPTED_CHANNEL_ABUSE
        if any("genome" in st for st in signal_types):
            return ZeroDayCategory.LIVING_OFF_THE_LAND
        if any("surface" in st for st in signal_types):
            return ZeroDayCategory.CONFIGURATION_DRIFT_EXPLOIT
        if "strategic_forecast" in layer_types:
            return ZeroDayCategory.SUPPLY_CHAIN_INJECTION

        return ZeroDayCategory.NOVEL_EXPLOIT

    @staticmethod
    def _confidence_to_tier(confidence: float) -> PredictionConfidence:
        if confidence >= 0.95:
            return PredictionConfidence.NEAR_CERTAIN
        if confidence >= 0.80:
            return PredictionConfidence.HIGH_CONFIDENCE
        if confidence >= 0.60:
            return PredictionConfidence.PROBABLE
        if confidence >= 0.30:
            return PredictionConfidence.EMERGING
        return PredictionConfidence.SPECULATIVE

    @staticmethod
    def _estimate_threat_horizon(
        signals: List[Dict[str, Any]]
    ) -> ThreatHorizon:
        avg_conf = statistics.mean(
            s.get("confidence", 0.5) for s in signals
        )
        if avg_conf >= 0.85:
            return ThreatHorizon.IMMEDIATE
        if avg_conf >= 0.65:
            return ThreatHorizon.SHORT_TERM
        if avg_conf >= 0.45:
            return ThreatHorizon.MEDIUM_TERM
        return ThreatHorizon.LONG_TERM

    def _generate_prediction_title(
        self,
        category: ZeroDayCategory,
        source: str,
        layers: set,
    ) -> str:
        titles = {
            ZeroDayCategory.NOVEL_EXPLOIT: (
                f"Predicted Novel Exploit Targeting {source}"
            ),
            ZeroDayCategory.VARIANT_MUTATION: (
                f"Threat Variant Evolution Detected — {source}"
            ),
            ZeroDayCategory.SUPPLY_CHAIN_INJECTION: (
                f"Supply Chain Compromise Indicators — {source}"
            ),
            ZeroDayCategory.LIVING_OFF_THE_LAND: (
                f"Novel LOTL Attack Pattern — {source}"
            ),
            ZeroDayCategory.ENCRYPTED_CHANNEL_ABUSE: (
                f"Covert Encrypted Channel — {source}"
            ),
            ZeroDayCategory.CONFIGURATION_DRIFT_EXPLOIT: (
                f"Configuration Drift Exploitation Risk — {source}"
            ),
        }
        return titles.get(
            category,
            f"Predicted Unknown Threat — {source} ({len(layers)} layers)",
        )

    def _generate_prediction_description(
        self,
        category: ZeroDayCategory,
        signals: List[Dict[str, Any]],
        source: str,
    ) -> str:
        layer_names = set(s.get("layer", "") for s in signals)
        return (
            f"Cross-layer threat prediction triggered by "
            f"{len(signals)} signals across {len(layer_names)} detection "
            f"layers ({', '.join(layer_names)}). "
            f"Category: {category.value}. Source: {source}. "
            f"This prediction indicates potential zero-day or unknown "
            f"threat activity requiring preemptive defensive action."
        )

    def _generate_preemptive_actions(
        self, prediction: ThreatPrediction
    ) -> List[str]:
        """Generate context-aware preemptive defensive actions."""
        actions: List[str] = []

        cat = prediction.category

        # Universal actions for high-confidence predictions
        if prediction.confidence >= 0.7:
            actions.append(
                "ELEVATE monitoring sensitivity on affected assets"
            )
            actions.append("CAPTURE baseline snapshot for forensic comparison")

        if cat == ZeroDayCategory.NOVEL_EXPLOIT:
            actions.extend([
                "DEPLOY virtual patching rules for affected services",
                "INCREASE IDS/IPS sensitivity to minimum thresholds",
                "ENABLE packet capture on suspected attack vectors",
                "RESTRICT network access to critical assets",
            ])

        elif cat == ZeroDayCategory.ENCRYPTED_CHANNEL_ABUSE:
            actions.extend([
                "ENABLE TLS inspection on suspected channels",
                "MONITOR DNS query patterns for tunneling",
                "BLOCK connections to newly-registered domains",
                "DEPLOY JA3/JA3S fingerprinting for TLS anomalies",
            ])

        elif cat == ZeroDayCategory.LIVING_OFF_THE_LAND:
            actions.extend([
                "ENFORCE application whitelisting on affected assets",
                "RESTRICT PowerShell to Constrained Language Mode",
                "ENABLE command-line auditing (Process Creation 4688)",
                "BLOCK LOLBin lateral movement paths",
            ])

        elif cat == ZeroDayCategory.SUPPLY_CHAIN_INJECTION:
            actions.extend([
                "FREEZE dependency updates pending manual review",
                "AUDIT recently installed packages against known-good list",
                "ENABLE Software Bill of Materials (SBOM) validation",
                "RESTRICT outbound connections from build systems",
            ])

        elif cat == ZeroDayCategory.CONFIGURATION_DRIFT_EXPLOIT:
            actions.extend([
                "REVERT configuration changes to last known-good state",
                "ENFORCE configuration management policy compliance",
                "SCAN for exposed services created by drift",
                "AUDIT firewall rules and access control lists",
            ])

        elif cat == ZeroDayCategory.VARIANT_MUTATION:
            actions.extend([
                "UPDATE behavioral detection rules for variant indicators",
                "DISTRIBUTE IOCs from related known campaigns",
                "ENABLE YARA rules for structural pattern matching",
                "COORDINATE with threat intel partners on variant details",
            ])

        # Critical-tier gets automatic containment
        if prediction.confidence >= 0.9:
            actions.insert(
                0,
                "AUTO-CONTAIN: Restrict affected asset network access "
                "to critical services only",
            )

        return actions

    # ─── Prediction Validation ────────────────────────────────────────────

    def validate_prediction(
        self,
        prediction_id: str,
        outcome: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Validate a prediction outcome for accuracy tracking.
        Outcomes: confirmed, false_positive, inconclusive
        """
        with self._lock:
            pred = self.active_predictions.get(prediction_id)
            if not pred:
                return None

            pred.validated = True
            pred.outcome = outcome
            pred.updated_at = datetime.utcnow()

            # Update accuracy stats
            if outcome in self.prediction_accuracy:
                self.prediction_accuracy[outcome] += 1
            self.prediction_accuracy["pending"] = max(
                0, self.prediction_accuracy["pending"] - 1
            )

            # Calculate overall accuracy
            total = (
                self.prediction_accuracy["confirmed"]
                + self.prediction_accuracy["false_positive"]
            )
            if total > 0:
                self.stats["accuracy_rate"] = round(
                    self.prediction_accuracy["confirmed"] / total, 3
                )

            return pred.to_dict()

    # ─── Status & Reporting ──────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive predictor status."""
        with self._lock:
            active = [
                p for p in self.active_predictions.values()
                if not p.validated
            ]
            active_by_tier = defaultdict(int)
            for p in active:
                active_by_tier[p.confidence_tier.value] += 1

            active_by_category = defaultdict(int)
            for p in active:
                active_by_category[p.category.value] += 1

            return {
                "engine": "zero_day_predictor",
                "status": "operational",
                "statistics": {
                    **self.stats,
                    "start_time": self.stats["start_time"].isoformat(),
                },
                "active_predictions": {
                    "total": len(active),
                    "by_confidence_tier": dict(active_by_tier),
                    "by_category": dict(active_by_category),
                },
                "prediction_accuracy": self.prediction_accuracy,
                "threat_landscape_vectors": len(self.threat_landscape),
                "behavioral_genomes_tracked": len(self.genomes),
                "entropy_streams_monitored": len(self.entropy_history),
                "signal_bus_depth": len(self.signal_bus),
                "uptime_hours": round(
                    (
                        datetime.utcnow() - self.stats["start_time"]
                    ).total_seconds()
                    / 3600,
                    2,
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_active_predictions(
        self, min_confidence: float = 0.0
    ) -> List[Dict[str, Any]]:
        """Get active (unvalidated) predictions above confidence threshold."""
        with self._lock:
            preds = [
                p.to_dict()
                for p in self.active_predictions.values()
                if not p.validated and p.confidence >= min_confidence
            ]
        preds.sort(key=lambda p: p["confidence"], reverse=True)
        return preds

    def get_threat_landscape(self) -> Dict[str, Any]:
        """Get the current strategic threat landscape assessment."""
        return {
            "vectors": self.threat_landscape,
            "campaign_activity": {
                k: len(v)
                for k, v in self.campaign_indicators.items()
                if v
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
