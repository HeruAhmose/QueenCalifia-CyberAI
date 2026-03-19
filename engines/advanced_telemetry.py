"""
QueenCalifia CyberAI — Advanced Telemetry for Zero-Day Prediction
===================================================================
Deep observability and predictive signal intelligence that amplifies
the 5-layer prediction engine with high-fidelity telemetry streams.

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                   ADVANCED TELEMETRY MATRIX                     │
    │                                                                 │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
    │  │  T1: Network  │  │  T2: Temporal │  │  T3: Kernel/Endpoint │  │
    │  │  Flow Intel   │  │  Patterns    │  │  Profiling           │  │
    │  │              │  │              │  │                      │  │
    │  │ JA3/JA4      │  │ Beaconing    │  │ Syscall freq         │  │
    │  │ DNS profiling │  │ Burst detect │  │ File I/O patterns    │  │
    │  │ Protocol dev  │  │ Dwell time   │  │ Memory anomalies     │  │
    │  │ Cert anomaly  │  │ Periodicity  │  │ Privilege transitions │  │
    │  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
    │         │                 │                      │              │
    │         ▼                 ▼                      ▼              │
    │  ┌─────────────────────────────────────────────────────────┐    │
    │  │            CROSS-ASSET CORRELATION GRAPH (T4)            │    │
    │  │  Lateral movement detection, blast radius estimation,    │    │
    │  │  communication baseline deviation, pivot chain mapping   │    │
    │  └──────────────────────┬──────────────────────────────────┘    │
    │                         │                                       │
    │  ┌──────────────────────▼──────────────────────────────────┐    │
    │  │          ADAPTIVE FEEDBACK LOOP (T5)                     │    │
    │  │  Confidence recalibration, threshold auto-tuning,        │    │
    │  │  FP suppression learning, signal weight optimization     │    │
    │  └──────────────────────┬──────────────────────────────────┘    │
    │                         │                                       │
    │  ┌──────────────────────▼──────────────────────────────────┐    │
    │  │          COLLECTION HEALTH MONITOR (T6)                  │    │
    │  │  Sensor coverage gaps, blind spot mapping, telemetry     │    │
    │  │  freshness scoring, ingestion lag, drop rate alerts      │    │
    │  └─────────────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────────────┘

Design Philosophy:
    Traditional SIEM telemetry captures WHAT happened.
    Advanced telemetry captures the WHY and WHAT'S NEXT —
    temporal cadence, behavioral fingerprints, relationship graphs,
    and adaptive feedback that learns from every prediction outcome.

    Like the mycelium network in the Tamerian Mesh, each telemetry
    stream is an independent sensory organ. Alone, each detects
    fragments. Fused together, they reveal the complete attack
    narrative before the attacker completes their kill chain.
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
from typing import Dict, Any, List, Optional, Tuple, Set, Deque
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger("queencalifia.telemetry")


# ─── Enumerations ──────────────────────────────────────────────────────────

class TelemetryStream(Enum):
    """Classification of telemetry collection streams."""
    NETWORK_FLOW = "network_flow"
    TEMPORAL_PATTERN = "temporal_pattern"
    KERNEL_ENDPOINT = "kernel_endpoint"
    CROSS_ASSET = "cross_asset"
    FEEDBACK_LOOP = "feedback_loop"
    COLLECTION_HEALTH = "collection_health"


class BeaconClassification(Enum):
    """Classification of beaconing behavior detected in temporal analysis."""
    NONE = "none"
    PERIODIC_EXACT = "periodic_exact"        # Fixed interval (C2 heartbeat)
    PERIODIC_JITTERED = "periodic_jittered"  # Interval + random jitter
    BURSTY = "bursty"                        # Clustered bursts (data staging)
    SLOW_DRIP = "slow_drip"                  # Low-and-slow exfil
    ADAPTIVE = "adaptive"                    # Changing intervals (evasive C2)


class SensorHealth(Enum):
    """Health status for telemetry collection sensors."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STALE = "stale"
    OFFLINE = "offline"
    BLIND_SPOT = "blind_spot"


# ─── Data Models ───────────────────────────────────────────────────────────

@dataclass
class NetworkFlowFingerprint:
    """TLS/protocol fingerprint for a connection."""
    fingerprint_id: str = ""
    ja3_hash: str = ""
    ja3s_hash: str = ""
    ja4_hash: str = ""
    cipher_suite: str = ""
    tls_version: str = ""
    server_name: str = ""
    certificate_chain_hash: str = ""
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    connection_count: int = 1
    known_malicious: bool = False
    reputation_score: float = 0.5  # 0.0 = known bad, 1.0 = known good


@dataclass
class BeaconProfile:
    """Temporal beaconing analysis for a communication pair."""
    source: str = ""
    destination: str = ""
    intervals: List[float] = field(default_factory=list)
    mean_interval: float = 0.0
    interval_jitter: float = 0.0       # std deviation / mean
    classification: BeaconClassification = BeaconClassification.NONE
    confidence: float = 0.0
    data_volume_per_beacon: List[int] = field(default_factory=list)
    first_detected: datetime = field(default_factory=datetime.utcnow)
    sample_count: int = 0


@dataclass
class AssetRelationship:
    """Communication relationship between two assets."""
    source_asset: str = ""
    dest_asset: str = ""
    protocols: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    total_bytes: int = 0
    connection_count: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    baseline_bytes_per_hour: float = 0.0
    baseline_connections_per_hour: float = 0.0
    is_new: bool = True  # True until baseline established


@dataclass
class SensorStatus:
    """Health status for a telemetry sensor/source."""
    sensor_id: str = ""
    sensor_type: str = ""
    last_event_at: datetime = field(default_factory=datetime.utcnow)
    events_per_minute: float = 0.0
    drop_rate: float = 0.0
    latency_ms: float = 0.0
    health: SensorHealth = SensorHealth.HEALTHY
    coverage_assets: Set[str] = field(default_factory=set)


@dataclass
class TelemetrySignal:
    """A signal generated by the telemetry analysis pipeline."""
    signal_id: str = field(
        default_factory=lambda: f"TEL-{uuid.uuid4().hex[:8].upper()}"
    )
    stream: TelemetryStream = TelemetryStream.NETWORK_FLOW
    signal_type: str = ""
    source: str = ""
    confidence: float = 0.0
    severity: str = "medium"
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    recommended_enrichment: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "stream": self.stream.value,
            "signal_type": self.signal_type,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "recommended_enrichment": self.recommended_enrichment,
        }

    def to_predictor_signal(self) -> Dict[str, Any]:
        """Convert to signal format compatible with ZeroDayPredictor signal bus."""
        return {
            "layer": f"telemetry_{self.stream.value}",
            "signal_type": self.signal_type,
            "source": self.source,
            "confidence": self.confidence,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "telemetry_signal_id": self.signal_id,
            **self.details,
        }


# ─── Advanced Telemetry Engine ──────────────────────────────────────────────

class AdvancedTelemetry:
    """
    QueenCalifia Advanced Telemetry Matrix

    Six telemetry streams that instrument, enrich, and amplify the
    5-layer zero-day prediction engine with deep signal intelligence.

    Biological analogy: If the ZeroDayPredictor is the immune system,
    Advanced Telemetry is the nervous system — it provides the
    sensory resolution, temporal awareness, and proprioceptive
    feedback that lets the immune system respond with precision.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._lock = threading.RLock()

        # ── T1: Network Flow Intelligence ──
        self.flow_fingerprints: Dict[str, NetworkFlowFingerprint] = {}
        self.dns_profiles: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=5_000)
        )
        self.protocol_baselines: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.known_bad_fingerprints: Set[str] = set()
        self._init_threat_fingerprints()

        # ── T2: Temporal Pattern Analysis ──
        self.beacon_profiles: Dict[str, BeaconProfile] = {}
        self.event_timestamps: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10_000)
        )
        self.burst_windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.dwell_time_estimates: Dict[str, Dict[str, Any]] = {}

        # ── T3: Kernel/Endpoint Telemetry ──
        self.syscall_profiles: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.syscall_baselines: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.file_io_patterns: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=5_000)
        )
        self.memory_anomalies: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.privilege_transitions: deque = deque(maxlen=10_000)

        # ── T4: Cross-Asset Correlation ──
        self.asset_graph: Dict[str, Dict[str, AssetRelationship]] = defaultdict(dict)
        self.lateral_movement_chains: deque = deque(maxlen=5_000)
        self.asset_risk_scores: Dict[str, float] = defaultdict(float)

        # ── T5: Adaptive Feedback Loop ──
        self.feedback_history: deque = deque(maxlen=10_000)
        self.layer_accuracy: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"true_positive": 0, "false_positive": 0, "total": 0}
        )
        self.threshold_adjustments: Dict[str, float] = {}
        self.suppression_rules: List[Dict[str, Any]] = []
        self.signal_weights: Dict[str, float] = defaultdict(lambda: 1.0)

        # ── T6: Collection Health ──
        self.sensors: Dict[str, SensorStatus] = {}
        self.coverage_map: Dict[str, Set[str]] = defaultdict(set)
        self.blind_spots: List[Dict[str, Any]] = []
        self.ingestion_lag: deque = deque(maxlen=1_000)

        # ── Telemetry Signal Bus ──
        self.telemetry_signals: deque = deque(maxlen=100_000)

        # ── Statistics ──
        self.stats = {
            "events_processed": 0,
            "signals_generated": 0,
            "beacons_detected": 0,
            "lateral_movements_detected": 0,
            "fingerprints_catalogued": 0,
            "blind_spots_identified": 0,
            "threshold_adjustments": 0,
            "false_positives_suppressed": 0,
            "start_time": datetime.utcnow(),
        }

        logger.info(
            "📡 Advanced Telemetry Matrix online | "
            f"6 streams active | "
            f"{len(self.known_bad_fingerprints)} threat fingerprints loaded"
        )

    # ─── Threat Fingerprint Database ───────────────────────────────────────

    def _init_threat_fingerprints(self) -> None:
        """
        Initialize known-bad TLS fingerprints (JA3 hashes).

        These are documented fingerprints associated with malware families,
        C2 frameworks, and offensive tooling. In production, this would
        be fed by threat intel feeds (Abuse.ch, JA3er.com, etc.).
        """
        self.known_bad_fingerprints = {
            # Cobalt Strike default
            "72a589da586844d7f0818ce684948eea",
            # Metasploit Meterpreter
            "5d65ea3fb1d4aa7d826733d2f2cbf228",
            # Trickbot
            "6734f37431670b3ab4292b8f60f29984",
            # Emotet
            "4d7a28d6f2263ed61de88ca66eb011e3",
            # Sliver C2
            "c12f54a3f91dc7bafd92b15ef9a5c999",
            # Havoc C2
            "3b5074b1b5d032e5620f69f9f700ff0e",
            # Brute Ratel C4
            "a5c0d6381a6f94c2e99c2dd8c8715e66",
            # Mythic C2
            "e7d705a3286e19ea42f587b344ee6865",
            # PoshC2
            "8e1ce1c7f1052e8eebd98927fc1c3adc",
            # AsyncRAT
            "a0e9f5d64349fb13191bc781f81f42e1",
            # Generic Meterpreter HTTPS
            "b386946a5a44d1ddcc843bc75336dfce",
            # Covenant C2
            "2c39ad72c90e0ca2f9c83ecb2d6b4c4c",
        }

    # ─── Primary Telemetry Pipeline ────────────────────────────────────────

    def process_event(
        self, event_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process a security event through all 6 telemetry streams.

        Returns telemetry signals that can be injected into the
        ZeroDayPredictor's signal bus for enhanced prediction accuracy.
        """
        start = time.monotonic()

        with self._lock:
            self.stats["events_processed"] += 1

        signals: List[TelemetrySignal] = []

        # T1: Network Flow Intelligence
        t1_signals = self._t1_network_flow_intel(event_data)
        signals.extend(t1_signals)

        # T2: Temporal Pattern Analysis
        t2_signals = self._t2_temporal_patterns(event_data)
        signals.extend(t2_signals)

        # T3: Kernel/Endpoint Profiling
        t3_signals = self._t3_kernel_endpoint(event_data)
        signals.extend(t3_signals)

        # T4: Cross-Asset Correlation
        t4_signals = self._t4_cross_asset_correlation(event_data)
        signals.extend(t4_signals)

        # T6: Collection Health (runs on every event to track sensor health)
        self._t6_update_collection_health(event_data)

        # Store signals
        with self._lock:
            for sig in signals:
                self.telemetry_signals.append(sig)
                self.stats["signals_generated"] += 1

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)

        return {
            "telemetry_processed": True,
            "processing_time_ms": elapsed_ms,
            "signals_generated": len(signals),
            "signals": [s.to_dict() for s in signals],
            "predictor_signals": [s.to_predictor_signal() for s in signals],
            "stream_summary": {
                "network_flow": len(t1_signals),
                "temporal_pattern": len(t2_signals),
                "kernel_endpoint": len(t3_signals),
                "cross_asset": len(t4_signals),
            },
        }

    # ─── T1: Network Flow Intelligence ─────────────────────────────────────

    def _t1_network_flow_intel(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Deep network flow analysis — TLS fingerprinting, DNS transaction
        profiling, protocol anomaly detection, certificate chain analysis.

        Detection principle: Malware and C2 frameworks have characteristic
        TLS fingerprints that persist even when IPs and domains rotate.
        JA3/JA4 fingerprinting turns encrypted traffic into a searchable
        signature space. DNS transaction patterns reveal tunneling,
        DGA activity, and covert channels.
        """
        signals: List[TelemetrySignal] = []

        # ── JA3/JA4 TLS Fingerprint Analysis ──
        ja3 = event.get("ja3_hash", "")
        ja3s = event.get("ja3s_hash", "")
        ja4 = event.get("ja4_hash", "")

        if ja3 or ja4:
            signals.extend(
                self._analyze_tls_fingerprint(event, ja3, ja3s, ja4)
            )

        # ── DNS Transaction Profiling ──
        if event.get("event_type") in ("dns_query", "dns_response"):
            signals.extend(self._analyze_dns_transaction(event))

        # ── Protocol Deviation Scoring ──
        protocol = event.get("protocol", "")
        if protocol:
            signals.extend(self._analyze_protocol_deviation(event))

        # ── Certificate Chain Anomaly Detection ──
        if event.get("cert_chain") or event.get("server_cert"):
            signals.extend(self._analyze_certificate_chain(event))

        return signals

    def _analyze_tls_fingerprint(
        self,
        event: Dict[str, Any],
        ja3: str,
        ja3s: str,
        ja4: str,
    ) -> List[TelemetrySignal]:
        """Analyze TLS fingerprints against known-bad and baseline databases."""
        signals: List[TelemetrySignal] = []
        source = event.get("source_ip", "unknown")
        dest = event.get("dest_ip", event.get("server_name", "unknown"))
        fp_key = ja3 or ja4

        with self._lock:
            # Catalogue the fingerprint
            if fp_key not in self.flow_fingerprints:
                self.flow_fingerprints[fp_key] = NetworkFlowFingerprint(
                    fingerprint_id=fp_key[:16],
                    ja3_hash=ja3,
                    ja3s_hash=ja3s,
                    ja4_hash=ja4,
                    cipher_suite=event.get("cipher_suite", ""),
                    tls_version=event.get("tls_version", ""),
                    server_name=event.get("server_name", ""),
                    certificate_chain_hash=event.get("cert_chain_hash", ""),
                )
                self.stats["fingerprints_catalogued"] += 1

                # NEW fingerprint — always noteworthy
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.NETWORK_FLOW,
                    signal_type="new_tls_fingerprint",
                    source=source,
                    confidence=0.3,
                    severity="low",
                    details={
                        "ja3": ja3, "ja3s": ja3s, "ja4": ja4,
                        "destination": dest,
                        "tls_version": event.get("tls_version", ""),
                    },
                    description=(
                        f"New TLS fingerprint observed from {source} → "
                        f"{dest} (JA3: {ja3[:16]}...)"
                    ),
                ))
            else:
                fp = self.flow_fingerprints[fp_key]
                fp.last_seen = datetime.utcnow()
                fp.connection_count += 1

            # ── Known-bad fingerprint match ──
            if ja3 in self.known_bad_fingerprints:
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.NETWORK_FLOW,
                    signal_type="malicious_tls_fingerprint",
                    source=source,
                    confidence=0.88,
                    severity="critical",
                    details={
                        "ja3": ja3,
                        "destination": dest,
                        "matched_database": "threat_fingerprint_db",
                        "known_associations": self._lookup_ja3_associations(ja3),
                    },
                    description=(
                        f"CRITICAL: Known-malicious JA3 fingerprint detected "
                        f"from {source} → {dest}. Matches C2/malware database."
                    ),
                    recommended_enrichment=[
                        "PCAP capture on source asset",
                        "Memory forensics on source host",
                        "Full TLS session reconstruction",
                        "Reverse DNS and WHOIS on destination",
                    ],
                ))

            # ── TLS version downgrade detection ──
            tls_ver = event.get("tls_version", "")
            if tls_ver and tls_ver in ("TLSv1.0", "TLSv1.1", "SSLv3"):
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.NETWORK_FLOW,
                    signal_type="tls_downgrade_detected",
                    source=source,
                    confidence=0.65,
                    severity="high",
                    details={
                        "tls_version": tls_ver,
                        "destination": dest,
                        "expected_minimum": "TLSv1.2",
                    },
                    description=(
                        f"TLS downgrade to {tls_ver} from {source} → {dest}. "
                        f"Potential MITM or legacy exploit vector."
                    ),
                ))

        return signals

    def _lookup_ja3_associations(self, ja3: str) -> List[str]:
        """Look up known malware/tool associations for a JA3 hash."""
        associations = {
            "72a589da586844d7f0818ce684948eea": ["Cobalt Strike"],
            "5d65ea3fb1d4aa7d826733d2f2cbf228": ["Metasploit Meterpreter"],
            "6734f37431670b3ab4292b8f60f29984": ["Trickbot"],
            "4d7a28d6f2263ed61de88ca66eb011e3": ["Emotet"],
            "c12f54a3f91dc7bafd92b15ef9a5c999": ["Sliver C2"],
            "3b5074b1b5d032e5620f69f9f700ff0e": ["Havoc C2"],
            "a5c0d6381a6f94c2e99c2dd8c8715e66": ["Brute Ratel C4"],
            "e7d705a3286e19ea42f587b344ee6865": ["Mythic C2"],
            "8e1ce1c7f1052e8eebd98927fc1c3adc": ["PoshC2"],
            "a0e9f5d64349fb13191bc781f81f42e1": ["AsyncRAT"],
            "b386946a5a44d1ddcc843bc75336dfce": ["Meterpreter HTTPS"],
            "2c39ad72c90e0ca2f9c83ecb2d6b4c4c": ["Covenant C2"],
        }
        return associations.get(ja3, ["Unknown threat"])

    def _analyze_dns_transaction(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        DNS transaction profiling — detect tunneling, DGA, fast-flux,
        and covert channel indicators from DNS metadata.
        """
        signals: List[TelemetrySignal] = []
        source = event.get("source_ip", "unknown")
        query_name = event.get("query_name", "")
        query_type = event.get("query_type", "A")
        response_size = event.get("response_size", 0)

        if not query_name:
            return signals

        with self._lock:
            dns_history = self.dns_profiles[source]
            dns_history.append({
                "query": query_name,
                "type": query_type,
                "response_size": response_size,
                "timestamp": datetime.utcnow().isoformat(),
            })

        # ── DGA Detection (Domain Generation Algorithm) ──
        # High entropy in domain labels + unusual length = likely DGA
        labels = query_name.split(".")
        if len(labels) >= 2:
            second_level = labels[-2]
            if len(second_level) > 12:
                # Calculate entropy of the domain label
                label_entropy = self._label_entropy(second_level)
                if label_entropy > 3.5 and len(second_level) > 16:
                    signals.append(TelemetrySignal(
                        stream=TelemetryStream.NETWORK_FLOW,
                        signal_type="dga_domain_detected",
                        source=source,
                        confidence=min(0.90, 0.4 + label_entropy * 0.1),
                        severity="high",
                        details={
                            "domain": query_name,
                            "label_entropy": round(label_entropy, 3),
                            "label_length": len(second_level),
                            "query_type": query_type,
                        },
                        description=(
                            f"Potential DGA domain from {source}: {query_name} "
                            f"(entropy={label_entropy:.2f}, len={len(second_level)})"
                        ),
                        recommended_enrichment=[
                            "Passive DNS lookup for domain history",
                            "WHOIS registration date check",
                            "Cross-reference with DGA known families",
                        ],
                    ))

        # ── DNS Tunneling Detection ──
        # TXT queries with large responses or high-entropy subdomains
        if query_type == "TXT" and response_size > 512:
            signals.append(TelemetrySignal(
                stream=TelemetryStream.NETWORK_FLOW,
                signal_type="dns_tunneling_indicator",
                source=source,
                confidence=0.70,
                severity="high",
                details={
                    "query": query_name,
                    "query_type": query_type,
                    "response_size": response_size,
                },
                description=(
                    f"DNS tunneling indicator from {source}: "
                    f"TXT query with {response_size}B response to {query_name}"
                ),
            ))

        # ── Subdomain entropy (data exfil via DNS) ──
        if len(labels) > 3:
            subdomain = ".".join(labels[:-2])
            if len(subdomain) > 30:
                sub_entropy = self._label_entropy(subdomain.replace(".", ""))
                if sub_entropy > 4.0:
                    signals.append(TelemetrySignal(
                        stream=TelemetryStream.NETWORK_FLOW,
                        signal_type="dns_exfil_subdomain",
                        source=source,
                        confidence=min(0.85, 0.3 + sub_entropy * 0.1),
                        severity="high",
                        details={
                            "query": query_name,
                            "subdomain_length": len(subdomain),
                            "subdomain_entropy": round(sub_entropy, 3),
                        },
                        description=(
                            f"High-entropy subdomain from {source} — "
                            f"potential DNS data exfiltration: {query_name}"
                        ),
                    ))

        # ── Query volume spike (per source) ──
        with self._lock:
            recent = [
                d for d in self.dns_profiles[source]
                if datetime.fromisoformat(d["timestamp"])
                > datetime.utcnow() - timedelta(minutes=1)
            ]
            if len(recent) > int(self.config.get("dns_qps_threshold", 50)):
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.NETWORK_FLOW,
                    signal_type="dns_query_flood",
                    source=source,
                    confidence=0.60,
                    severity="medium",
                    details={
                        "queries_per_minute": len(recent),
                        "threshold": self.config.get("dns_qps_threshold", 50),
                    },
                    description=(
                        f"DNS query flood from {source}: "
                        f"{len(recent)} queries/min exceeds threshold"
                    ),
                ))

        return signals

    @staticmethod
    def _label_entropy(label: str) -> float:
        """Shannon entropy of a DNS label string."""
        if not label:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in label.lower():
            freq[ch] = freq.get(ch, 0) + 1
        length = len(label)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _analyze_protocol_deviation(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Score protocol-level deviations from learned baselines.
        Detects protocol misuse, non-standard implementations,
        and covert channels riding on legitimate protocols.
        """
        signals: List[TelemetrySignal] = []
        source = event.get("source_ip", "unknown")
        protocol = event.get("protocol", "").upper()
        dest_port = event.get("dest_port", 0)
        payload_size = event.get("payload_size", event.get("bytes_out", 0))

        # Protocol-port mismatch detection
        expected_ports = {
            "HTTP": {80, 8080, 8443, 8000, 8888},
            "HTTPS": {443, 8443},
            "DNS": {53, 5353},
            "SSH": {22},
            "SMTP": {25, 465, 587},
            "RDP": {3389},
            "LDAP": {389, 636},
            "KERBEROS": {88},
        }

        if protocol in expected_ports and dest_port:
            if dest_port not in expected_ports[protocol]:
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.NETWORK_FLOW,
                    signal_type="protocol_port_mismatch",
                    source=source,
                    confidence=0.55,
                    severity="medium",
                    details={
                        "protocol": protocol,
                        "dest_port": dest_port,
                        "expected_ports": list(expected_ports[protocol]),
                    },
                    description=(
                        f"Protocol-port mismatch from {source}: "
                        f"{protocol} on port {dest_port} "
                        f"(expected {expected_ports[protocol]})"
                    ),
                ))

        # Track protocol baseline for the source
        baseline_key = f"{source}:{protocol}"
        with self._lock:
            if baseline_key in self.protocol_baselines:
                baseline = self.protocol_baselines[baseline_key]
                avg_size = baseline.get("avg_payload_size", 0)
                if avg_size > 0 and payload_size > 0:
                    ratio = payload_size / max(1, avg_size)
                    if ratio > 10.0:  # 10x normal payload
                        signals.append(TelemetrySignal(
                            stream=TelemetryStream.NETWORK_FLOW,
                            signal_type="protocol_payload_anomaly",
                            source=source,
                            confidence=min(0.80, 0.3 + ratio * 0.02),
                            severity="medium",
                            details={
                                "protocol": protocol,
                                "payload_size": payload_size,
                                "baseline_avg": round(avg_size, 0),
                                "deviation_ratio": round(ratio, 1),
                            },
                            description=(
                                f"Protocol payload anomaly from {source}: "
                                f"{protocol} payload {payload_size}B is "
                                f"{ratio:.0f}x baseline ({avg_size:.0f}B)"
                            ),
                        ))
                # Update running average
                count = baseline.get("sample_count", 1)
                baseline["avg_payload_size"] = (
                    (avg_size * count + payload_size) / (count + 1)
                )
                baseline["sample_count"] = count + 1
            else:
                self.protocol_baselines[baseline_key] = {
                    "avg_payload_size": float(payload_size),
                    "sample_count": 1,
                }

        return signals

    def _analyze_certificate_chain(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """Detect anomalous certificate chains — self-signed, short-lived, mismatched."""
        signals: List[TelemetrySignal] = []
        source = event.get("source_ip", "unknown")
        dest = event.get("dest_ip", event.get("server_name", "unknown"))

        is_self_signed = event.get("cert_self_signed", False)
        cert_age_days = event.get("cert_age_days", 365)
        cert_validity_days = event.get("cert_validity_days", 365)
        subject_cn = event.get("cert_subject_cn", "")
        server_name = event.get("server_name", "")

        if is_self_signed:
            signals.append(TelemetrySignal(
                stream=TelemetryStream.NETWORK_FLOW,
                signal_type="self_signed_certificate",
                source=source,
                confidence=0.50,
                severity="medium",
                details={
                    "destination": dest,
                    "subject_cn": subject_cn,
                },
                description=(
                    f"Self-signed certificate detected: "
                    f"{source} → {dest} (CN={subject_cn})"
                ),
            ))

        # Short-lived certificate (< 7 days) — common with Let's Encrypt abuse
        if 0 < cert_validity_days < 7:
            signals.append(TelemetrySignal(
                stream=TelemetryStream.NETWORK_FLOW,
                signal_type="short_lived_certificate",
                source=source,
                confidence=0.60,
                severity="medium",
                details={
                    "destination": dest,
                    "validity_days": cert_validity_days,
                    "cert_age_days": cert_age_days,
                },
                description=(
                    f"Short-lived certificate ({cert_validity_days}d) "
                    f"on {dest} — potential disposable C2 infrastructure"
                ),
            ))

        # CN / SNI mismatch
        if subject_cn and server_name and subject_cn != server_name:
            if not server_name.endswith(subject_cn.lstrip("*")):
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.NETWORK_FLOW,
                    signal_type="cert_cn_mismatch",
                    source=source,
                    confidence=0.55,
                    severity="medium",
                    details={
                        "subject_cn": subject_cn,
                        "server_name": server_name,
                        "destination": dest,
                    },
                    description=(
                        f"Certificate CN mismatch: CN={subject_cn} but "
                        f"SNI={server_name} on {dest}"
                    ),
                ))

        return signals

    # ─── T2: Temporal Pattern Analysis ─────────────────────────────────────

    def _t2_temporal_patterns(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Time-series intelligence — detect beaconing, burst patterns,
        periodicity anomalies, and dwell time indicators.

        Detection principle: C2 frameworks beacon at intervals.
        Data staging creates burst patterns. Dwell time between
        compromise and action reveals adversary sophistication.
        Even jittered beaconing has statistical signatures that
        betray the underlying periodicity.
        """
        signals: List[TelemetrySignal] = []
        source = event.get("source_ip", "unknown")
        dest = event.get("dest_ip", event.get("server_name", "unknown"))
        now = datetime.utcnow()

        # Record event timestamp for this communication pair
        pair_key = f"{source}->{dest}"
        with self._lock:
            timestamps = self.event_timestamps[pair_key]
            timestamps.append(now.timestamp())

        # ── Beaconing Detection ──
        beacon_signal = self._detect_beaconing(pair_key, source, dest)
        if beacon_signal:
            signals.append(beacon_signal)

        # ── Burst Detection ──
        burst_signal = self._detect_burst_pattern(
            pair_key, source, dest, event
        )
        if burst_signal:
            signals.append(burst_signal)

        # ── Time-of-Day Anomaly ──
        tod_signal = self._detect_time_anomaly(source, now, event)
        if tod_signal:
            signals.append(tod_signal)

        return signals

    def _detect_beaconing(
        self, pair_key: str, source: str, dest: str
    ) -> Optional[TelemetrySignal]:
        """
        Statistical beaconing detection using interval analysis.

        Method: Compute inter-arrival intervals, calculate coefficient
        of variation (CV = stdev / mean). True beacons have low CV
        (< 0.3 for exact, < 0.5 for jittered). Random traffic has
        CV > 1.0 typically.
        """
        with self._lock:
            timestamps = list(self.event_timestamps[pair_key])

        if len(timestamps) < 10:
            return None

        # Compute inter-arrival intervals
        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        # Filter out very short intervals (< 1s) — likely retransmissions
        intervals = [i for i in intervals if i >= 1.0]

        if len(intervals) < 8:
            return None

        mean_interval = statistics.mean(intervals)
        if mean_interval < 2.0:
            return None  # Too frequent to be meaningful beaconing

        stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

        # Classify beaconing behavior
        classification = BeaconClassification.NONE
        confidence = 0.0

        if cv < 0.10:
            classification = BeaconClassification.PERIODIC_EXACT
            confidence = 0.92
        elif cv < 0.30:
            classification = BeaconClassification.PERIODIC_JITTERED
            confidence = 0.80
        elif cv < 0.50 and mean_interval > 30:
            classification = BeaconClassification.ADAPTIVE
            confidence = 0.65
        elif 20 < mean_interval < 600 and cv < 0.60:
            classification = BeaconClassification.SLOW_DRIP
            confidence = 0.55

        if classification == BeaconClassification.NONE:
            return None

        # Update beacon profile
        with self._lock:
            self.beacon_profiles[pair_key] = BeaconProfile(
                source=source,
                destination=dest,
                intervals=intervals[-50:],  # Keep last 50
                mean_interval=round(mean_interval, 2),
                interval_jitter=round(cv, 4),
                classification=classification,
                confidence=confidence,
                sample_count=len(timestamps),
            )
            self.stats["beacons_detected"] += 1

        severity = "critical" if classification in (
            BeaconClassification.PERIODIC_EXACT,
            BeaconClassification.PERIODIC_JITTERED,
        ) else "high"

        return TelemetrySignal(
            stream=TelemetryStream.TEMPORAL_PATTERN,
            signal_type="beaconing_detected",
            source=source,
            confidence=confidence,
            severity=severity,
            details={
                "destination": dest,
                "classification": classification.value,
                "mean_interval_seconds": round(mean_interval, 2),
                "interval_cv": round(cv, 4),
                "sample_count": len(timestamps),
                "intervals_analyzed": len(intervals),
            },
            description=(
                f"Beaconing detected: {source} → {dest} | "
                f"Type: {classification.value} | "
                f"Interval: {mean_interval:.1f}s (CV={cv:.3f}) | "
                f"Samples: {len(timestamps)}"
            ),
            recommended_enrichment=[
                "Full PCAP capture on this communication pair",
                "Payload entropy analysis on beacon payloads",
                "Correlate destination with threat intel feeds",
                "Check for data volume asymmetry (exfil indicator)",
            ],
        )

    def _detect_burst_pattern(
        self,
        pair_key: str,
        source: str,
        dest: str,
        event: Dict[str, Any],
    ) -> Optional[TelemetrySignal]:
        """
        Detect data staging / burst exfiltration patterns.

        Pattern: Quiet period → sudden high-volume transfer → quiet.
        Characteristic of data staging before exfil or batch C2 tasking.
        """
        bytes_out = event.get("bytes_out", 0)
        if bytes_out < 1000:
            return None

        now = datetime.utcnow()

        with self._lock:
            bursts = self.burst_windows[pair_key]
            bursts.append({
                "bytes": bytes_out,
                "timestamp": now.timestamp(),
            })

            # Keep only last 5 minutes
            cutoff = now.timestamp() - 300
            bursts[:] = [b for b in bursts if b["timestamp"] > cutoff]

            if len(bursts) < 5:
                return None

            # Check for burst pattern: high transfer rate in short window
            total_bytes = sum(b["bytes"] for b in bursts)
            time_span = bursts[-1]["timestamp"] - bursts[0]["timestamp"]

            if time_span < 1:
                return None

            bytes_per_second = total_bytes / time_span

        # Burst threshold: >1MB/s concentrated in <60s window
        if bytes_per_second > 1_000_000 and time_span < 60:
            return TelemetrySignal(
                stream=TelemetryStream.TEMPORAL_PATTERN,
                signal_type="data_burst_detected",
                source=source,
                confidence=0.60,
                severity="high",
                details={
                    "destination": dest,
                    "total_bytes": total_bytes,
                    "duration_seconds": round(time_span, 1),
                    "bytes_per_second": round(bytes_per_second, 0),
                    "event_count": len(bursts),
                },
                description=(
                    f"Data burst from {source} → {dest}: "
                    f"{total_bytes / 1_000_000:.1f}MB in {time_span:.0f}s "
                    f"({bytes_per_second / 1_000_000:.1f} MB/s)"
                ),
            )

        return None

    def _detect_time_anomaly(
        self,
        source: str,
        now: datetime,
        event: Dict[str, Any],
    ) -> Optional[TelemetrySignal]:
        """
        Detect activity outside normal operating hours.
        Tracks per-asset activity patterns and flags deviations.
        """
        hour = now.hour
        asset = event.get("asset_id", source)
        event_type = event.get("event_type", "")

        # Define suspicious hours (configurable)
        off_hours_start = int(self.config.get("off_hours_start", 22))
        off_hours_end = int(self.config.get("off_hours_end", 5))

        is_off_hours = (
            hour >= off_hours_start or hour < off_hours_end
        )

        # Only flag significant events during off-hours
        significant_events = {
            "process_start", "config_change", "auth_success",
            "file_download", "service_discovered", "lateral_movement",
        }

        if is_off_hours and event_type in significant_events:
            return TelemetrySignal(
                stream=TelemetryStream.TEMPORAL_PATTERN,
                signal_type="off_hours_activity",
                source=source,
                confidence=0.40,
                severity="low",
                details={
                    "asset": asset,
                    "event_type": event_type,
                    "hour": hour,
                    "off_hours_range": f"{off_hours_start}:00-{off_hours_end}:00",
                },
                description=(
                    f"Off-hours activity on {asset}: {event_type} at "
                    f"{hour:02d}:00 (outside {off_hours_end}:00-{off_hours_start}:00)"
                ),
            )

        return None

    # ─── T3: Kernel/Endpoint Telemetry ─────────────────────────────────────

    def _t3_kernel_endpoint(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Kernel-level telemetry — syscall frequency analysis, file I/O
        pattern recognition, memory access anomalies, privilege transitions.

        Detection principle: Exploitation and post-exploitation leave
        distinctive footprints at the kernel level — unusual syscall
        patterns, anomalous file I/O sequences, memory injection
        artifacts, and privilege escalation chains that are nearly
        impossible to fully mask.
        """
        signals: List[TelemetrySignal] = []

        # ── Syscall Frequency Analysis ──
        if event.get("syscalls") or event.get("syscall_name"):
            signals.extend(self._analyze_syscall_patterns(event))

        # ── File I/O Pattern Recognition ──
        if event.get("event_type") in (
            "file_create", "file_modify", "file_delete",
            "file_rename", "file_read", "file_write",
        ):
            signals.extend(self._analyze_file_io(event))

        # ── Memory Anomaly Detection ──
        if event.get("memory_event") or event.get("event_type") in (
            "memory_injection", "rwx_allocation", "hollowed_process",
        ):
            signals.extend(self._analyze_memory_anomaly(event))

        # ── Privilege Transition Tracking ──
        if event.get("event_type") in (
            "privilege_escalation", "token_manipulation",
            "runas", "sudo", "setuid",
        ):
            signals.extend(self._analyze_privilege_transition(event))

        return signals

    def _analyze_syscall_patterns(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Profile syscall frequencies per process and detect anomalies.

        Key indicators:
        - Spike in NtWriteVirtualMemory → process injection
        - NtMapViewOfSection + NtCreateThreadEx → DLL injection
        - High rate of NtOpenProcess → credential dumping / proc scanning
        - NtQuerySystemInformation bursts → reconnaissance
        """
        signals: List[TelemetrySignal] = []
        asset = event.get("asset_id", event.get("hostname", "unknown"))
        process = event.get("process_name", "unknown")
        profile_key = f"{asset}:{process}"

        # Process bulk syscall data
        syscalls = event.get("syscalls", {})
        if isinstance(syscalls, dict):
            with self._lock:
                for name, count in syscalls.items():
                    self.syscall_profiles[profile_key][name] += count

        # Single syscall event
        syscall_name = event.get("syscall_name", "")
        if syscall_name:
            with self._lock:
                self.syscall_profiles[profile_key][syscall_name] += 1

        # ── Injection pattern detection ──
        injection_syscalls = {
            "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
            "NtCreateThreadEx", "NtMapViewOfSection",
            "WriteProcessMemory", "VirtualAllocEx",
            "CreateRemoteThread", "NtQueueApcThread",
        }

        with self._lock:
            profile = self.syscall_profiles[profile_key]
            injection_count = sum(
                profile.get(sc, 0) for sc in injection_syscalls
            )

        if injection_count > int(self.config.get("injection_syscall_threshold", 10)):
            signals.append(TelemetrySignal(
                stream=TelemetryStream.KERNEL_ENDPOINT,
                signal_type="injection_syscall_pattern",
                source=asset,
                confidence=min(0.90, 0.5 + injection_count * 0.02),
                severity="critical",
                details={
                    "process": process,
                    "injection_syscall_count": injection_count,
                    "syscall_breakdown": {
                        sc: profile.get(sc, 0)
                        for sc in injection_syscalls
                        if profile.get(sc, 0) > 0
                    },
                },
                description=(
                    f"Process injection syscall pattern on {asset}: "
                    f"{process} made {injection_count} injection-related "
                    f"syscalls"
                ),
                recommended_enrichment=[
                    "Memory dump of target processes",
                    "Volatile memory forensics",
                    "Process hollowing detection scan",
                    "Thread start address validation",
                ],
            ))

        # ── Credential access pattern ──
        cred_syscalls = {
            "NtOpenProcess", "NtReadVirtualMemory",
            "MiniDumpWriteDump", "LsaRetrievePrivateData",
        }
        cred_count = sum(profile.get(sc, 0) for sc in cred_syscalls)

        if cred_count > int(self.config.get("cred_syscall_threshold", 20)):
            signals.append(TelemetrySignal(
                stream=TelemetryStream.KERNEL_ENDPOINT,
                signal_type="credential_access_pattern",
                source=asset,
                confidence=min(0.85, 0.4 + cred_count * 0.015),
                severity="high",
                details={
                    "process": process,
                    "credential_syscall_count": cred_count,
                },
                description=(
                    f"Credential access syscall pattern on {asset}: "
                    f"{process} — {cred_count} suspicious syscalls"
                ),
            ))

        return signals

    def _analyze_file_io(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        File I/O pattern recognition — detect ransomware encryption
        patterns, mass file access (exfil staging), and suspicious
        file creation sequences.
        """
        signals: List[TelemetrySignal] = []
        asset = event.get("asset_id", event.get("hostname", "unknown"))
        file_path = event.get("file_path", "")
        operation = event.get("event_type", "")
        process = event.get("process_name", "unknown")

        with self._lock:
            io_history = self.file_io_patterns[asset]
            io_history.append({
                "operation": operation,
                "file_path": file_path,
                "process": process,
                "timestamp": datetime.utcnow().timestamp(),
            })

            # ── Ransomware pattern: rapid read → write → rename/delete ──
            recent = [
                e for e in io_history
                if e["timestamp"] > datetime.utcnow().timestamp() - 30
            ]

        if len(recent) > 20:
            ops = [r["operation"] for r in recent]
            # Count unique files touched
            unique_files = len(set(r["file_path"] for r in recent))

            # Ransomware heuristic: many files, mixed read/write/rename
            read_count = ops.count("file_read")
            write_count = ops.count("file_write") + ops.count("file_modify")
            rename_count = ops.count("file_rename")
            delete_count = ops.count("file_delete")

            # Pattern: reads ≈ writes, high rename count, many unique files
            if (
                unique_files > 15
                and write_count > 10
                and rename_count > 5
                and abs(read_count - write_count) < write_count * 0.5
            ):
                confidence = min(
                    0.95,
                    0.5 + unique_files * 0.01 + rename_count * 0.02,
                )
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.KERNEL_ENDPOINT,
                    signal_type="ransomware_file_pattern",
                    source=asset,
                    confidence=confidence,
                    severity="critical",
                    details={
                        "process": process,
                        "unique_files_touched": unique_files,
                        "reads": read_count,
                        "writes": write_count,
                        "renames": rename_count,
                        "deletes": delete_count,
                        "window_seconds": 30,
                    },
                    description=(
                        f"CRITICAL: Ransomware file I/O pattern on {asset} "
                        f"by {process} — {unique_files} files "
                        f"(R:{read_count}/W:{write_count}/RN:{rename_count}) "
                        f"in 30s window"
                    ),
                    recommended_enrichment=[
                        "IMMEDIATE: Isolate asset from network",
                        "Snapshot filesystem state NOW",
                        "Check for ransom note artifacts",
                        "Identify encryption algorithm from file headers",
                    ],
                ))

            # ── Mass file access (exfil staging) ──
            elif unique_files > 50 and read_count > 40:
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.KERNEL_ENDPOINT,
                    signal_type="mass_file_access",
                    source=asset,
                    confidence=0.55,
                    severity="high",
                    details={
                        "process": process,
                        "unique_files": unique_files,
                        "reads": read_count,
                        "window_seconds": 30,
                    },
                    description=(
                        f"Mass file access on {asset} by {process}: "
                        f"{unique_files} files read in 30s — "
                        f"potential data staging"
                    ),
                ))

        # ── Suspicious file extension creation ──
        if operation in ("file_create", "file_rename"):
            suspicious_extensions = {
                ".encrypted", ".locked", ".crypt", ".enc",
                ".ransom", ".pay", ".zepto", ".cerber",
                ".locky", ".wallet", ".onion",
            }
            for ext in suspicious_extensions:
                if file_path.lower().endswith(ext):
                    signals.append(TelemetrySignal(
                        stream=TelemetryStream.KERNEL_ENDPOINT,
                        signal_type="ransomware_extension_created",
                        source=asset,
                        confidence=0.75,
                        severity="critical",
                        details={
                            "file_path": file_path,
                            "extension": ext,
                            "process": process,
                            "operation": operation,
                        },
                        description=(
                            f"Ransomware file extension on {asset}: "
                            f"{file_path} created by {process}"
                        ),
                    ))
                    break

        return signals

    def _analyze_memory_anomaly(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Detect memory-based attack indicators — RWX allocations,
        process hollowing, reflective DLL injection, shellcode patterns.
        """
        signals: List[TelemetrySignal] = []
        asset = event.get("asset_id", event.get("hostname", "unknown"))
        event_type = event.get("event_type", event.get("memory_event", ""))
        process = event.get("process_name", "unknown")

        if event_type == "rwx_allocation":
            size = event.get("allocation_size", 0)
            signals.append(TelemetrySignal(
                stream=TelemetryStream.KERNEL_ENDPOINT,
                signal_type="rwx_memory_allocation",
                source=asset,
                confidence=0.65,
                severity="high",
                details={
                    "process": process,
                    "allocation_size": size,
                    "target_process": event.get("target_process", process),
                    "is_remote": event.get("is_remote", False),
                },
                description=(
                    f"RWX memory allocation on {asset}: "
                    f"{process} allocated {size}B executable memory"
                    f"{' in remote process' if event.get('is_remote') else ''}"
                ),
            ))

        if event_type == "hollowed_process":
            signals.append(TelemetrySignal(
                stream=TelemetryStream.KERNEL_ENDPOINT,
                signal_type="process_hollowing_detected",
                source=asset,
                confidence=0.90,
                severity="critical",
                details={
                    "process": process,
                    "target_process": event.get("target_process", ""),
                    "original_image": event.get("original_image", ""),
                    "injected_image_hash": event.get("injected_hash", ""),
                },
                description=(
                    f"CRITICAL: Process hollowing on {asset}: "
                    f"{process} → {event.get('target_process', 'unknown')}"
                ),
                recommended_enrichment=[
                    "Memory dump of hollowed process",
                    "Extract injected payload for analysis",
                    "Check for persistence mechanisms",
                    "Map full process tree from hollowed PID",
                ],
            ))

        if event_type == "memory_injection":
            signals.append(TelemetrySignal(
                stream=TelemetryStream.KERNEL_ENDPOINT,
                signal_type="memory_injection_detected",
                source=asset,
                confidence=0.80,
                severity="critical",
                details={
                    "process": process,
                    "injection_type": event.get("injection_type", "unknown"),
                    "target_process": event.get("target_process", ""),
                },
                description=(
                    f"Memory injection on {asset}: {process} injected "
                    f"into {event.get('target_process', 'unknown')} "
                    f"via {event.get('injection_type', 'unknown')}"
                ),
            ))

        return signals

    def _analyze_privilege_transition(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """Track privilege escalation chains across assets."""
        signals: List[TelemetrySignal] = []
        asset = event.get("asset_id", event.get("hostname", "unknown"))
        user_from = event.get("user_from", event.get("source_user", ""))
        user_to = event.get("user_to", event.get("target_user", ""))
        method = event.get("event_type", "")
        process = event.get("process_name", "")

        transition = {
            "asset": asset,
            "user_from": user_from,
            "user_to": user_to,
            "method": method,
            "process": process,
            "timestamp": datetime.utcnow().isoformat(),
        }

        with self._lock:
            self.privilege_transitions.append(transition)

            # Check for privilege escalation chain: user → admin → system
            recent = [
                t for t in self.privilege_transitions
                if t["asset"] == asset
                and datetime.fromisoformat(t["timestamp"])
                > datetime.utcnow() - timedelta(minutes=30)
            ]

        # Multiple escalations on same asset in short window
        if len(recent) >= 3:
            unique_targets = set(t["user_to"] for t in recent)
            admin_targets = {
                u for u in unique_targets
                if any(kw in u.lower() for kw in (
                    "admin", "root", "system", "nt authority",
                    "localsystem", "networkservice",
                ))
            }

            if admin_targets:
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.KERNEL_ENDPOINT,
                    signal_type="privilege_escalation_chain",
                    source=asset,
                    confidence=min(0.85, 0.5 + len(recent) * 0.1),
                    severity="critical",
                    details={
                        "escalation_count": len(recent),
                        "unique_target_accounts": list(unique_targets),
                        "admin_accounts_reached": list(admin_targets),
                        "window_minutes": 30,
                        "latest_method": method,
                    },
                    description=(
                        f"Privilege escalation chain on {asset}: "
                        f"{len(recent)} escalations in 30min, "
                        f"admin accounts reached: {admin_targets}"
                    ),
                ))

        # Single escalation to high-privilege account
        high_priv_keywords = {"system", "root", "nt authority", "localsystem"}
        if user_to and any(kw in user_to.lower() for kw in high_priv_keywords):
            signals.append(TelemetrySignal(
                stream=TelemetryStream.KERNEL_ENDPOINT,
                signal_type="high_privilege_transition",
                source=asset,
                confidence=0.60,
                severity="high",
                details={
                    "user_from": user_from,
                    "user_to": user_to,
                    "method": method,
                    "process": process,
                },
                description=(
                    f"High-privilege transition on {asset}: "
                    f"{user_from} → {user_to} via {method}"
                ),
            ))

        return signals

    # ─── T4: Cross-Asset Correlation ───────────────────────────────────────

    def _t4_cross_asset_correlation(
        self, event: Dict[str, Any]
    ) -> List[TelemetrySignal]:
        """
        Build and analyze the inter-asset communication graph to detect
        lateral movement, blast radius expansion, and pivot chains.

        Biological analogy: Like tracking pathogen spread through a
        population — mapping which hosts communicate, when, how much,
        and detecting when the pattern shifts to reveal an adversary
        moving laterally through the network.
        """
        signals: List[TelemetrySignal] = []
        source = event.get("source_ip", event.get("asset_id", ""))
        dest = event.get("dest_ip", event.get("target_asset", ""))

        if not source or not dest or source == dest:
            return signals

        protocol = event.get("protocol", "unknown")
        dest_port = event.get("dest_port", 0)
        bytes_transferred = event.get("bytes_out", 0) + event.get("bytes_in", 0)

        # ── Update asset relationship graph ──
        with self._lock:
            if dest not in self.asset_graph[source]:
                self.asset_graph[source][dest] = AssetRelationship(
                    source_asset=source,
                    dest_asset=dest,
                )
                # New communication pair — always worth noting
                is_new_pair = True
            else:
                is_new_pair = False

            rel = self.asset_graph[source][dest]
            rel.protocols.add(protocol)
            if dest_port:
                rel.ports.add(dest_port)
            rel.total_bytes += bytes_transferred
            rel.connection_count += 1
            rel.last_seen = datetime.utcnow()

        # ── New lateral communication detection ──
        if is_new_pair:
            # Check if source is already under suspicion
            source_risk = self.asset_risk_scores.get(source, 0)
            if source_risk > 0.5:
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.CROSS_ASSET,
                    signal_type="lateral_movement_from_suspect",
                    source=source,
                    confidence=min(0.85, 0.5 + source_risk * 0.3),
                    severity="critical",
                    details={
                        "source_risk_score": round(source_risk, 2),
                        "destination": dest,
                        "protocol": protocol,
                        "dest_port": dest_port,
                    },
                    description=(
                        f"Suspected lateral movement: high-risk asset "
                        f"{source} (risk={source_risk:.2f}) initiated "
                        f"new connection to {dest} via {protocol}:{dest_port}"
                    ),
                    recommended_enrichment=[
                        "Isolate destination asset for inspection",
                        "Capture authentication logs for dest asset",
                        "Check for credential usage on new target",
                        "Map full lateral movement chain",
                    ],
                ))

            # Check for suspicious port usage on new pair
            lateral_ports = {445, 135, 3389, 5985, 5986, 22, 139}
            if dest_port in lateral_ports:
                signals.append(TelemetrySignal(
                    stream=TelemetryStream.CROSS_ASSET,
                    signal_type="new_lateral_protocol",
                    source=source,
                    confidence=0.50,
                    severity="medium",
                    details={
                        "destination": dest,
                        "protocol": protocol,
                        "dest_port": dest_port,
                        "known_lateral_port": True,
                    },
                    description=(
                        f"New communication pair {source} → {dest} "
                        f"using lateral movement port {dest_port}"
                    ),
                ))

        # ── Blast radius estimation ──
        blast_signal = self._estimate_blast_radius(source)
        if blast_signal:
            signals.append(blast_signal)

        return signals

    def _estimate_blast_radius(
        self, source: str
    ) -> Optional[TelemetrySignal]:
        """
        Estimate the blast radius if a given asset is compromised.
        Based on the communication graph — how many assets are
        reachable within N hops?
        """
        with self._lock:
            direct_targets = set(self.asset_graph.get(source, {}).keys())

        if len(direct_targets) < 5:
            return None

        # 2-hop reachability
        two_hop = set()
        with self._lock:
            for target in direct_targets:
                two_hop.update(self.asset_graph.get(target, {}).keys())
        two_hop.discard(source)
        two_hop -= direct_targets

        total_reachable = len(direct_targets) + len(two_hop)

        blast_threshold = int(self.config.get("blast_radius_threshold", 20))

        if total_reachable >= blast_threshold:
            risk_score = min(1.0, total_reachable / 100)
            with self._lock:
                self.asset_risk_scores[source] = max(
                    self.asset_risk_scores.get(source, 0), risk_score
                )

            return TelemetrySignal(
                stream=TelemetryStream.CROSS_ASSET,
                signal_type="high_blast_radius",
                source=source,
                confidence=0.45,
                severity="high" if total_reachable > 50 else "medium",
                details={
                    "direct_targets": len(direct_targets),
                    "two_hop_reachable": len(two_hop),
                    "total_blast_radius": total_reachable,
                    "risk_score": round(risk_score, 2),
                },
                description=(
                    f"High blast radius for {source}: "
                    f"{len(direct_targets)} direct + {len(two_hop)} 2-hop = "
                    f"{total_reachable} reachable assets"
                ),
            )

        return None

    # ─── T5: Adaptive Feedback Loop ────────────────────────────────────────

    def record_prediction_outcome(
        self,
        prediction_id: str,
        outcome: str,
        contributing_layers: List[str],
        signal_types: List[str],
    ) -> Dict[str, Any]:
        """
        Record a prediction outcome to calibrate detection sensitivity.

        This is the learning mechanism: when a prediction is confirmed
        or false-positived, the feedback loop adjusts signal weights
        and thresholds to improve future accuracy.

        Like a biological immune system's memory B-cells — each
        encounter makes future detection more precise.
        """
        adjustments_made: List[str] = []

        with self._lock:
            self.feedback_history.append({
                "prediction_id": prediction_id,
                "outcome": outcome,
                "layers": contributing_layers,
                "signal_types": signal_types,
                "timestamp": datetime.utcnow().isoformat(),
            })

            for layer in contributing_layers:
                self.layer_accuracy[layer]["total"] += 1
                if outcome == "confirmed":
                    self.layer_accuracy[layer]["true_positive"] += 1
                elif outcome == "false_positive":
                    self.layer_accuracy[layer]["false_positive"] += 1

            # ── Adaptive Threshold Adjustment ──
            for layer in contributing_layers:
                acc = self.layer_accuracy[layer]
                total = acc["total"]

                if total < 10:
                    continue  # Not enough data to adjust

                fp_rate = acc["false_positive"] / max(1, total)

                # If FP rate is high, INCREASE thresholds (less sensitive)
                if fp_rate > 0.40:
                    adjustment = 1.0 + (fp_rate - 0.40) * 0.5
                    self.threshold_adjustments[layer] = adjustment
                    adjustments_made.append(
                        f"{layer}: sensitivity decreased by "
                        f"{(adjustment - 1) * 100:.0f}% (FP rate: {fp_rate:.0%})"
                    )
                    self.stats["threshold_adjustments"] += 1

                # If FP rate is low and TP rate high, DECREASE thresholds
                elif fp_rate < 0.10 and total > 20:
                    tp_rate = acc["true_positive"] / max(1, total)
                    if tp_rate > 0.7:
                        adjustment = 1.0 - (tp_rate - 0.7) * 0.3
                        self.threshold_adjustments[layer] = max(0.5, adjustment)
                        adjustments_made.append(
                            f"{layer}: sensitivity increased by "
                            f"{(1 - adjustment) * 100:.0f}% "
                            f"(TP rate: {tp_rate:.0%})"
                        )
                        self.stats["threshold_adjustments"] += 1

            # ── Signal Weight Optimization ──
            for sig_type in signal_types:
                if outcome == "confirmed":
                    self.signal_weights[sig_type] = min(
                        2.0, self.signal_weights[sig_type] * 1.05
                    )
                elif outcome == "false_positive":
                    self.signal_weights[sig_type] = max(
                        0.3, self.signal_weights[sig_type] * 0.90
                    )

            # ── FP Suppression Rule Generation ──
            if outcome == "false_positive":
                # Check if this signal_type has > 3 FPs in 24h
                recent_fps = [
                    f for f in self.feedback_history
                    if f["outcome"] == "false_positive"
                    and set(f["signal_types"]) & set(signal_types)
                    and datetime.fromisoformat(f["timestamp"])
                    > datetime.utcnow() - timedelta(hours=24)
                ]
                if len(recent_fps) >= 3:
                    rule = {
                        "signal_types": signal_types,
                        "suppression_factor": 0.5,
                        "reason": f"Auto-suppressed: {len(recent_fps)} FPs in 24h",
                        "created_at": datetime.utcnow().isoformat(),
                        "expires_at": (
                            datetime.utcnow() + timedelta(hours=72)
                        ).isoformat(),
                    }
                    self.suppression_rules.append(rule)
                    self.stats["false_positives_suppressed"] += 1
                    adjustments_made.append(
                        f"Suppression rule created for {signal_types}"
                    )

        return {
            "prediction_id": prediction_id,
            "outcome": outcome,
            "adjustments_made": adjustments_made,
            "layer_accuracy": dict(self.layer_accuracy),
            "active_threshold_adjustments": dict(self.threshold_adjustments),
            "active_suppression_rules": len(self.suppression_rules),
        }

    def get_signal_weight(self, signal_type: str) -> float:
        """Get the current adaptive weight for a signal type."""
        weight = self.signal_weights.get(signal_type, 1.0)

        # Apply suppression rules
        for rule in self.suppression_rules:
            if signal_type in rule.get("signal_types", []):
                expires = datetime.fromisoformat(rule["expires_at"])
                if datetime.utcnow() < expires:
                    weight *= rule["suppression_factor"]

        return weight

    def get_threshold_adjustment(self, layer: str) -> float:
        """Get the current threshold adjustment multiplier for a layer."""
        return self.threshold_adjustments.get(layer, 1.0)

    # ─── T6: Collection Health Monitor ─────────────────────────────────────

    def _t6_update_collection_health(
        self, event: Dict[str, Any]
    ) -> None:
        """
        Track sensor health, coverage gaps, and telemetry freshness.

        Without healthy collection, prediction is blind. This stream
        monitors the monitoring — ensuring no blind spots develop
        that an adversary could exploit.
        """
        sensor_id = event.get("sensor_id", event.get("source_sensor", ""))
        sensor_type = event.get("sensor_type", "")
        asset = event.get("asset_id", event.get("hostname", ""))

        if not sensor_id:
            return

        now = datetime.utcnow()

        with self._lock:
            if sensor_id not in self.sensors:
                self.sensors[sensor_id] = SensorStatus(
                    sensor_id=sensor_id,
                    sensor_type=sensor_type,
                )

            sensor = self.sensors[sensor_id]

            # Calculate events per minute (rolling window)
            time_delta = (now - sensor.last_event_at).total_seconds()
            if time_delta > 0 and time_delta < 300:
                sensor.events_per_minute = 60.0 / time_delta
            sensor.last_event_at = now

            # Update coverage
            if asset:
                sensor.coverage_assets.add(asset)
                self.coverage_map[sensor_type].add(asset)

            # Track ingestion lag
            event_time_str = event.get("event_timestamp", "")
            if event_time_str:
                try:
                    event_time = datetime.fromisoformat(
                        event_time_str.replace("Z", "+00:00").replace("+00:00", "")
                    )
                    lag_ms = (now - event_time).total_seconds() * 1000
                    sensor.latency_ms = lag_ms
                    self.ingestion_lag.append({
                        "sensor_id": sensor_id,
                        "lag_ms": lag_ms,
                        "timestamp": now.isoformat(),
                    })
                except (ValueError, TypeError):
                    pass

    def check_collection_health(self) -> Dict[str, Any]:
        """
        Comprehensive health check across all telemetry sensors.

        Returns health status, coverage gaps, and blind spot alerts.
        """
        now = datetime.utcnow()
        health_report: Dict[str, Any] = {
            "timestamp": now.isoformat(),
            "sensors": {},
            "blind_spots": [],
            "coverage_summary": {},
            "overall_health": "healthy",
        }

        degraded_count = 0
        offline_count = 0

        with self._lock:
            for sensor_id, sensor in self.sensors.items():
                staleness = (now - sensor.last_event_at).total_seconds()

                # Classify health
                if staleness > 600:  # 10 min
                    sensor.health = SensorHealth.OFFLINE
                    offline_count += 1
                elif staleness > 120:  # 2 min
                    sensor.health = SensorHealth.STALE
                    degraded_count += 1
                elif sensor.latency_ms > 5000:  # 5s lag
                    sensor.health = SensorHealth.DEGRADED
                    degraded_count += 1
                else:
                    sensor.health = SensorHealth.HEALTHY

                health_report["sensors"][sensor_id] = {
                    "sensor_type": sensor.sensor_type,
                    "health": sensor.health.value,
                    "last_event_seconds_ago": round(staleness, 0),
                    "events_per_minute": round(sensor.events_per_minute, 1),
                    "latency_ms": round(sensor.latency_ms, 0),
                    "coverage_asset_count": len(sensor.coverage_assets),
                }

            # Coverage gap analysis
            all_known_assets = set()
            for assets in self.coverage_map.values():
                all_known_assets.update(assets)

            expected_sensor_types = {
                "network", "endpoint", "dns", "auth", "file_integrity",
            }
            for stype in expected_sensor_types:
                covered = self.coverage_map.get(stype, set())
                uncovered = all_known_assets - covered
                if uncovered:
                    blind_spot = {
                        "sensor_type": stype,
                        "uncovered_assets": list(uncovered)[:20],
                        "uncovered_count": len(uncovered),
                        "total_known_assets": len(all_known_assets),
                        "coverage_percentage": round(
                            len(covered) / max(1, len(all_known_assets)) * 100, 1
                        ),
                    }
                    health_report["blind_spots"].append(blind_spot)
                    self.stats["blind_spots_identified"] += 1

            health_report["coverage_summary"] = {
                stype: {
                    "assets_covered": len(assets),
                    "total_known": len(all_known_assets),
                    "coverage_pct": round(
                        len(assets) / max(1, len(all_known_assets)) * 100, 1
                    ),
                }
                for stype, assets in self.coverage_map.items()
            }

        # Overall health determination
        total_sensors = len(health_report["sensors"])
        if offline_count > total_sensors * 0.3:
            health_report["overall_health"] = "critical"
        elif degraded_count + offline_count > total_sensors * 0.2:
            health_report["overall_health"] = "degraded"
        elif health_report["blind_spots"]:
            health_report["overall_health"] = "blind_spots_detected"

        return health_report

    # ─── Confidence Enrichment (for ZeroDayPredictor integration) ──────────

    def enrich_signal_confidence(
        self, signal: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply adaptive feedback adjustments to a signal's confidence.
        Called by ZeroDayPredictor to recalibrate signal confidence
        based on learned accuracy patterns.
        """
        signal_type = signal.get("signal_type", "")
        layer = signal.get("layer", "")
        original_confidence = signal.get("confidence", 0.5)

        # Apply signal weight
        weight = self.get_signal_weight(signal_type)

        # Apply layer threshold adjustment
        layer_adj = self.get_threshold_adjustment(layer)

        adjusted_confidence = min(
            0.99,
            original_confidence * weight / max(0.5, layer_adj),
        )

        signal["original_confidence"] = original_confidence
        signal["confidence"] = round(adjusted_confidence, 3)
        signal["telemetry_weight"] = round(weight, 3)
        signal["layer_adjustment"] = round(layer_adj, 3)
        signal["confidence_enriched"] = True

        return signal

    def update_asset_risk(
        self, asset: str, risk_delta: float, reason: str
    ) -> float:
        """Update an asset's risk score (used by cross-asset correlation)."""
        with self._lock:
            current = self.asset_risk_scores.get(asset, 0.0)
            new_score = max(0.0, min(1.0, current + risk_delta))
            self.asset_risk_scores[asset] = new_score
        return new_score

    # ─── Status & Reporting ──────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive telemetry status."""
        with self._lock:
            return {
                "engine": "advanced_telemetry",
                "status": "operational",
                "statistics": {
                    **self.stats,
                    "start_time": self.stats["start_time"].isoformat(),
                },
                "streams": {
                    "network_flow": {
                        "fingerprints_catalogued": len(self.flow_fingerprints),
                        "known_bad_fingerprints": len(self.known_bad_fingerprints),
                        "dns_sources_profiled": len(self.dns_profiles),
                        "protocol_baselines": len(self.protocol_baselines),
                    },
                    "temporal_patterns": {
                        "beacon_profiles": len(self.beacon_profiles),
                        "communication_pairs_tracked": len(self.event_timestamps),
                        "active_burst_windows": len(self.burst_windows),
                    },
                    "kernel_endpoint": {
                        "syscall_profiles": len(self.syscall_profiles),
                        "file_io_assets_tracked": len(self.file_io_patterns),
                        "privilege_transitions_logged": len(self.privilege_transitions),
                    },
                    "cross_asset": {
                        "assets_in_graph": len(self.asset_graph),
                        "total_relationships": sum(
                            len(v) for v in self.asset_graph.values()
                        ),
                        "assets_with_risk_scores": len(self.asset_risk_scores),
                    },
                    "feedback_loop": {
                        "feedback_entries": len(self.feedback_history),
                        "layers_tracked": len(self.layer_accuracy),
                        "active_threshold_adjustments": len(self.threshold_adjustments),
                        "active_suppression_rules": len(self.suppression_rules),
                        "signal_weights_tuned": sum(
                            1 for w in self.signal_weights.values()
                            if w != 1.0
                        ),
                    },
                    "collection_health": {
                        "sensors_registered": len(self.sensors),
                        "coverage_types": len(self.coverage_map),
                        "blind_spots_identified": self.stats["blind_spots_identified"],
                    },
                },
                "signal_bus_depth": len(self.telemetry_signals),
                "uptime_hours": round(
                    (datetime.utcnow() - self.stats["start_time"]).total_seconds()
                    / 3600, 2
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_beacon_report(self) -> List[Dict[str, Any]]:
        """Get all detected beacon profiles sorted by confidence."""
        with self._lock:
            beacons = [
                {
                    "source": bp.source,
                    "destination": bp.destination,
                    "classification": bp.classification.value,
                    "mean_interval": bp.mean_interval,
                    "jitter": bp.interval_jitter,
                    "confidence": bp.confidence,
                    "sample_count": bp.sample_count,
                    "first_detected": bp.first_detected.isoformat(),
                }
                for bp in self.beacon_profiles.values()
                if bp.classification != BeaconClassification.NONE
            ]
        beacons.sort(key=lambda b: b["confidence"], reverse=True)
        return beacons

    def get_asset_risk_map(self) -> Dict[str, Any]:
        """Get the asset risk scoring map."""
        with self._lock:
            return {
                "assets": dict(self.asset_risk_scores),
                "high_risk_assets": [
                    {"asset": a, "risk": round(r, 2)}
                    for a, r in sorted(
                        self.asset_risk_scores.items(),
                        key=lambda x: x[1],
                        reverse=True,
                    )
                    if r > 0.5
                ],
                "total_tracked": len(self.asset_risk_scores),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_lateral_movement_graph(self) -> Dict[str, Any]:
        """Export the asset communication graph for visualization."""
        nodes = set()
        edges = []

        with self._lock:
            for source, targets in self.asset_graph.items():
                nodes.add(source)
                for dest, rel in targets.items():
                    nodes.add(dest)
                    edges.append({
                        "source": source,
                        "target": dest,
                        "protocols": list(rel.protocols),
                        "ports": list(rel.ports)[:10],
                        "total_bytes": rel.total_bytes,
                        "connection_count": rel.connection_count,
                        "is_new": rel.is_new,
                    })

        return {
            "nodes": [
                {
                    "id": n,
                    "risk_score": round(
                        self.asset_risk_scores.get(n, 0), 2
                    ),
                }
                for n in nodes
            ],
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_feedback_summary(self) -> Dict[str, Any]:
        """Get adaptive feedback loop summary."""
        with self._lock:
            return {
                "layer_accuracy": {
                    layer: {
                        **stats,
                        "accuracy_rate": round(
                            stats["true_positive"]
                            / max(1, stats["total"]), 3
                        ),
                        "fp_rate": round(
                            stats["false_positive"]
                            / max(1, stats["total"]), 3
                        ),
                    }
                    for layer, stats in self.layer_accuracy.items()
                },
                "threshold_adjustments": dict(self.threshold_adjustments),
                "signal_weights": {
                    k: round(v, 3)
                    for k, v in self.signal_weights.items()
                    if v != 1.0
                },
                "active_suppression_rules": [
                    {
                        "signal_types": r["signal_types"],
                        "factor": r["suppression_factor"],
                        "reason": r["reason"],
                        "expires": r["expires_at"],
                    }
                    for r in self.suppression_rules
                    if datetime.fromisoformat(r["expires_at"])
                    > datetime.utcnow()
                ],
                "total_feedback_entries": len(self.feedback_history),
                "timestamp": datetime.utcnow().isoformat(),
            }
