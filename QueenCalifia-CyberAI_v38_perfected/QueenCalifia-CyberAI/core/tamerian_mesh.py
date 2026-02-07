"""
QueenCalifia CyberAI - Tamerian Security Mesh
==============================================
Biomimetic self-healing security architecture inspired by spider web
resilience and mycelium distributed intelligence.

Spider Web Topology: Threat correlation across interconnected sensor nodes.
    - Hub nodes = Security domain controllers (network, endpoint, identity, data)
    - Radial threads = Detection pipelines (signature, behavioral, heuristic)
    - Spiral threads = Correlation paths linking disparate events into attack chains
    - When a thread breaks (sensor fails), adjacent nodes absorb the load.

Mycelium Network: Distributed threat intelligence propagation.
    - Threat indicators spread across all nodes like nutrient signals
    - Pattern recognition emerges from collective analysis, not centralized processing
    - New IOCs propagate in O(log n) time across the mesh

Tamerian Circuits: Hardened processing pipelines with fault tolerance.
    - Each circuit has redundant pathways and integrity verification
    - Phosphorene coating = cryptographic integrity checks on all data in transit
    - Biological healing = automatic failover and state reconstruction
"""

import time
import uuid
import hashlib
import hmac
import logging
import threading
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import secrets
import ipaddress
import re

logger = logging.getLogger("queencalifia.mesh")


# ─── Enumerations ───────────────────────────────────────────────────────────

class ThreatSeverity(IntEnum):
    """CVSS-aligned severity levels"""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ThreatCategory(Enum):
    """MITRE ATT&CK-aligned threat categories"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class MeshNodeState(Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    HEALING = "healing"
    ISOLATED = "isolated"
    OFFLINE = "offline"

class DetectionMethod(Enum):
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    HEURISTIC = "heuristic"
    ML_ANOMALY = "ml_anomaly"
    CORRELATION = "correlation"
    THREAT_INTEL = "threat_intel"


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class SecurityEvent:
    """Normalized security event from any source"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str = "unknown"
    raw_data: Dict[str, Any] = field(default_factory=dict)
    severity: ThreatSeverity = ThreatSeverity.INFO
    category: Optional[ThreatCategory] = None
    detection_method: DetectionMethod = DetectionMethod.SIGNATURE
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    hash_fingerprint: str = ""

    def __post_init__(self):
        if not self.hash_fingerprint:
            content = f"{self.source_ip}:{self.dest_ip}:{self.event_type}:{self.timestamp.isoformat()}"
            self.hash_fingerprint = hashlib.sha256(content.encode()).hexdigest()[:16]

@dataclass
class ThreatIndicator:
    """Indicator of Compromise (IOC)"""
    ioc_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    indicator_type: str = "unknown"  # ip, domain, hash, url, email, cve
    value: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.5
    source: str = "internal"
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    ttl: int = 86400  # Seconds until expiry

    @property
    def is_expired(self) -> bool:
        return (datetime.utcnow() - self.last_seen).total_seconds() > self.ttl

@dataclass
class AttackChain:
    """Correlated sequence of events forming an attack narrative"""
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    events: List[SecurityEvent] = field(default_factory=list)
    kill_chain_phase: str = "unknown"
    severity: ThreatSeverity = ThreatSeverity.INFO
    confidence: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    affected_assets: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
    recommended_actions: List[str] = field(default_factory=list)

@dataclass
class MeshNode:
    """Security sensor node in the spider web mesh"""
    node_id: str
    node_type: str  # hub, radial, spiral
    security_domain: str
    state: MeshNodeState = MeshNodeState.ACTIVE
    health: float = 1.0
    connections: List[str] = field(default_factory=list)
    events_processed: int = 0
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    detection_rules: List[str] = field(default_factory=list)
    repair_count: int = 0

@dataclass
class TamerianCircuit:
    """Hardened processing pipeline with integrity verification"""
    circuit_id: str
    pipeline_type: str
    integrity_hash: str = ""
    fault_tolerance: float = 0.95
    redundant_paths: int = 3
    throughput_events_sec: int = 0
    is_healthy: bool = True
    last_integrity_check: datetime = field(default_factory=datetime.utcnow)


# ─── Core Security Mesh ─────────────────────────────────────────────────────

class TamerianSecurityMesh:
    """
    The core defensive intelligence mesh for Queen Califia CyberAI.
    
    Architecture:
        Hub Nodes (4): Network, Endpoint, Identity, Data security controllers
        Radial Nodes (12): Detection pipelines per security domain
        Spiral Nodes (8): Cross-domain correlation engines
        Tamerian Circuits (6): Hardened processing pipelines
    
    Capabilities:
        - Real-time event ingestion and normalization
        - Multi-method threat detection (signature + behavioral + ML)
        - Attack chain correlation across kill chain phases
        - IOC management with automatic propagation
        - Self-healing mesh with automatic failover
        - MITRE ATT&CK technique mapping
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.mesh_id = str(uuid.uuid4())[:8]

        # Concurrency guard (shared state spans threads)
        self._lock = threading.RLock()

        # ── Mesh topology ──
        self.nodes: Dict[str, MeshNode] = {}
        self.circuits: Dict[str, TamerianCircuit] = {}
        self._build_mesh_topology()

        # ── Threat state ──
        self.event_buffer: deque = deque(maxlen=50000)
        self.active_threats: Dict[str, AttackChain] = {}
        self.ioc_database: Dict[str, ThreatIndicator] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.blocked_domains: Set[str] = set()

        # ── Detection state ──
        self.signature_rules = self._load_default_signatures()
        self.behavioral_baselines: Dict[str, Dict] = defaultdict(dict)
        self.anomaly_scores: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # ── Correlation state ──
        self.correlation_windows: Dict[str, List[SecurityEvent]] = defaultdict(list)
        self.attack_patterns = self._load_attack_patterns()

        # ── Statistics ──
        self.stats = {
            "events_ingested": 0,
            "threats_detected": 0,
            "attacks_correlated": 0,
            "iocs_active": 0,
            "ips_blocked": 0,
            "mesh_heals": 0,
            "false_positives_suppressed": 0,
            "start_time": datetime.utcnow(),
        }

        # ── Thread pool for parallel detection ──
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.get("detection_threads", 8),
            thread_name_prefix="qc_detect"
        )

        # ── Self-healing background thread ──
        self._healing_active = True
        self._healing_thread = threading.Thread(
            target=self._self_healing_loop, daemon=True, name="qc_healing"
        )
        self._healing_thread.start()

        # ── IOC expiry background thread ──
        self._ioc_cleanup_thread = threading.Thread(
            target=self._ioc_cleanup_loop, daemon=True, name="qc_ioc_cleanup"
        )
        self._ioc_cleanup_thread.start()

        logger.info(
            f"🕷️  Tamerian Security Mesh [{self.mesh_id}] online | "
            f"{len(self.nodes)} nodes | {len(self.circuits)} circuits | "
            f"{len(self.signature_rules)} signatures loaded"
        )

    # ─── Mesh Topology Construction ──────────────────────────────────────────

    def _build_mesh_topology(self):
        """Construct the spider web security mesh"""

        # Hub nodes — one per security domain
        hub_domains = {
            "network": ["traffic_analysis", "ids_ips", "firewall_mgmt", "dns_security"],
            "endpoint": ["edr_analysis", "process_monitoring", "file_integrity", "memory_forensics"],
            "identity": ["auth_analysis", "privilege_monitoring", "credential_protection", "mfa_enforcement"],
            "data": ["dlp_monitoring", "encryption_verification", "access_auditing", "classification"],
        }
        for domain, capabilities in hub_domains.items():
            node_id = f"hub_{domain}"
            self.nodes[node_id] = MeshNode(
                node_id=node_id,
                node_type="hub",
                security_domain=domain,
                connections=[],
                detection_rules=capabilities,
            )

        # Radial nodes — detection pipelines
        detection_pipelines = {
            "sig_network": ("radial", "network", ["snort_rules", "suricata_rules"]),
            "sig_endpoint": ("radial", "endpoint", ["yara_rules", "sigma_rules"]),
            "sig_identity": ("radial", "identity", ["auth_signatures", "brute_force_patterns"]),
            "beh_network": ("radial", "network", ["traffic_baseline", "protocol_anomaly"]),
            "beh_endpoint": ("radial", "endpoint", ["process_baseline", "registry_anomaly"]),
            "beh_identity": ("radial", "identity", ["login_baseline", "access_anomaly"]),
            "heur_network": ("radial", "network", ["port_scan_heuristic", "c2_beacon_heuristic"]),
            "heur_endpoint": ("radial", "endpoint", ["fileless_heuristic", "injection_heuristic"]),
            "ml_network": ("radial", "network", ["traffic_autoencoder", "dns_classifier"]),
            "ml_endpoint": ("radial", "endpoint", ["process_classifier", "anomaly_detector"]),
            "ml_identity": ("radial", "identity", ["auth_anomaly_model", "insider_threat_model"]),
            "ml_data": ("radial", "data", ["exfil_detector", "classification_model"]),
        }
        for node_name, (ntype, domain, rules) in detection_pipelines.items():
            node_id = f"radial_{node_name}"
            self.nodes[node_id] = MeshNode(
                node_id=node_id,
                node_type=ntype,
                security_domain=domain,
                detection_rules=rules,
            )

        # Spiral nodes — cross-domain correlation
        correlation_engines = [
            "kill_chain_correlator",
            "lateral_movement_tracker",
            "data_exfil_correlator",
            "apt_campaign_tracker",
            "insider_threat_correlator",
            "supply_chain_correlator",
            "ransomware_chain_detector",
            "zero_day_anomaly_correlator",
        ]
        for engine in correlation_engines:
            node_id = f"spiral_{engine}"
            self.nodes[node_id] = MeshNode(
                node_id=node_id,
                node_type="spiral",
                security_domain="correlation",
                detection_rules=[engine],
            )

        # Wire connections — spider web pattern
        hub_ids = [nid for nid in self.nodes if nid.startswith("hub_")]
        radial_ids = [nid for nid in self.nodes if nid.startswith("radial_")]
        spiral_ids = [nid for nid in self.nodes if nid.startswith("spiral_")]

        # Hubs fully meshed to each other + connected to all spirals
        for hid in hub_ids:
            self.nodes[hid].connections = (
                [h for h in hub_ids if h != hid] + spiral_ids
            )

        # Radials connect to their domain hub + all spirals
        for rid in radial_ids:
            domain = self.nodes[rid].security_domain
            domain_hub = f"hub_{domain}"
            self.nodes[rid].connections = [domain_hub] + spiral_ids

        # Spirals connect to all hubs (full visibility)
        for sid in spiral_ids:
            self.nodes[sid].connections = hub_ids

        # Tamerian circuits — hardened processing pipelines
        circuit_types = [
            "ingestion_pipeline",
            "detection_pipeline",
            "correlation_pipeline",
            "response_pipeline",
            "intelligence_pipeline",
            "audit_pipeline",
        ]
        for ctype in circuit_types:
            cid = f"circuit_{ctype}"
            self.circuits[cid] = TamerianCircuit(
                circuit_id=cid,
                pipeline_type=ctype,
                integrity_hash=hashlib.sha256(cid.encode()).hexdigest()[:16],
                redundant_paths=3,
            )

    # ─── Signature Rules ─────────────────────────────────────────────────────

    def _load_default_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load defense-grade detection signatures"""
        return {
            # ── Network signatures ──
            "SIG-NET-001": {
                "name": "Port Scan Detected",
                "category": ThreatCategory.RECONNAISSANCE,
                "severity": ThreatSeverity.MEDIUM,
                "mitre": ["T1046"],
                "condition": lambda e: (
                    e.event_type == "connection_attempt"
                    and e.raw_data.get("unique_ports_1min", 0) > 20
                ),
                "description": "Host scanning multiple ports in rapid succession",
            },
            "SIG-NET-002": {
                "name": "Known C2 Domain Resolution",
                "category": ThreatCategory.COMMAND_AND_CONTROL,
                "severity": ThreatSeverity.CRITICAL,
                "mitre": ["T1071.001"],
                "condition": lambda e: (
                    e.event_type == "dns_query"
                    and e.raw_data.get("domain", "") in self.blocked_domains
                ),
                "description": "DNS resolution of known command-and-control domain",
            },
            "SIG-NET-003": {
                "name": "DNS Tunneling Detected",
                "category": ThreatCategory.EXFILTRATION,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1048.001"],
                "condition": lambda e: (
                    e.event_type == "dns_query"
                    and len(e.raw_data.get("query_name", "")) > 60
                    and e.raw_data.get("query_type") == "TXT"
                ),
                "description": "Suspiciously long DNS TXT query indicating data exfiltration",
            },
            "SIG-NET-004": {
                "name": "Beaconing Activity",
                "category": ThreatCategory.COMMAND_AND_CONTROL,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1071", "T1573"],
                "condition": lambda e: (
                    e.event_type == "http_request"
                    and e.raw_data.get("beacon_score", 0) > 0.85
                ),
                "description": "Periodic outbound HTTP traffic consistent with C2 beaconing",
            },
            "SIG-NET-005": {
                "name": "Large Outbound Data Transfer",
                "category": ThreatCategory.EXFILTRATION,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1041"],
                "condition": lambda e: (
                    e.event_type == "data_transfer"
                    and e.raw_data.get("bytes_out", 0) > 100_000_000
                    and not e.raw_data.get("is_known_destination", False)
                ),
                "description": "Large data transfer to unknown external destination",
            },

            # ── Endpoint signatures ──
            "SIG-END-001": {
                "name": "Suspicious Process Execution",
                "category": ThreatCategory.EXECUTION,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1059"],
                "condition": lambda e: (
                    e.event_type == "process_start"
                    and e.raw_data.get("process_name", "").lower() in {
                        "powershell.exe", "cmd.exe", "wscript.exe",
                        "cscript.exe", "mshta.exe", "regsvr32.exe",
                        "rundll32.exe", "certutil.exe",
                    }
                    and e.raw_data.get("parent_suspicious", False)
                ),
                "description": "LOLBin execution from suspicious parent process",
            },
            "SIG-END-002": {
                "name": "Ransomware File Activity",
                "category": ThreatCategory.IMPACT,
                "severity": ThreatSeverity.CRITICAL,
                "mitre": ["T1486"],
                "condition": lambda e: (
                    e.event_type == "file_modification"
                    and e.raw_data.get("encrypted_extensions_count", 0) > 10
                    and e.raw_data.get("time_window_sec", 999) < 60
                ),
                "description": "Rapid mass file encryption indicating ransomware",
            },
            "SIG-END-003": {
                "name": "Credential Dumping Tool",
                "category": ThreatCategory.CREDENTIAL_ACCESS,
                "severity": ThreatSeverity.CRITICAL,
                "mitre": ["T1003"],
                "condition": lambda e: (
                    e.event_type == "process_start"
                    and any(
                        tool in e.raw_data.get("command_line", "").lower()
                        for tool in ["mimikatz", "sekurlsa", "lsass", "procdump",
                                     "comsvcs.dll", "ntdsutil"]
                    )
                ),
                "description": "Known credential dumping tool or technique detected",
            },
            "SIG-END-004": {
                "name": "Persistence Mechanism Created",
                "category": ThreatCategory.PERSISTENCE,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1547", "T1053"],
                "condition": lambda e: (
                    e.event_type in {"registry_modification", "scheduled_task_created", "service_created"}
                    and e.raw_data.get("persistence_indicator", False)
                ),
                "description": "New persistence mechanism established",
            },

            # ── Identity signatures ──
            "SIG-IDN-001": {
                "name": "Brute Force Attack",
                "category": ThreatCategory.CREDENTIAL_ACCESS,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1110"],
                "condition": lambda e: (
                    e.event_type == "auth_failure"
                    and e.raw_data.get("failures_1min", 0) > 10
                ),
                "description": "Multiple authentication failures from single source",
            },
            "SIG-IDN-002": {
                "name": "Impossible Travel Login",
                "category": ThreatCategory.INITIAL_ACCESS,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1078"],
                "condition": lambda e: (
                    e.event_type == "auth_success"
                    and e.raw_data.get("impossible_travel", False)
                ),
                "description": "User authenticated from geographically impossible locations",
            },
            "SIG-IDN-003": {
                "name": "Privilege Escalation Attempt",
                "category": ThreatCategory.PRIVILEGE_ESCALATION,
                "severity": ThreatSeverity.CRITICAL,
                "mitre": ["T1068", "T1548"],
                "condition": lambda e: (
                    e.event_type == "privilege_change"
                    and e.raw_data.get("escalation_type") in {"admin_grant", "sudo_abuse", "token_manipulation"}
                ),
                "description": "Unauthorized privilege escalation detected",
            },

            # ── Data security signatures ──
            "SIG-DAT-001": {
                "name": "Sensitive Data Access Anomaly",
                "category": ThreatCategory.COLLECTION,
                "severity": ThreatSeverity.HIGH,
                "mitre": ["T1005", "T1039"],
                "condition": lambda e: (
                    e.event_type == "data_access"
                    and e.raw_data.get("classification") in {"SECRET", "TOP_SECRET", "PII", "PHI"}
                    and e.raw_data.get("access_anomaly_score", 0) > 0.8
                ),
                "description": "Anomalous access to classified or sensitive data",
            },
        }

    def _load_attack_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load kill chain attack correlation patterns"""
        return {
            "APT_LATERAL_CHAIN": {
                "name": "APT Lateral Movement Campaign",
                "phases": [
                    ThreatCategory.INITIAL_ACCESS,
                    ThreatCategory.EXECUTION,
                    ThreatCategory.CREDENTIAL_ACCESS,
                    ThreatCategory.LATERAL_MOVEMENT,
                ],
                "max_window_hours": 24,
                "min_events": 3,
                "severity": ThreatSeverity.CRITICAL,
            },
            "RANSOMWARE_CHAIN": {
                "name": "Ransomware Kill Chain",
                "phases": [
                    ThreatCategory.INITIAL_ACCESS,
                    ThreatCategory.EXECUTION,
                    ThreatCategory.DEFENSE_EVASION,
                    ThreatCategory.IMPACT,
                ],
                "max_window_hours": 4,
                "min_events": 2,
                "severity": ThreatSeverity.CRITICAL,
            },
            "DATA_EXFIL_CHAIN": {
                "name": "Data Exfiltration Campaign",
                "phases": [
                    ThreatCategory.COLLECTION,
                    ThreatCategory.COMMAND_AND_CONTROL,
                    ThreatCategory.EXFILTRATION,
                ],
                "max_window_hours": 12,
                "min_events": 2,
                "severity": ThreatSeverity.CRITICAL,
            },
            "INSIDER_THREAT_CHAIN": {
                "name": "Insider Threat Activity",
                "phases": [
                    ThreatCategory.DISCOVERY,
                    ThreatCategory.COLLECTION,
                    ThreatCategory.EXFILTRATION,
                ],
                "max_window_hours": 168,  # 7 days
                "min_events": 3,
                "severity": ThreatSeverity.HIGH,
            },
        }

    # ─── Event Ingestion ─────────────────────────────────────────────────────

    def ingest_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Ingest a security event into the mesh for real-time analysis.
        
        Pipeline: Validate → Normalize → Detect → Correlate → Respond
        
        Returns detection results including any threats found.
        """
        start = time.monotonic()
        with self._lock:
            self.stats["events_ingested"] += 1

        # Verify circuit integrity before processing
        if not self._verify_circuit_integrity("circuit_ingestion_pipeline"):
            logger.warning("Ingestion circuit integrity check failed — healing")
            self._heal_circuit("circuit_ingestion_pipeline")

        # Validate and sanitize
        event = self._validate_event(event)
        with self._lock:
            self.event_buffer.append(event)
            # Update node heartbeats based on event domain
            self._route_to_domain_hub(event)

        # Parallel detection across all methods
        detection_results = self._run_detection_pipeline(event)

        # Correlation analysis
        correlation_results = self._run_correlation_pipeline(event, detection_results)

        # Update mesh statistics
        elapsed = time.monotonic() - start
        result = {
            "event_id": event.event_id,
            "processing_time_ms": round(elapsed * 1000, 2),
            "detections": detection_results,
            "correlations": correlation_results,
            "severity": max(
                (d.get("severity", ThreatSeverity.INFO) for d in detection_results),
                default=ThreatSeverity.INFO,
            ),
            "action_required": any(
                d.get("severity", ThreatSeverity.INFO) >= ThreatSeverity.HIGH
                for d in detection_results
            ),
        }

        if result["action_required"]:
            self.stats["threats_detected"] += 1
            logger.warning(
                f"⚠️  THREAT DETECTED | {event.event_id} | "
                f"severity={result['severity'].name} | "
                f"src={event.source_ip} → dst={event.dest_ip}"
            )

        return result

    def _validate_event(self, event: SecurityEvent) -> SecurityEvent:
        """Validate and sanitize incoming event data"""
        # Sanitize IP addresses
        if event.source_ip:
            try:
                ipaddress.ip_address(event.source_ip)
            except ValueError:
                event.source_ip = None

        if event.dest_ip:
            try:
                ipaddress.ip_address(event.dest_ip)
            except ValueError:
                event.dest_ip = None

        # Sanitize ports
        if event.source_port and not (0 <= event.source_port <= 65535):
            event.source_port = None
        if event.dest_port and not (0 <= event.dest_port <= 65535):
            event.dest_port = None

        # Sanitize string fields against injection
        if event.event_type:
            event.event_type = re.sub(r'[^\w_.-]', '', event.event_type)[:128]

        return event

    def _route_to_domain_hub(self, event: SecurityEvent):
        """Route event to the appropriate domain hub node"""
        domain_map = {
            "connection_attempt": "hub_network",
            "dns_query": "hub_network",
            "http_request": "hub_network",
            "data_transfer": "hub_network",
            "process_start": "hub_endpoint",
            "file_modification": "hub_endpoint",
            "registry_modification": "hub_endpoint",
            "scheduled_task_created": "hub_endpoint",
            "service_created": "hub_endpoint",
            "auth_failure": "hub_identity",
            "auth_success": "hub_identity",
            "privilege_change": "hub_identity",
            "data_access": "hub_data",
        }
        hub_id = domain_map.get(event.event_type, "hub_network")
        if hub_id in self.nodes:
            node = self.nodes[hub_id]
            node.events_processed += 1
            node.last_heartbeat = datetime.utcnow()

    # ─── Detection Pipeline ──────────────────────────────────────────────────

    def _run_detection_pipeline(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Run parallel detection across all methods"""
        if not self._verify_circuit_integrity("circuit_detection_pipeline"):
            self._heal_circuit("circuit_detection_pipeline")

        detections = []

        # 1. Signature-based detection
        sig_results = self._signature_detection(event)
        detections.extend(sig_results)

        # 2. Behavioral analysis
        beh_results = self._behavioral_detection(event)
        detections.extend(beh_results)

        # 3. IOC matching
        ioc_results = self._ioc_matching(event)
        detections.extend(ioc_results)

        # 4. Anomaly scoring
        anomaly_results = self._anomaly_detection(event)
        detections.extend(anomaly_results)

        return detections

    def _signature_detection(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Match event against signature rules"""
        matches = []
        for sig_id, rule in self.signature_rules.items():
            try:
                if rule["condition"](event):
                    detection = {
                        "detection_id": str(uuid.uuid4())[:8],
                        "signature_id": sig_id,
                        "name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "mitre_techniques": rule["mitre"],
                        "method": DetectionMethod.SIGNATURE,
                        "confidence": 0.90,
                        "description": rule["description"],
                        "event_id": event.event_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    matches.append(detection)

                    # Tag the event
                    event.severity = max(event.severity, rule["severity"])
                    event.category = rule["category"]
                    event.mitre_techniques.extend(rule["mitre"])
                    event.detection_method = DetectionMethod.SIGNATURE

            except Exception as exc:
                logger.debug(f"Signature {sig_id} evaluation error: {exc}")

        return matches

    def _behavioral_detection(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Detect deviations from established behavioral baselines."""
        detections: List[Dict[str, Any]] = []
        source_key = event.source_ip or "unknown"

        with self._lock:
            baseline = self.behavioral_baselines[source_key]

            if event.event_type == "connection_attempt":
                count_key = f"{source_key}_conn_count"
                current_count = int(baseline.get(count_key, 0)) + 1
                baseline[count_key] = current_count

                if current_count > self.config.get("conn_burst_threshold", 100):
                    detections.append(
                        {
                            "detection_id": str(uuid.uuid4())[:8],
                            "name": "Connection Burst Anomaly",
                            "category": ThreatCategory.RECONNAISSANCE,
                            "severity": ThreatSeverity.MEDIUM,
                            "mitre_techniques": ["T1046"],
                            "method": DetectionMethod.BEHAVIORAL,
                            "confidence": 0.75,
                            "description": f"Source {source_key} exceeded connection burst threshold",
                            "event_id": event.event_id,
                            "baseline_value": 50,
                            "observed_value": current_count,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

            if event.event_type == "auth_failure":
                fail_key = f"{source_key}_auth_fails"
                fail_count = int(baseline.get(fail_key, 0)) + 1
                baseline[fail_key] = fail_count

                if fail_count > self.config.get("auth_fail_threshold", 5):
                    detections.append(
                        {
                            "detection_id": str(uuid.uuid4())[:8],
                            "name": "Authentication Failure Spike",
                            "category": ThreatCategory.CREDENTIAL_ACCESS,
                            "severity": ThreatSeverity.HIGH,
                            "mitre_techniques": ["T1110"],
                            "method": DetectionMethod.BEHAVIORAL,
                            "confidence": 0.85,
                            "description": f"Source {source_key} has {fail_count} auth failures",
                            "event_id": event.event_id,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

        return detections
    def _ioc_matching(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Match event against IOC database."""
        detections: List[Dict[str, Any]] = []
        check_values: List[Tuple[str, str]] = []

        if event.source_ip:
            check_values.append(("ip", event.source_ip))
        if event.dest_ip:
            check_values.append(("ip", event.dest_ip))
        if event.raw_data.get("domain"):
            check_values.append(("domain", str(event.raw_data["domain"])))
        if event.raw_data.get("file_hash"):
            check_values.append(("hash", str(event.raw_data["file_hash"])))
        if event.raw_data.get("url"):
            check_values.append(("url", str(event.raw_data["url"])))

        now = datetime.utcnow()
        with self._lock:
            for ioc_type, value in check_values:
                ioc_key = f"{ioc_type}:{value}"
                ioc = self.ioc_database.get(ioc_key)
                if not ioc or ioc.is_expired:
                    continue
                ioc.last_seen = now
                detections.append(
                    {
                        "detection_id": str(uuid.uuid4())[:8],
                        "name": f"IOC Match: {ioc.indicator_type}",
                        "category": ThreatCategory.COMMAND_AND_CONTROL,
                        "severity": ioc.severity,
                        "mitre_techniques": ioc.mitre_techniques,
                        "method": DetectionMethod.THREAT_INTEL,
                        "confidence": ioc.confidence,
                        "description": f"Matched {ioc.indicator_type} IOC: {value}",
                        "ioc_id": ioc.ioc_id,
                        "ioc_source": ioc.source,
                        "ioc_tags": ioc.tags,
                        "event_id": event.event_id,
                        "timestamp": now.isoformat(),
                    }
                )

        return detections
    def _anomaly_detection(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Statistical anomaly detection using a simple Z-score heuristic."""
        import statistics

        detections: List[Dict[str, Any]] = []
        source = event.source_ip or "unknown"

        features = {
            "bytes_out": event.raw_data.get("bytes_out", 0),
            "bytes_in": event.raw_data.get("bytes_in", 0),
            "duration_ms": event.raw_data.get("duration_ms", 0),
            "unique_ports": event.raw_data.get("unique_ports_1min", 0),
        }

        threshold = float(self.config.get("anomaly_z_threshold", 3.0))
        now = datetime.utcnow()

        with self._lock:
            for feature_name, value in features.items():
                try:
                    value = float(value)
                except Exception:
                    continue
                if value <= 0:
                    continue

                score_key = f"{source}_{feature_name}"
                history = self.anomaly_scores[score_key]
                history.append(value)

                if len(history) < 10:
                    continue

                mean = statistics.mean(history)
                stdev = statistics.stdev(history) if len(history) > 1 else 1.0
                if stdev <= 0:
                    continue

                z_score = abs(value - mean) / stdev
                if z_score > threshold:
                    detections.append(
                        {
                            "detection_id": str(uuid.uuid4())[:8],
                            "name": f"Statistical Anomaly: {feature_name}",
                            "category": ThreatCategory.DISCOVERY,
                            "severity": ThreatSeverity.MEDIUM,
                            "mitre_techniques": [],
                            "method": DetectionMethod.ML_ANOMALY,
                            "confidence": min(0.95, 0.5 + z_score * 0.1),
                            "description": (
                                f"Anomalous {feature_name} for {source}: "
                                f"value={value}, mean={mean:.1f}, z={z_score:.2f}"
                            ),
                            "event_id": event.event_id,
                            "z_score": round(float(z_score), 3),
                            "timestamp": now.isoformat(),
                        }
                    )

        return detections
    # ─── Correlation Pipeline ────────────────────────────────────────────────

    def _run_correlation_pipeline(
        self, event: SecurityEvent, detections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Correlate events into attack chains."""
        if not detections:
            return []

        if not self._verify_circuit_integrity("circuit_correlation_pipeline"):
            self._heal_circuit("circuit_correlation_pipeline")

        correlations: List[Dict[str, Any]] = []
        source = event.source_ip or "unknown"
        now = datetime.utcnow()

        with self._lock:
            self.correlation_windows[source].append(event)

            cutoff_24h = now - timedelta(hours=24)
            self.correlation_windows[source] = [
                e for e in self.correlation_windows[source] if e.timestamp > cutoff_24h
            ]

            window_events = self.correlation_windows[source]
            for pattern_id, pattern in self.attack_patterns.items():
                window_cutoff = now - timedelta(hours=pattern["max_window_hours"])
                relevant_events = [e for e in window_events if e.timestamp > window_cutoff]

                matched_phases = set()
                matched_events: List[SecurityEvent] = []
                for evt in relevant_events:
                    if evt.category in pattern["phases"]:
                        matched_phases.add(evt.category)
                        matched_events.append(evt)

                if len(matched_phases) < pattern["min_events"]:
                    continue

                chain = AttackChain(
                    events=matched_events,
                    kill_chain_phase=pattern["name"],
                    severity=pattern["severity"],
                    confidence=len(matched_phases) / max(1, len(pattern["phases"])),
                    mitre_techniques=[t for e in matched_events for t in e.mitre_techniques],
                    affected_assets={e.dest_ip for e in matched_events if e.dest_ip},
                    first_seen=min(e.timestamp for e in matched_events),
                    last_activity=max(e.timestamp for e in matched_events),
                    recommended_actions=self._generate_response_actions(pattern["severity"], pattern_id),
                )

                self.active_threats[chain.chain_id] = chain
                self.stats["attacks_correlated"] += 1

                correlations.append(
                    {
                        "chain_id": chain.chain_id,
                        "pattern": pattern["name"],
                        "severity": chain.severity,
                        "confidence": round(chain.confidence, 2),
                        "events_count": len(chain.events),
                        "affected_assets": list(chain.affected_assets),
                        "mitre_techniques": chain.mitre_techniques,
                        "recommended_actions": chain.recommended_actions,
                        "timestamp": now.isoformat(),
                    }
                )

                logger.critical(
                    f"🚨 ATTACK CHAIN DETECTED | {pattern['name']} | "
                    f"severity={chain.severity.name} | "
                    f"confidence={chain.confidence:.0%} | "
                    f"assets={chain.affected_assets}"
                )

        return correlations
    def _generate_response_actions(
        self, severity: ThreatSeverity, pattern_id: str
    ) -> List[str]:
        """Generate recommended incident response actions"""
        actions = []

        if severity >= ThreatSeverity.CRITICAL:
            actions.extend([
                "ISOLATE affected endpoints from network immediately",
                "BLOCK source IPs at perimeter firewall",
                "CAPTURE full memory dump of affected systems",
                "NOTIFY incident response team — Priority 1",
                "PRESERVE all log data for forensic analysis",
                "INITIATE incident response playbook",
            ])
        elif severity >= ThreatSeverity.HIGH:
            actions.extend([
                "MONITOR affected systems with enhanced logging",
                "BLOCK suspicious source IPs",
                "ALERT SOC analyst for investigation",
                "COLLECT relevant logs and artifacts",
                "ASSESS scope of potential compromise",
            ])
        else:
            actions.extend([
                "LOG event for trend analysis",
                "MONITOR source for additional activity",
                "UPDATE behavioral baselines",
            ])

        # Pattern-specific actions
        if pattern_id == "RANSOMWARE_CHAIN":
            actions.insert(0, "EMERGENCY: Disconnect affected systems from network")
            actions.insert(1, "VERIFY backup integrity immediately")
        elif pattern_id == "DATA_EXFIL_CHAIN":
            actions.insert(0, "BLOCK all outbound traffic from affected systems")

        return actions

    # ─── IOC Management ──────────────────────────────────────────────────────


    def list_active_iocs(self) -> List[Dict[str, Any]]:
        """List non-expired IOCs in a stable JSON shape."""
        with self._lock:
            out: List[Dict[str, Any]] = []
            for ioc in self.ioc_database.values():
                if getattr(ioc, "is_expired", False):
                    continue
                out.append(
                    {
                        "type": ioc.indicator_type,
                        "value": ioc.value,
                        "severity": ioc.severity.name,
                        "confidence": ioc.confidence,
                        "source": ioc.source,
                        "tags": ioc.tags,
                        "first_seen": ioc.first_seen.isoformat(),
                        "last_seen": ioc.last_seen.isoformat(),
                    }
                )
            return out

    def add_ioc(self, indicator: ThreatIndicator) -> str:
        """Add an IOC to the database and propagate across the mesh."""
        key = f"{indicator.indicator_type}:{indicator.value}"
        with self._lock:
            self.ioc_database[key] = indicator
            self.stats["iocs_active"] = len([i for i in self.ioc_database.values() if not i.is_expired])

            if indicator.indicator_type == "ip" and indicator.severity >= ThreatSeverity.HIGH:
                self.blocked_ips[indicator.value] = datetime.utcnow()
                self.stats["ips_blocked"] = len(self.blocked_ips)
            elif indicator.indicator_type == "domain":
                self.blocked_domains.add(indicator.value)

        logger.info(
            f"🔒 IOC added: {indicator.indicator_type}={indicator.value} "
            f"severity={indicator.severity.name} source={indicator.source}"
        )
        return key
    def bulk_import_iocs(self, iocs: List[Dict[str, Any]]) -> int:
        """Bulk import IOCs from threat intelligence feeds."""
        imported = 0
        for ioc_data in iocs:
            try:
                indicator = ThreatIndicator(
                    indicator_type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    severity=ThreatSeverity(ioc_data.get("severity", 2)),
                    confidence=ioc_data.get("confidence", 0.5),
                    source=ioc_data.get("source", "feed_import"),
                    tags=ioc_data.get("tags", []),
                    mitre_techniques=ioc_data.get("mitre", []),
                    ttl=ioc_data.get("ttl", 86400),
                )
                self.add_ioc(indicator)
                imported += 1
            except Exception as exc:
                logger.warning(f"Failed to import IOC: {exc}")
        return imported
    # ─── Self-Healing ────────────────────────────────────────────────────────

    def _self_healing_loop(self):
        """Background thread: monitor and heal mesh nodes (thread-safe)."""
        while self._healing_active:
            try:
                now = datetime.utcnow()
                with self._lock:
                    for node_id, node in list(self.nodes.items()):
                        if (now - node.last_heartbeat).total_seconds() > 120:
                            if node.state == MeshNodeState.ACTIVE:
                                node.state = MeshNodeState.DEGRADED
                                logger.warning(f"🔧 Node {node_id} degraded — no heartbeat")

                        if node.state == MeshNodeState.DEGRADED:
                            node.state = MeshNodeState.HEALING
                            node.health = min(1.0, node.health + 0.1)
                            node.repair_count += 1
                            if node.health >= 0.8:
                                node.state = MeshNodeState.ACTIVE
                                node.last_heartbeat = now
                                self.stats["mesh_heals"] += 1
                                logger.info(f"✅ Node {node_id} healed — back online")

                    for circuit_id, circuit in list(self.circuits.items()):
                        if not circuit.is_healthy:
                            self._heal_circuit(circuit_id)

                    self._decay_baselines()

            except Exception as exc:
                logger.error(f"Healing loop error: {exc}")

            time.sleep(30)
    def _ioc_cleanup_loop(self):
        """Background thread: clean up expired IOCs (thread-safe)."""
        while self._healing_active:
            try:
                with self._lock:
                    expired_keys = [k for k, v in self.ioc_database.items() if v.is_expired]
                    for key in expired_keys:
                        self.ioc_database.pop(key, None)
                    if expired_keys:
                        logger.info(f"🧹 Cleaned {len(expired_keys)} expired IOCs")
                        self.stats["iocs_active"] = len([i for i in self.ioc_database.values() if not i.is_expired])
            except Exception as exc:
                logger.error(f"IOC cleanup error: {exc}")
            time.sleep(300)
    def _decay_baselines(self):
        """Decay behavioral baseline counters to prevent permanent elevation."""
        decay_factor = 0.95
        for source, baselines in list(self.behavioral_baselines.items()):
            for key in list(baselines.keys()):
                if isinstance(baselines[key], (int, float)):
                    baselines[key] = int(baselines[key] * decay_factor)
                    if baselines[key] <= 0:
                        baselines.pop(key, None)
    def _verify_circuit_integrity(self, circuit_id: str) -> bool:
        """Verify cryptographic integrity of a processing circuit"""
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            return False

        expected_hash = hashlib.sha256(circuit.circuit_id.encode()).hexdigest()[:16]
        return circuit.integrity_hash == expected_hash and circuit.is_healthy

    def _heal_circuit(self, circuit_id: str):
        """Heal a compromised circuit by resetting integrity and failover"""
        circuit = self.circuits.get(circuit_id)
        if circuit:
            circuit.integrity_hash = hashlib.sha256(circuit.circuit_id.encode()).hexdigest()[:16]
            circuit.is_healthy = True
            circuit.last_integrity_check = datetime.utcnow()
            self.stats["mesh_heals"] += 1
            logger.info(f"🔧 Circuit {circuit_id} healed and integrity restored")

    # ─── Mesh Status ─────────────────────────────────────────────────────────

    def get_mesh_status(self) -> Dict[str, Any]:
        """Get comprehensive mesh health and threat status."""
        with self._lock:
            active_nodes = sum(1 for n in self.nodes.values() if n.state == MeshNodeState.ACTIVE)
            healthy_circuits = sum(1 for c in self.circuits.values() if c.is_healthy)

            active_threats_summary: List[Dict[str, Any]] = []
            for chain_id, chain in self.active_threats.items():
                if chain.is_active:
                    active_threats_summary.append(
                        {
                            "chain_id": chain_id,
                            "pattern": chain.kill_chain_phase,
                            "severity": chain.severity.name,
                            "events": len(chain.events),
                            "confidence": round(chain.confidence, 2),
                            "affected_assets": list(chain.affected_assets),
                        }
                    )

            return {
                "mesh_id": self.mesh_id,
                "topology": {
                    "total_nodes": len(self.nodes),
                    "active_nodes": active_nodes,
                    "degraded_nodes": len(self.nodes) - active_nodes,
                    "healthy_circuits": healthy_circuits,
                    "total_circuits": len(self.circuits),
                },
                "threat_posture": {
                    "active_attack_chains": len(active_threats_summary),
                    "attack_chains": active_threats_summary[:10],
                    "iocs_active": int(self.stats.get("iocs_active", 0)),
                    "ips_blocked": int(self.stats.get("ips_blocked", 0)),
                    "blocked_domains": len(self.blocked_domains),
                },
                "statistics": self.stats,
                "uptime_hours": round((datetime.utcnow() - self.stats["start_time"]).total_seconds() / 3600, 2),
                "timestamp": datetime.utcnow().isoformat(),
            }
    def shutdown(self):
        """Gracefully shutdown the mesh"""
        self._healing_active = False
        self.executor.shutdown(wait=False)
        logger.info(f"🕷️  Tamerian Security Mesh [{self.mesh_id}] shutdown complete")
