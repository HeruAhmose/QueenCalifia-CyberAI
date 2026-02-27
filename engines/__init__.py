"""
QueenCalifia CyberAI — Engine Registry (v4.0)
================================================
All 12 engines. Imports are lazy to avoid cascade failures.
"""

# Use lazy imports — only load when accessed
def __getattr__(name):
    """Lazy-load engines on demand to prevent import cascade errors."""
    _map = {
        "VulnerabilityEngine": "engines.vulnerability_engine",
        "IncidentResponseOrchestrator": "engines.incident_response",
        "ZeroDayPredictor": "engines.zero_day_predictor",
        "AdvancedTelemetry": "engines.advanced_telemetry",
        "LiveScanner": "engines.live_scanner",
        "AutoRemediation": "engines.auto_remediation",
        "EvolutionEngine": "engines.evolution_engine",
        "EntropyPool": "engines.quantum_engine",
        "LatticeKeyGenerator": "engines.quantum_engine",
        "QuantumKeyVault": "engines.quantum_engine",
        "quantum_hash": "engines.quantum_engine",
        "quantum_mac": "engines.quantum_engine",
        "quantum_random_bytes": "engines.quantum_engine",
        "assess_quantum_readiness": "engines.quantum_engine",
        "RedTeamEngine": "engines.red_team_tactics",
        "EngagementBounds": "engines.red_team_tactics",
        "DetectionRuleEngine": "engines.blue_team_tactics",
        "IOCCorrelationEngine": "engines.blue_team_tactics",
        "ThreatHuntEngine": "engines.blue_team_tactics",
        "SOAREngine": "engines.blue_team_tactics",
        "PurpleTeamOrchestrator": "engines.purple_team",
        "ContinuousValidator": "engines.purple_team",
        "ThreatIntelEngine": "engines.threat_intel_auto",
    }
    if name in _map:
        import importlib
        module = importlib.import_module(_map[name])
        return getattr(module, name)
    raise AttributeError(f"module 'engines' has no attribute {name!r}")


__all__ = [
    "VulnerabilityEngine", "IncidentResponseOrchestrator",
    "ZeroDayPredictor", "AdvancedTelemetry",
    "LiveScanner", "AutoRemediation", "EvolutionEngine",
    "EntropyPool", "LatticeKeyGenerator", "QuantumKeyVault",
    "quantum_hash", "quantum_mac", "quantum_random_bytes",
    "assess_quantum_readiness",
    "RedTeamEngine", "EngagementBounds",
    "DetectionRuleEngine", "IOCCorrelationEngine",
    "ThreatHuntEngine", "SOAREngine",
    "PurpleTeamOrchestrator", "ContinuousValidator",
    "ThreatIntelEngine",
]
