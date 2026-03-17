"""
QC OS — Quantum Research Worker
=================================
OPTIONAL module for hybrid quantum/classical optimization experiments.
Uses Qiskit (IBM Quantum) or Amazon Braket as backends.

Use cases:
  - Portfolio optimization (QAOA-based)
  - Combinatorial search
  - Feature selection research
  - Regime clustering research

CRITICAL: This is never the sole decision engine.
All quantum outputs feed into the forecast lab for human review.
"""
from __future__ import annotations

import os



QISKIT_AVAILABLE = False
BRAKET_AVAILABLE = False

try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    QISKIT_AVAILABLE = True
except ImportError:
    pass

try:
    import braket  # noqa: F401 — feature probe only
    BRAKET_AVAILABLE = bool(braket)
except ImportError:
    pass


def get_quantum_status() -> dict:
    """Report which quantum backends are available."""
    return {
        "qiskit_available": QISKIT_AVAILABLE,
        "braket_available": BRAKET_AVAILABLE,
        "active_backend": _active_backend(),
        "note": "Quantum module is for research experiments only. Never the sole decision engine.",
    }


def _active_backend() -> str:
    preferred = os.getenv("QC_QUANTUM_BACKEND", "simulator")
    if preferred == "qiskit" and QISKIT_AVAILABLE:
        return "qiskit"
    if preferred == "braket" and BRAKET_AVAILABLE:
        return "braket"
    if QISKIT_AVAILABLE:
        return "qiskit_simulator"
    return "classical_fallback"


def run_portfolio_optimization(
    assets: list[str],
    expected_returns: list[float],
    covariance: list[list[float]],
    risk_tolerance: float = 0.5,
) -> dict:
    """
    Run portfolio optimization experiment.
    If Qiskit available: uses QAOA-inspired approach on simulator.
    Otherwise: classical mean-variance fallback.
    """
    n = len(assets)

    if QISKIT_AVAILABLE and n <= 8:
        result = _qiskit_portfolio_opt(assets, expected_returns, covariance, risk_tolerance)
        result["backend"] = "qiskit_simulator"
    else:
        result = _classical_portfolio_opt(assets, expected_returns, covariance, risk_tolerance)
        result["backend"] = "classical"

    result["note"] = "Research output. Not a trading signal or allocation recommendation."
    return result


def _qiskit_portfolio_opt(
    assets: list[str],
    returns: list[float],
    cov: list[list[float]],
    risk_tolerance: float,
) -> dict:
    """Simplified quantum-inspired portfolio optimization via Qiskit."""
    n = len(assets)

    # Create a simple variational circuit
    qc = QuantumCircuit(n)
    for i in range(n):
        qc.h(i)
        qc.ry(returns[i] * 3.14159, i)
    for i in range(n - 1):
        qc.cx(i, i + 1)
    qc.measure_all()

    sim = AerSimulator()
    job = sim.run(qc, shots=1024)
    counts = job.result().get_counts()

    # Interpret measurement outcomes as portfolio weight candidates
    best_bitstring = max(counts, key=counts.get)
    weights = [int(b) for b in best_bitstring[:n]]
    total = sum(weights) or 1
    normalized = [w / total for w in weights]

    return {
        "assets": assets,
        "suggested_weights": {a: round(w, 4) for a, w in zip(assets, normalized)},
        "method": "qaoa_inspired_variational",
        "shots": 1024,
        "top_measurement": best_bitstring,
        "measurement_counts": len(counts),
    }


def _classical_portfolio_opt(
    assets: list[str],
    returns: list[float],
    cov: list[list[float]],
    risk_tolerance: float,
) -> dict:
    """Classical equal-risk-contribution fallback."""
    n = len(assets)

    # Inverse-variance weighting as simple heuristic
    variances = [cov[i][i] for i in range(n)] if cov else [1.0] * n
    inv_var = [1.0 / max(v, 1e-8) for v in variances]
    total = sum(inv_var)
    weights = [iv / total for iv in inv_var]

    return {
        "assets": assets,
        "suggested_weights": {a: round(w, 4) for a, w in zip(assets, weights)},
        "method": "inverse_variance",
    }
