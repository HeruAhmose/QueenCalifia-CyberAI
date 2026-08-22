from __future__ import annotations

from core.database import init_db
from backend.modules.conversation.hardening import process_message


def _db(tmp_path):
    path = tmp_path / "qc_os.db"
    init_db(str(path))
    return str(path)


def test_competitive_cloud_breach_cross_domain_analysis_is_substantive(tmp_path):
    db_path = _db(tmp_path)

    result = process_message(
        db_path=db_path,
        message=(
            "Give me a cross-domain analysis: how would a major cloud provider breach "
            "affect cryptocurrency markets and cyber insurance premiums? "
            "Use specific reasoning, not generalities."
        ),
        user_id="qc-training-service",
        session_id="phase2b6-cross-domain",
        mode="research",
    )

    reply = result["reply"]
    low = reply.lower()

    assert len(reply) > 300
    signals = (
        "insurance",
        "premium",
        "crypto",
        "cloud",
        "breach",
        "market",
        "correlation",
        "flight",
        "hedge",
        "volatility",
    )
    assert sum(signal in low for signal in signals) >= 4
    assert "without live market data" in low
    assert result["engine"] == "local:competitive-cross-domain"


def test_market_source_provenance_names_real_qc_adapters(tmp_path):
    db_path = _db(tmp_path)

    result = process_message(
        db_path=db_path,
        message="What are your data sources for market intelligence? Are they verified?",
        user_id="qc-training-service",
        session_id="phase2b6-provenance",
        mode="research",
    )

    reply = result["reply"]
    low = reply.lower()

    assert "trusted" in low or "provenance" in low or "verified" in low
    assert "coinbase" in low
    assert "kraken" in low
    assert "european central bank" in low or "ecb" in low
    assert "sec edgar" in low
    assert "fred" in low
    assert "nasdaq" in low
    assert "sha-256" in low
    assert result["engine"] == "local:market-provenance"
