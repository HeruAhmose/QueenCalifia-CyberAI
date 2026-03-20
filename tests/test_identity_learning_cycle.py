"""Regression coverage for throttled automatic Identity Core learning."""

from __future__ import annotations

from pathlib import Path

from core.database import get_db, init_db
from backend.modules.identity.engine import run_learning_cycle_if_due


def _seed_activity(db_path: Path) -> None:
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO sessions (id, user_id, mode, created_at, updated_at) VALUES (?,?,?,?,?)",
            ("sess-1", "user-1", "cyber", "2026-03-20T00:00:00+00:00", "2026-03-20T00:00:00+00:00"),
        )
        c.execute(
            "INSERT INTO turns (session_id, role, content, created_at) VALUES (?,?,?,?)",
            ("sess-1", "user", "Please keep hardening production resilience and threat learning.", "2026-03-20T00:00:00+00:00"),
        )
        c.execute(
            "INSERT INTO turns (session_id, role, content, created_at) VALUES (?,?,?,?)",
            ("sess-1", "user", "Track market pressure and cyber readiness together.", "2026-03-20T00:01:00+00:00"),
        )
        c.execute(
            "INSERT INTO turns (session_id, role, content, created_at) VALUES (?,?,?,?)",
            ("sess-1", "user", "Remember that resilience and memory continuity matter most.", "2026-03-20T00:02:00+00:00"),
        )
        c.execute(
            "INSERT INTO market_snapshots (asset_type, symbol, source, price, quote_ccy, payload_json, created_at) VALUES (?,?,?,?,?,?,?)",
            ("macro", "FEDFUNDS", "fred", 5.25, "USD", "{}", "2026-03-20T00:03:00+00:00"),
        )
        c.execute(
            "INSERT INTO forecast_runs (id, user_id, run_type, input_json, output_json, status, created_at, completed_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "forecast-1",
                "user-1",
                "macro",
                "{}",
                "{}",
                "completed",
                "2026-03-20T00:04:00+00:00",
                "2026-03-20T00:05:00+00:00",
            ),
        )


def test_run_learning_cycle_if_due_runs_once_and_then_throttles(tmp_path, monkeypatch):
    db_path = tmp_path / "queen.db"
    init_db(db_path)
    _seed_activity(db_path)

    monkeypatch.setenv("QC_AUTO_LEARNING_ENABLED", "1")
    monkeypatch.setenv("QC_AUTO_LEARNING_INTERVAL_MINUTES", "180")

    first = run_learning_cycle_if_due(db_path)
    second = run_learning_cycle_if_due(db_path)

    assert first["ok"] is True
    assert first.get("skipped") is not True
    assert first["generated"]["reflections"] >= 1
    assert second["ok"] is True
    assert second["skipped"] is True
    assert second["reason"] == "interval_not_elapsed"

    with get_db(db_path) as c:
        proposal_count = c.execute("SELECT COUNT(*) AS cnt FROM identity_proposals").fetchone()["cnt"]
        reflection_count = c.execute("SELECT COUNT(*) AS cnt FROM identity_reflections").fetchone()["cnt"]
        note_count = c.execute("SELECT COUNT(*) AS cnt FROM identity_self_notes").fetchone()["cnt"]
        audit_count = c.execute(
            "SELECT COUNT(*) AS cnt FROM audit_log WHERE event_type IN ('learning_cycle', 'learning_cycle_auto')"
        ).fetchone()["cnt"]

    assert proposal_count >= 1
    assert reflection_count >= 1
    assert note_count >= 1
    assert audit_count >= 2
