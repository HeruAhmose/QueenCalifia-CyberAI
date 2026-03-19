"""
QC OS — Identity Core Engine v4.3
==================================
Real implementation of:
- Memory proposals across 4 lanes (personal, cyber, market, persona)
- Reflection proposals from conversation + telemetry
- Persona rule proposals
- Weekly self-notes
- Learning cycle (biomimetic sense → interpret → propose)
- Persona state aggregation

Public traffic never directly rewrites QC. Everything enters as proposals.
Admin approval creates durable identity changes.
"""
from __future__ import annotations

from core.database import get_db, utc_now, audit, log_event
from . import store

VALID_LANES = store.VALID_LANES


# ═══════════════════════════════════════════════════════════════
#  PROPOSALS (CRUD across all 4 memory lanes)
# ═══════════════════════════════════════════════════════════════

def create_proposal(db_path, lane: str, kind: str, content: str,
                    score: float = 0.5, source: str | None = None) -> dict:
    proposal = store.create_proposal(db_path, lane, kind, content, score=score, source=source)
    audit(db_path, "identity_proposal_create", "system", str(proposal["id"]),
          {"lane": lane, "kind": kind, "score": score})
    return {"id": proposal["id"], "lane": proposal["lane"], "kind": proposal["kind"], "status": proposal["status"]}


def list_pending(db_path, lane: str | None = None) -> list[dict]:
    return store.list_proposals(db_path, status="pending", lane=lane)


def approve_proposal(db_path, proposal_id: int) -> dict:
    row = store.promote_proposal_to_memory(db_path, proposal_id)
    audit(db_path, "identity_proposal_approve", "admin", str(proposal_id),
          {"lane": row["lane"], "kind": row["kind"]})
    return {"id": proposal_id, "status": "approved", "lane": row["lane"]}


def reject_proposal(db_path, proposal_id: int) -> dict:
    row = store.set_proposal_status(db_path, proposal_id, "rejected")
    audit(db_path, "identity_proposal_reject", "admin", str(proposal_id),
          {"lane": row["lane"], "kind": row["kind"]})
    return {"id": proposal_id, "status": "rejected", "lane": row["lane"]}


# ═══════════════════════════════════════════════════════════════
#  REFLECTIONS
# ═══════════════════════════════════════════════════════════════

def create_reflection(db_path, content: str, source: str | None = None) -> dict:
    reflection = store.create_reflection(db_path, content, source=source)
    audit(db_path, "reflection_create", "system", str(reflection["id"]), {"source": source})
    return {"id": reflection["id"], "status": reflection["status"]}


def list_pending_reflections(db_path) -> list[dict]:
    return store.list_reflections(db_path, status="pending")


def approve_reflection(db_path, rid: int) -> dict:
    store.set_reflection_status(db_path, rid, "approved")
    audit(db_path, "reflection_approve", "admin", str(rid), {})
    return {"id": rid, "status": "approved"}


def reject_reflection(db_path, rid: int) -> dict:
    store.set_reflection_status(db_path, rid, "rejected")
    return {"id": rid, "status": "rejected"}


# ═══════════════════════════════════════════════════════════════
#  PERSONA RULES
# ═══════════════════════════════════════════════════════════════

def create_persona_rule(db_path, rule_text: str) -> dict:
    rule = store.create_persona_rule(db_path, rule_text)
    audit(db_path, "persona_rule_create", "system", str(rule["id"]), {})
    return {"id": rule["id"], "status": rule["status"]}


def list_pending_rules(db_path) -> list[dict]:
    return store.list_persona_rules(db_path, status="pending")


def list_approved_rules(db_path) -> list[dict]:
    return store.list_persona_rules(db_path, status="approved")


def approve_rule(db_path, rid: int) -> dict:
    row = store.set_persona_rule_status(db_path, rid, "approved")
    audit(db_path, "persona_rule_approve", "admin", str(rid), {"rule": row["rule_text"]})
    return {"id": rid, "status": "approved"}


def reject_rule(db_path, rid: int) -> dict:
    store.set_persona_rule_status(db_path, rid, "rejected")
    return {"id": rid, "status": "rejected"}


# ═══════════════════════════════════════════════════════════════
#  SELF-NOTES
# ═══════════════════════════════════════════════════════════════

def create_self_note(db_path, note_text: str, period: str | None = None) -> dict:
    note = store.create_self_note(db_path, note_text, period=period)
    return {"id": note["id"], "status": note["status"]}


def list_pending_notes(db_path) -> list[dict]:
    return store.list_self_notes(db_path, status="pending")


def approve_note(db_path, nid: int) -> dict:
    store.set_self_note_status(db_path, nid, "approved")
    return {"id": nid, "status": "approved"}


def reject_note(db_path, nid: int) -> dict:
    store.set_self_note_status(db_path, nid, "rejected")
    return {"id": nid, "status": "rejected"}


# ═══════════════════════════════════════════════════════════════
#  PERSONA STATE (aggregated view)
# ═══════════════════════════════════════════════════════════════

def get_persona_state(db_path) -> dict:
    with get_db(db_path) as c:
        approved_rules = [
            {"id": r["id"], "rule_text": r["rule_text"], "created_at": r["created_at"]}
            for r in store.list_persona_rules(db_path, status="approved")
        ]
        approved_notes = len(store.list_self_notes(db_path, status="approved"))
        lane_memories = store.get_memory_lanes(db_path)
        lane_counts = {lane: len(items) for lane, items in lane_memories.items()}
        pending_total = len(store.list_proposals(db_path, status="pending"))
        pending_total += len(store.list_reflections(db_path, status="pending"))
        pending_total += len(store.list_persona_rules(db_path, status="pending"))
        pending_total += len(store.list_self_notes(db_path, status="pending"))
        latest_note = c.execute(
            "SELECT note_text, created_at FROM identity_self_notes WHERE status='approved' ORDER BY id DESC LIMIT 1"
        ).fetchone()

    return {
        "identity_summary": "Queen Califia: sovereign cybersecurity intelligence, market-aware, self-reflective.",
        "approved_rules": approved_rules,
        "approved_rules_count": len(approved_rules),
        "approved_notes_count": approved_notes,
        "memory_lanes": lane_counts,
        "memory_lane_items": lane_memories,
        "pending_items": pending_total,
        "latest_approved_note": dict(latest_note) if latest_note else None,
        "mode": "stable",
        "learning_enabled": True,
        "storage_contract": store.storage_contract(),
    }


# ═══════════════════════════════════════════════════════════════
#  LEARNING CYCLE (biomimetic sense → interpret → propose)
# ═══════════════════════════════════════════════════════════════

def run_learning_cycle(db_path) -> dict:
    """
    Read recent activity across all cores, generate proposals.
    This is the REAL learning cycle, not a stub.
    """
    now = utc_now()
    generated = {"proposals": 0, "reflections": 0, "rules": 0, "self_notes": 0}

    with get_db(db_path) as c:
        # SENSE: Gather recent conversation turns
        recent_turns = c.execute(
            "SELECT role, content, created_at FROM turns ORDER BY id DESC LIMIT 30"
        ).fetchall()

        # SENSE: Gather recent market snapshots
        recent_market = c.execute(
            "SELECT asset_type, symbol, source, price, created_at FROM market_snapshots ORDER BY id DESC LIMIT 20"
        ).fetchall()

        # SENSE: Gather recent forecast runs
        recent_forecasts = c.execute(
            "SELECT run_type, output_json, status, created_at FROM forecast_runs WHERE status='completed' ORDER BY id DESC LIMIT 10"
        ).fetchall()

        # SENSE: Gather recent audit events
        recent_events = c.execute(
            "SELECT event_type, actor, target, created_at FROM audit_log ORDER BY id DESC LIMIT 20"
        ).fetchall()

    # ── INTERPRET: Extract patterns from conversation ──
    user_turns = [dict(t) for t in recent_turns if t["role"] == "user"]

    if len(user_turns) >= 3:
        # Detect recurring topics
        all_words = " ".join(t["content"].lower() for t in user_turns).split()
        word_freq = {}
        stopwords = {"the", "a", "an", "is", "are", "was", "i", "my", "to", "and", "of", "in", "for", "it", "me", "you"}
        for w in all_words:
            if len(w) > 3 and w not in stopwords:
                word_freq[w] = word_freq.get(w, 0) + 1
        top_topics = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]

        if top_topics:
            topic_str = ", ".join(f"{w} ({n}x)" for w, n in top_topics)
            create_proposal(db_path, "personal", "recurring_topics",
                            f"User frequently discusses: {topic_str}",
                            score=0.6, source="learning_cycle")
            generated["proposals"] += 1

    # ── INTERPRET: Extract patterns from market activity ──
    market_data = [dict(m) for m in recent_market]
    if market_data:
        symbols_seen = list(set(m["symbol"] for m in market_data))
        if symbols_seen:
            create_proposal(db_path, "market", "watched_symbols",
                            f"Recently queried symbols: {', '.join(symbols_seen[:8])}",
                            score=0.55, source="learning_cycle")
            generated["proposals"] += 1

    # ── INTERPRET: Extract patterns from forecasts ──
    forecast_data = [dict(f) for f in recent_forecasts]
    if forecast_data:
        types_used = list(set(f["run_type"] for f in forecast_data))
        create_proposal(db_path, "market", "forecast_patterns",
                        f"Forecast types used: {', '.join(types_used)}",
                        score=0.5, source="learning_cycle")
        generated["proposals"] += 1

    # ── Generate reflection ──
    turn_count = len(recent_turns)
    market_count = len(market_data)
    forecast_count = len(forecast_data)

    reflection_text = (
        f"Learning cycle at {now}. Analyzed {turn_count} recent turns, "
        f"{market_count} market snapshots, {forecast_count} forecast runs. "
    )

    if user_turns:
        last_topic = user_turns[0]["content"][:100]
        reflection_text += f"Most recent user focus: '{last_topic}'. "

    if market_data:
        reflection_text += f"Active market symbols: {', '.join(symbols_seen[:5])}. "

    reflection_text += "Recommendation: continue building context density across all three cores."

    create_reflection(db_path, reflection_text, source="learning_cycle")
    generated["reflections"] += 1

    # ── Generate persona rule proposal if enough data ──
    if turn_count >= 10:
        create_persona_rule(db_path,
            "Prioritize context-rich responses that reference stored memories and recent market data.")
        generated["rules"] += 1

    # ── Generate weekly self-note ──
    event_count = len(recent_events)
    self_note = (
        f"Weekly self-note ({now}): {turn_count} conversation turns processed, "
        f"{market_count} market data points ingested, {forecast_count} forecasts run, "
        f"{event_count} system events logged. "
    )
    if market_data:
        self_note += f"Active research symbols: {', '.join(symbols_seen[:5])}. "
    self_note += "Identity continuity maintained. All proposals require admin approval."

    create_self_note(db_path, self_note, period="weekly")
    generated["self_notes"] += 1

    # Audit the cycle itself
    audit(db_path, "learning_cycle", "system", None, generated)
    log_event(db_path, "identity", "learning_cycle", "run", generated)

    return {
        "ok": True,
        "run_at": now,
        "generated": generated,
        "sensed": {
            "conversation_turns": turn_count,
            "market_snapshots": market_count,
            "forecast_runs": forecast_count,
            "audit_events": event_count,
        },
    }
