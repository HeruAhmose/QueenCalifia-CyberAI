"""
QC OS — Identity Core Store v4.3
=================================

Canonical persistence layer for Identity Core.

The original build plan used `qc_*` table names. The stabilized runtime schema
uses `identity_*` tables plus the shared `memories` table for durable memory.
This store provides the planned CRUD surface while cleanly mapping it onto the
current production schema.
"""

from __future__ import annotations

from typing import Any

from core.database import get_db, json_dumps, utc_now


VALID_LANES = ("personal", "cyber", "market", "persona")
VALID_PROPOSAL_STATUS = ("pending", "approved", "rejected")
VALID_FINDING_SEVERITY = ("info", "low", "medium", "high", "critical")

PLAN_TABLE_MAP = {
    "qc_memory_proposals": "identity_proposals",
    "qc_reflections": "identity_reflections",
    "qc_persona_rules": "identity_persona_rules",
    "qc_self_notes": "identity_self_notes",
    "qc_runtime_provider": "identity_provider",
    "qc_cyber_missions": "identity_missions",
    "qc_cyber_findings": "identity_findings",
    "qc_remediation_packages": "identity_remediation",
    "qc_memory_lanes": "memories",
}


def storage_contract() -> dict[str, str]:
    """Expose the logical plan-to-runtime storage mapping."""
    return dict(PLAN_TABLE_MAP)


def _ensure_lane(lane: str) -> str:
    if lane not in VALID_LANES:
        raise ValueError(f"lane must be one of {VALID_LANES}")
    return lane


def _ensure_status(status: str) -> str:
    if status not in VALID_PROPOSAL_STATUS:
        raise ValueError(f"status must be one of {VALID_PROPOSAL_STATUS}")
    return status


def _rows(query_result) -> list[dict[str, Any]]:
    return [dict(r) for r in query_result.fetchall()]


def create_proposal(
    db_path,
    lane: str,
    kind: str,
    content: str,
    score: float = 0.5,
    source: str | None = None,
) -> dict[str, Any]:
    lane = _ensure_lane(lane)
    now = utc_now()
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_proposals (lane,kind,content,score,source,status,created_at) "
            "VALUES (?,?,?,?,?,'pending',?)",
            (lane, kind, content, score, source, now),
        )
        row = c.execute("SELECT * FROM identity_proposals WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def get_proposal(db_path, proposal_id: int) -> dict[str, Any] | None:
    with get_db(db_path) as c:
        row = c.execute("SELECT * FROM identity_proposals WHERE id=?", (proposal_id,)).fetchone()
    return dict(row) if row else None


def list_proposals(db_path, status: str = "pending", lane: str | None = None) -> list[dict[str, Any]]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        if lane:
            lane = _ensure_lane(lane)
            rows = c.execute(
                "SELECT * FROM identity_proposals WHERE status=? AND lane=? ORDER BY score DESC, id DESC",
                (status, lane),
            )
        else:
            rows = c.execute(
                "SELECT * FROM identity_proposals WHERE status=? ORDER BY score DESC, id DESC",
                (status,),
            )
        return _rows(rows)


def set_proposal_status(db_path, proposal_id: int, status: str) -> dict[str, Any]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        row = c.execute("SELECT * FROM identity_proposals WHERE id=?", (proposal_id,)).fetchone()
        if not row:
            raise ValueError(f"proposal {proposal_id} not found")
        c.execute("UPDATE identity_proposals SET status=? WHERE id=?", (status, proposal_id))
        updated = c.execute("SELECT * FROM identity_proposals WHERE id=?", (proposal_id,)).fetchone()
    return dict(updated)


def promote_proposal_to_memory(db_path, proposal_id: int) -> dict[str, Any]:
    with get_db(db_path) as c:
        row = c.execute(
            "SELECT * FROM identity_proposals WHERE id=? AND status='pending'",
            (proposal_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"proposal {proposal_id} not found or not pending")
        c.execute("UPDATE identity_proposals SET status='approved' WHERE id=?", (proposal_id,))
        c.execute(
            "INSERT OR IGNORE INTO memories (user_id,key,value,confidence,source,created_at) "
            "VALUES ('qc_identity',?,?,?,?,?)",
            (row["kind"], row["content"], row["score"], f"proposal:{proposal_id}", utc_now()),
        )
        updated = c.execute("SELECT * FROM identity_proposals WHERE id=?", (proposal_id,)).fetchone()
    return dict(updated)


def create_reflection(db_path, content: str, source: str | None = None) -> dict[str, Any]:
    now = utc_now()
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_reflections (content,source,status,created_at) VALUES (?,?,'pending',?)",
            (content, source, now),
        )
        row = c.execute("SELECT * FROM identity_reflections WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def list_reflections(db_path, status: str = "pending") -> list[dict[str, Any]]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        return _rows(c.execute("SELECT * FROM identity_reflections WHERE status=? ORDER BY id DESC", (status,)))


def set_reflection_status(db_path, reflection_id: int, status: str) -> dict[str, Any]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        row = c.execute("SELECT * FROM identity_reflections WHERE id=?", (reflection_id,)).fetchone()
        if not row:
            raise ValueError(f"reflection {reflection_id} not found")
        c.execute("UPDATE identity_reflections SET status=? WHERE id=?", (status, reflection_id))
        updated = c.execute("SELECT * FROM identity_reflections WHERE id=?", (reflection_id,)).fetchone()
    return dict(updated)


def create_persona_rule(db_path, rule_text: str) -> dict[str, Any]:
    now = utc_now()
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_persona_rules (rule_text,status,created_at) VALUES (?,'pending',?)",
            (rule_text, now),
        )
        row = c.execute("SELECT * FROM identity_persona_rules WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def list_persona_rules(db_path, status: str) -> list[dict[str, Any]]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        return _rows(c.execute("SELECT * FROM identity_persona_rules WHERE status=? ORDER BY id DESC", (status,)))


def set_persona_rule_status(db_path, rule_id: int, status: str) -> dict[str, Any]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        row = c.execute("SELECT * FROM identity_persona_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise ValueError(f"rule {rule_id} not found")
        c.execute("UPDATE identity_persona_rules SET status=? WHERE id=?", (status, rule_id))
        updated = c.execute("SELECT * FROM identity_persona_rules WHERE id=?", (rule_id,)).fetchone()
    return dict(updated)


def create_self_note(db_path, note_text: str, period: str | None = None) -> dict[str, Any]:
    now = utc_now()
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_self_notes (note_text,status,period,created_at) VALUES (?,'pending',?,?)",
            (note_text, period, now),
        )
        row = c.execute("SELECT * FROM identity_self_notes WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def list_self_notes(db_path, status: str = "pending") -> list[dict[str, Any]]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        return _rows(c.execute("SELECT * FROM identity_self_notes WHERE status=? ORDER BY id DESC", (status,)))


def set_self_note_status(db_path, note_id: int, status: str) -> dict[str, Any]:
    status = _ensure_status(status)
    with get_db(db_path) as c:
        row = c.execute("SELECT * FROM identity_self_notes WHERE id=?", (note_id,)).fetchone()
        if not row:
            raise ValueError(f"note {note_id} not found")
        c.execute("UPDATE identity_self_notes SET status=? WHERE id=?", (status, note_id))
        updated = c.execute("SELECT * FROM identity_self_notes WHERE id=?", (note_id,)).fetchone()
    return dict(updated)


def get_provider_config(db_path) -> dict[str, Any]:
    with get_db(db_path) as c:
        row = c.execute("SELECT provider, model, updated_at FROM identity_provider WHERE id=1").fetchone()
    if not row:
        return {"provider": "local_symbolic_core", "model": None, "updated_at": None}
    return dict(row)


def set_provider_config(db_path, provider: str, model: str | None = None) -> dict[str, Any]:
    now = utc_now()
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO identity_provider (id,provider,model,updated_at) VALUES (1,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET provider=excluded.provider, model=excluded.model, updated_at=excluded.updated_at",
            (provider, model, now),
        )
        row = c.execute("SELECT provider, model, updated_at FROM identity_provider WHERE id=1").fetchone()
    return dict(row)


def create_mission(db_path, name: str, objective: str) -> dict[str, Any]:
    now = utc_now()
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_missions (name,objective,status,created_at) VALUES (?,?,'open',?)",
            (name, objective, now),
        )
        row = c.execute("SELECT * FROM identity_missions WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def list_missions(db_path) -> list[dict[str, Any]]:
    with get_db(db_path) as c:
        missions = _rows(c.execute("SELECT * FROM identity_missions ORDER BY id DESC"))
        for mission in missions:
            mission["findings_count"] = c.execute(
                "SELECT COUNT(*) AS cnt FROM identity_findings WHERE mission_id=?",
                (mission["id"],),
            ).fetchone()["cnt"]
            mission["has_remediation"] = (
                c.execute(
                    "SELECT COUNT(*) AS cnt FROM identity_remediation WHERE mission_id=?",
                    (mission["id"],),
                ).fetchone()["cnt"]
                > 0
            )
    return missions


def get_mission(db_path, mission_id: int) -> dict[str, Any] | None:
    with get_db(db_path) as c:
        mission = c.execute("SELECT * FROM identity_missions WHERE id=?", (mission_id,)).fetchone()
        if not mission:
            return None
        result = dict(mission)
        result["findings"] = _rows(
            c.execute("SELECT * FROM identity_findings WHERE mission_id=? ORDER BY id", (mission_id,))
        )
        result["remediation_packages"] = _rows(
            c.execute("SELECT * FROM identity_remediation WHERE mission_id=? ORDER BY id DESC", (mission_id,))
        )
    return result


def create_finding(
    db_path,
    mission_id: int,
    severity: str,
    summary: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if severity not in VALID_FINDING_SEVERITY:
        raise ValueError(f"severity must be one of {VALID_FINDING_SEVERITY}")
    with get_db(db_path) as c:
        mission = c.execute("SELECT id FROM identity_missions WHERE id=?", (mission_id,)).fetchone()
        if not mission:
            raise ValueError(f"mission {mission_id} not found")
        cur = c.execute(
            "INSERT INTO identity_findings (mission_id,severity,summary,details_json,created_at) VALUES (?,?,?,?,?)",
            (mission_id, severity, summary, json_dumps(details or {}), utc_now()),
        )
        row = c.execute("SELECT * FROM identity_findings WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def list_findings_for_mission(db_path, mission_id: int) -> list[dict[str, Any]]:
    with get_db(db_path) as c:
        return _rows(c.execute("SELECT * FROM identity_findings WHERE mission_id=? ORDER BY id", (mission_id,)))


def create_remediation_package(db_path, mission_id: int, package: dict[str, Any]) -> dict[str, Any]:
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_remediation (mission_id,package_json,applied,created_at) VALUES (?,?,0,?)",
            (mission_id, json_dumps(package), utc_now()),
        )
        row = c.execute("SELECT * FROM identity_remediation WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def get_latest_unapplied_remediation(db_path, mission_id: int) -> dict[str, Any] | None:
    with get_db(db_path) as c:
        row = c.execute(
            "SELECT * FROM identity_remediation WHERE mission_id=? AND applied=0 ORDER BY id DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
    return dict(row) if row else None


def mark_remediation_applied(db_path, remediation_id: int) -> dict[str, Any]:
    now = utc_now()
    with get_db(db_path) as c:
        row = c.execute("SELECT * FROM identity_remediation WHERE id=?", (remediation_id,)).fetchone()
        if not row:
            raise ValueError(f"remediation package {remediation_id} not found")
        c.execute("UPDATE identity_remediation SET applied=1, applied_at=? WHERE id=?", (now, remediation_id))
        updated = c.execute("SELECT * FROM identity_remediation WHERE id=?", (remediation_id,)).fetchone()
        if updated["mission_id"]:
            c.execute(
                "UPDATE identity_missions SET status='in_progress' WHERE id=? AND status='open'",
                (updated["mission_id"],),
            )
    return dict(updated)


def get_memory_lanes(db_path) -> dict[str, list[dict[str, Any]]]:
    """
    Return durable identity memory organized by lane.

    Current runtime stores durable memory in the shared `memories` table and
    uses approved identity proposals as the canonical lane source.
    """
    lanes = {lane: [] for lane in VALID_LANES}
    with get_db(db_path) as c:
        approved = _rows(
            c.execute(
                "SELECT id, lane, kind, content, score, source, created_at FROM identity_proposals WHERE status='approved' ORDER BY id DESC"
            )
        )
        memory_rows = _rows(
            c.execute(
                "SELECT id, key, value, confidence, source, created_at FROM memories WHERE user_id='qc_identity' ORDER BY id DESC"
            )
        )

    proposal_index = {(row["kind"], row["content"]): row for row in approved}
    for mem in memory_rows:
        matched = proposal_index.get((mem["key"], mem["value"]))
        lane = matched["lane"] if matched else "persona"
        lanes[lane].append(
            {
                "memory_id": mem["id"],
                "key": mem["key"],
                "value": mem["value"],
                "confidence": mem["confidence"],
                "source": mem["source"],
                "created_at": mem["created_at"],
            }
        )

    # Preserve visibility into approved proposals that have not yet created a
    # distinct durable memory row (e.g. older data migrations).
    seen = {(m["key"], m["value"]) for items in lanes.values() for m in items}
    for row in approved:
        marker = (row["kind"], row["content"])
        if marker in seen:
            continue
        lanes[row["lane"]].append(
            {
                "memory_id": None,
                "key": row["kind"],
                "value": row["content"],
                "confidence": row["score"],
                "source": row["source"] or "identity_proposal",
                "created_at": row["created_at"],
            }
        )

    return lanes
