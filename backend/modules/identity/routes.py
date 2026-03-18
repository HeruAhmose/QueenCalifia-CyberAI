"""QC OS — Identity Core Routes v4.3"""
from __future__ import annotations

from flask import Blueprint, jsonify, request, current_app
from core.auth import require_api_key, require_admin

identity_bp = Blueprint("identity", __name__)


def _db():
    return current_app.config["settings"].db_path


# ── Persona State ─────────────────────────────────────────────

@identity_bp.get("/state")
@require_api_key
def persona_state():
    from modules.identity.engine import get_persona_state
    return jsonify(get_persona_state(_db()))


# ── Memory Proposals ──────────────────────────────────────────

@identity_bp.get("/memory/pending")
@require_api_key
def pending_proposals():
    lane = request.args.get("lane")
    from modules.identity.engine import list_pending
    return jsonify({"items": list_pending(_db(), lane)})


@identity_bp.post("/memory/<int:pid>/approve")
@require_admin
def approve_proposal(pid):
    from modules.identity.engine import approve_proposal
    return jsonify(approve_proposal(_db(), pid))


@identity_bp.post("/memory/<int:pid>/reject")
@require_admin
def reject_proposal(pid):
    from modules.identity.engine import reject_proposal
    return jsonify(reject_proposal(_db(), pid))


# ── Reflections ───────────────────────────────────────────────

@identity_bp.get("/reflections/pending")
@require_api_key
def pending_reflections():
    from modules.identity.engine import list_pending_reflections
    return jsonify({"items": list_pending_reflections(_db())})


@identity_bp.post("/reflections/<int:rid>/approve")
@require_admin
def approve_reflection(rid):
    from modules.identity.engine import approve_reflection
    return jsonify(approve_reflection(_db(), rid))


@identity_bp.post("/reflections/<int:rid>/reject")
@require_admin
def reject_reflection(rid):
    from modules.identity.engine import reject_reflection
    return jsonify(reject_reflection(_db(), rid))


# ── Persona Rules ─────────────────────────────────────────────

@identity_bp.get("/rules/pending")
@require_api_key
def pending_rules():
    from modules.identity.engine import list_pending_rules
    return jsonify({"items": list_pending_rules(_db())})


@identity_bp.get("/rules/approved")
@require_api_key
def approved_rules():
    from modules.identity.engine import list_approved_rules
    return jsonify({"items": list_approved_rules(_db())})


@identity_bp.post("/rules/<int:rid>/approve")
@require_admin
def approve_rule(rid):
    from modules.identity.engine import approve_rule
    return jsonify(approve_rule(_db(), rid))


@identity_bp.post("/rules/<int:rid>/reject")
@require_admin
def reject_rule(rid):
    from modules.identity.engine import reject_rule
    return jsonify(reject_rule(_db(), rid))


# ── Self-Notes ────────────────────────────────────────────────

@identity_bp.get("/self-notes/pending")
@require_api_key
def pending_notes():
    from modules.identity.engine import list_pending_notes
    return jsonify({"items": list_pending_notes(_db())})


@identity_bp.post("/self-notes/<int:nid>/approve")
@require_admin
def approve_note(nid):
    from modules.identity.engine import approve_note
    return jsonify(approve_note(_db(), nid))


@identity_bp.post("/self-notes/<int:nid>/reject")
@require_admin
def reject_note(nid):
    from modules.identity.engine import reject_note
    return jsonify(reject_note(_db(), nid))


# ── Learning Cycle ────────────────────────────────────────────

@identity_bp.post("/learning/cycle/run")
@require_admin
def learning_cycle():
    from modules.identity.engine import run_learning_cycle
    return jsonify(run_learning_cycle(_db()))


# ── Provider Management ───────────────────────────────────────

@identity_bp.get("/provider-status")
@require_api_key
def provider_status():
    from modules.identity.provider import get_provider_status
    return jsonify(get_provider_status(_db()))


@identity_bp.post("/provider-status")
@require_admin
def set_provider():
    payload = request.get_json(silent=True) or {}
    provider = str(payload.get("provider", "")).strip()
    model = payload.get("model")
    from modules.identity.provider import set_provider as sp
    return jsonify(sp(_db(), provider, model))


@identity_bp.get("/ollama/health")
@require_api_key
def ollama_health():
    from modules.identity.provider import ollama_health as oh
    return jsonify(oh())


@identity_bp.get("/ollama/models")
@require_api_key
def ollama_models():
    from modules.identity.provider import ollama_models as om
    return jsonify(om())


@identity_bp.post("/ollama/pull")
@require_admin
def ollama_pull():
    payload = request.get_json(silent=True) or {}
    model = str(payload.get("model", "")).strip()
    if not model:
        return jsonify({"error": "model name required"}), 400
    from modules.identity.provider import ollama_pull as op
    return jsonify(op(model))


# ── Cyber Missions ────────────────────────────────────────────

@identity_bp.post("/missions")
@require_admin
def create_mission():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    objective = str(payload.get("objective", "")).strip()
    if not name or not objective:
        return jsonify({"error": "name and objective required"}), 400
    from modules.identity.missions import create_mission as cm
    return jsonify(cm(_db(), name, objective))


@identity_bp.get("/missions")
@require_api_key
def list_missions():
    from modules.identity.missions import list_missions as lm
    return jsonify({"items": lm(_db())})


@identity_bp.get("/missions/<int:mid>")
@require_api_key
def get_mission(mid):
    from modules.identity.missions import get_mission as gm
    result = gm(_db(), mid)
    if not result:
        return jsonify({"error": "mission not found"}), 404
    return jsonify(result)


@identity_bp.post("/missions/<int:mid>/findings")
@require_admin
def add_finding(mid):
    payload = request.get_json(silent=True) or {}
    severity = str(payload.get("severity", "medium")).strip()
    summary = str(payload.get("summary", "")).strip()
    details = payload.get("details")
    if not summary:
        return jsonify({"error": "summary required"}), 400
    from modules.identity.missions import add_finding as af
    return jsonify(af(_db(), mid, severity, summary, details))


@identity_bp.post("/missions/<int:mid>/remediation/generate")
@require_admin
def generate_remediation(mid):
    from modules.identity.missions import generate_remediation as gr
    return jsonify(gr(_db(), mid))


@identity_bp.post("/missions/<int:mid>/remediation/apply")
@require_admin
def apply_remediation(mid):
    from modules.identity.missions import apply_remediation as ar
    return jsonify(ar(_db(), mid))
