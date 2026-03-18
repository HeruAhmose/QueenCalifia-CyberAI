"""QC OS — Conversation Routes v4.2.1"""
from __future__ import annotations
import uuid
from flask import Blueprint, jsonify, request, current_app
from core.auth import require_api_key
from modules.conversation.engine import process_message

conversation_bp = Blueprint("conversation", __name__)


@conversation_bp.post("/")
@require_api_key
def chat():
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", "")).strip()
    session_id = str(payload.get("session_id") or uuid.uuid4())
    user_id = str(payload.get("user_id") or "anonymous")
    mode = str(payload.get("mode", "cyber"))
    s = current_app.config["settings"]

    if not message:
        return jsonify({"error": "message is required"}), 400
    if len(message) > s.max_message_chars:
        return jsonify({"error": f"message exceeds {s.max_message_chars} characters"}), 400
    if mode not in ("cyber", "research", "lab"):
        return jsonify({"error": "mode must be cyber, research, or lab"}), 400

    result = process_message(db_path=s.db_path, message=message,
                             user_id=user_id, session_id=session_id, mode=mode)
    return jsonify(result)


@conversation_bp.get("/memories")
@require_api_key
def get_memories():
    user_id = request.args.get("user_id", "anonymous")
    s = current_app.config["settings"]
    from core.database import get_db
    with get_db(s.db_path) as c:
        rows = c.execute(
            "SELECT key,value,confidence,source,created_at FROM memories "
            "WHERE user_id=? ORDER BY id DESC LIMIT 20", (user_id,)
        ).fetchall()
    return jsonify({"memories": [dict(r) for r in rows]})
