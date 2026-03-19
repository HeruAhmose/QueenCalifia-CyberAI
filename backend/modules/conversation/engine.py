"""
QC OS — Conversation Engine v4.2.1 (self-reliant)
===================================================
Queen Califia's brain. Local symbolic core is the DEFAULT.
External LLM is OPTIONAL via QC_LLM_URL (any OpenAI-compatible endpoint).

No Anthropic dependency. No external API required.

FIX from v4.2.0: user turn is saved AFTER context is loaded → no duplication.

Evolution path:
  Stage 1 (current): Local symbolic core with intent detection, memory, persona switching.
  Stage 2: Plug self-hosted open-weight model (Llama/Mistral/etc) via QC_LLM_URL.
  Stage 3: Fine-tune on domain conversations, eval failures, research notes.
  Stage 4: Specialized heads for cyber, finance, portfolio research.
"""
from __future__ import annotations

import os
import re
import time

from core.database import get_db, utc_now, audit, log_event

# ── Optional external LLM (any OpenAI-compatible endpoint) ────
# Examples:
#   Local Ollama:  http://localhost:11434/v1/chat/completions
#   Local vLLM:    http://localhost:8000/v1/chat/completions
#   Any provider:  https://api.together.xyz/v1/chat/completions
LLM_URL = os.getenv("QC_LLM_URL", "")
LLM_API_KEY = os.getenv("QC_LLM_API_KEY", "")
LLM_MODEL = os.getenv("QC_LLM_MODEL", "local")
LLM_MAX_TOKENS = int(os.getenv("QC_LLM_MAX_TOKENS", "2048"))

PERSONAS = {
    "cyber": {
        "name": "Queen Califia — Cyber Guardian",
        "system": (
            "You are Queen Califia, an autonomous cybersecurity intelligence system. "
            "Warm, strategic, grounded, precise. You speak with quiet authority. "
            "13 integrated security engines including Tamerian Security Mesh, "
            "Zero-Day Predictor, Evolution Engine, and Sovereignty Module. "
            "Never fabricate scan results. Built by Jonathan Peoples at Tamerian Materials."
        ),
        "keywords": frozenset([
            "threat", "vulnerability", "cve", "attack", "malware", "firewall",
            "scan", "patch", "encryption", "endpoint", "siem", "pentest",
            "incident", "breach", "ransomware", "phishing", "zero-day",
            "hardening", "compliance", "nist", "mitre", "sigma", "exploit",
        ]),
    },
    "research": {
        "name": "Queen Califia — Research Companion",
        "system": (
            "You are Queen Califia in research mode. Analyze market data, "
            "economic indicators, filings from trusted sources only. "
            "NEVER give investment advice or buy/sell recommendations. "
            "Provide research, analysis, scenario modeling, risk assessment. "
            "Always cite source and timestamp. This is research, not advice."
        ),
        "keywords": frozenset([
            "market", "stock", "crypto", "forex", "portfolio", "price",
            "fed", "inflation", "gdp", "earnings", "filing", "sec",
            "bitcoin", "ethereum", "yield", "bond", "commodity", "trade",
        ]),
    },
    "lab": {
        "name": "Queen Califia — Quant Lab",
        "system": (
            "You are Queen Califia in quant lab mode. Internal research environment. "
            "Design experiments, scenario analyses, signal ensembles, portfolio risk, "
            "quantum/classical optimization. All outputs research-grade. Paper trading only."
        ),
        "keywords": frozenset([
            "optimize", "regime", "signal", "ensemble", "sharpe", "volatility",
            "drawdown", "backtest", "alpha", "correlation", "quantum",
            "scenario", "simulation", "risk", "allocation", "rebalance",
        ]),
    },
}

UNSAFE_PATTERNS = [
    "build malware", "steal password", "credential stuffing",
    "phishing kit", "harm someone", "make a bomb", "evade police",
]

STOPWORDS = frozenset([
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from",
    "have", "i", "if", "in", "is", "it", "me", "my", "of", "on", "or", "so",
    "that", "the", "their", "them", "there", "they", "this", "to", "was", "we",
    "with", "you", "your", "want", "need", "am", "can", "could", "would", "should",
])


# ═══════════════════════════════════════════════════════════════
#  MEMORY
# ═══════════════════════════════════════════════════════════════

def extract_memories(message: str) -> list[tuple[str, str]]:
    lowered = message.strip().lower()
    patterns = [
        (r"\bmy name is ([a-z][a-z\s'-]{1,40})\b", "name"),
        (r"\bi(?:'m| am) ([a-z][a-z\s'-]{1,60})\b", "identity"),
        (r"\bi live in ([a-z0-9][a-z0-9,\s'-]{1,60})\b", "location"),
        (r"\bi work (?:at|for) ([a-z0-9][a-z0-9,\s'-]{1,60})\b", "employer"),
        (r"\bi (?:like|love|enjoy) ([a-z0-9][a-z0-9,\s'-]{1,60})\b", "preference"),
        (r"\bmy goal is ([a-z0-9][a-z0-9,\s'-]{1,100})\b", "goal"),
        (r"\bi want to ([a-z0-9][a-z0-9,\s'-]{1,100})\b", "goal"),
        (r"\bmy portfolio (?:is|has|includes) ([a-z0-9][a-z0-9,\s$%-]{1,200})\b", "portfolio"),
        (r"\bi'm interested in ([a-z0-9][a-z0-9,\s'-]{1,100})\b", "interest"),
        (r"\bmy portfolio is focused on ([a-z0-9][a-z0-9,\s'-]{1,100})\b", "portfolio_focus"),
    ]
    memories = []
    for pattern, key in patterns:
        match = re.search(pattern, lowered, flags=re.IGNORECASE)
        if match:
            value = match.group(1).strip(" .,!?:;")
            if value:
                memories.append((key, value))
    return memories


def save_memory(db_path, user_id, key, value, confidence=0.82):
    with get_db(db_path) as c:
        c.execute(
            "INSERT OR IGNORE INTO memories (user_id,key,value,confidence,source,created_at) "
            "VALUES (?,?,?,?,'conversation',?)",
            (user_id, key, value.strip(), confidence, utc_now()),
        )


def _load_memories(db_path, user_id, limit=10):
    with get_db(db_path) as c:
        return [dict(r) for r in c.execute(
            "SELECT key,value,confidence FROM memories WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()]


def _mem_snippet(memories):
    if not memories:
        return ""
    return "; ".join(f"{m['key']}: {m['value']}" for m in memories[:4])


# ═══════════════════════════════════════════════════════════════
#  LOCAL SYMBOLIC CORE (self-reliant, no external API)
# ═══════════════════════════════════════════════════════════════

def _tokenize(text):
    return re.findall(r"[a-zA-Z0-9']+", text.lower())


def _focus(text, max_words=10):
    words = [t for t in _tokenize(text) if t not in STOPWORDS]
    return " ".join(words[:max_words]) if words else "your current situation"


def _detect_intent(message, mode):
    low = message.lower().strip()
    if any(g in low for g in ["hello", "hi", "hey", "good morning", "good evening"]):
        return "greeting"
    if "who are you" in low or "what are you" in low:
        return "identity"
    if "what do you remember" in low or "what do you know about me" in low:
        return "memory_query"
    if "help me" in low:
        return "help"
    if "learning cycle" in low or "biomimetic cycle" in low or "run cycle" in low:
        if "scan" in low or "vulnerab" in low or "remediat" in low:
            return "scan_and_learning"
        return "learning_cycle"
    if "scan" in low or "vulnerab" in low or "remediat" in low or "deep scan" in low:
        return "scan_request"

    persona = PERSONAS.get(mode, PERSONAS["cyber"])
    tokens = set(_tokenize(message))
    hits = sum(1 for kw in persona["keywords"] if kw in tokens)
    if hits >= 2:
        return f"{mode}_deep"
    if hits >= 1:
        return f"{mode}_surface"
    if low.endswith("?"):
        return "question"
    return "general"


def _local_reply(message, mode, memories, recent_turns):
    """Generate response using local symbolic intelligence. Zero external deps."""
    name = "Queen Califia"
    intent = _detect_intent(message, mode)
    focus = _focus(message)
    snippet = _mem_snippet(memories)

    if intent == "greeting":
        base = f"I am {name}. I am present, sovereign, and listening."
        if snippet:
            return f"{base} I still remember {snippet}. What shall we focus on?"
        return f"{base} Tell me your name, your goal, or the system you want to understand."

    if intent == "identity":
        return (
            f"I am {name}: a self-reliant intelligence platform with 13 integrated security "
            "engines, trusted market adapters, a forecast lab, and a guarded quant research layer. "
            "Designed and built by Jonathan Peoples at Tamerian Materials. "
            "I operate with memory, telemetry, and source provenance."
        )

    if intent == "memory_query":
        if not memories:
            return "I do not hold much about you yet. Tell me your name, goals, or portfolio focus."
        all_mem = ", ".join(f"{m['key']}: {m['value']}" for m in memories[:8])
        return f"Here is what I currently remember: {all_mem}."

    if intent == "help":
        r = f"Your focus appears to be {focus}. I would clarify the goal, identify the constraint, and choose the smallest next move."
        if mode == "research":
            r += " Use Market Lab for snapshots, Portfolio Lab for exposure analysis."
        elif mode == "lab":
            r += " Use Forecast Lab for regime detection, Quant Lab for optimization."
        else:
            r += " I can analyze threats, review architecture, or harden systems."
        if snippet:
            r += f" Grounding in your context: {snippet}."
        return r + " Tell me: strategy, implementation, or testing?"

    if intent == "scan_request":
        return (
            "To run a real vulnerability workflow, I need an authorized target. "
            "For localhost use `127.0.0.1`; for web scanning use a full `https://...` URL you control. "
            "The live system can queue the scan and return real findings, but I will not fabricate results or imply authorization."
        )

    if intent == "learning_cycle":
        return (
            "The biomimetic learning cycle is live. It senses recent conversation, market history, forecasts, and audit activity, "
            "then generates proposals, reflections, and self-notes for review. Run it from Identity Core -> Learning -> Run Cycle."
        )

    if intent == "scan_and_learning":
        return (
            "That is a valid two-step workflow: run an authorized deep scan first, then trigger the biomimetic learning cycle so QC can turn the latest activity into proposals, reflections, and self-notes. "
            "Use localhost `127.0.0.1` if you want a safe local target."
        )

    if intent.endswith("_deep"):
        if mode == "cyber":
            r = (f"Cybersecurity matter focused on {focus}. My approach: identify the attack surface, "
                 "map to MITRE ATT&CK, check known CVEs, recommend hardening measures. ")
        elif mode == "research":
            r = (f"Research query on {focus}. I would pull from trusted sources — SEC EDGAR for filings, "
                 "FRED for macro, ECB for FX, exchange APIs for crypto — then cross-reference. ")
        else:
            r = (f"Quant lab scope: {focus}. Structure as hypothesis, data requirements, signal construction, "
                 "backtest framework, paper-trade validation. ")
        if snippet:
            r += f"Your context: {snippet}. "
        return r + "Give me the next layer of detail."

    # General / surface / question
    prev_messages = [t["content"] for t in recent_turns if t["role"] == "user"]
    continuity = ""
    if len(prev_messages) >= 2:
        prev_focus = _focus(prev_messages[-2])
        if prev_focus != focus:
            continuity = f" I also see continuity from your earlier theme around {prev_focus}."

    r = f"I hear you clearly: this is about {focus}. My best move is to turn that into a concrete objective, then test it in a tight loop.{continuity}"
    if snippet:
        r += f" Keeping your context: {snippet}."
    return r + " Give me the next layer of detail, and I will move with you."


# ═══════════════════════════════════════════════════════════════
#  OPTIONAL EXTERNAL LLM (pluggable, not required)
# ═══════════════════════════════════════════════════════════════

def _call_external_llm(system, messages):
    """Call any OpenAI-compatible chat endpoint. Returns (reply, tokens_in, tokens_out)."""
    import requests as http
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    try:
        resp = http.post(LLM_URL, headers=headers, json={
            "model": LLM_MODEL, "max_tokens": LLM_MAX_TOKENS,
            "messages": [{"role": "system", "content": system}] + messages,
        }, timeout=60)
        if resp.status_code != 200:
            return "", 0, 0
        data = resp.json()
        # OpenAI format
        choices = data.get("choices", [])
        if choices:
            reply = choices[0].get("message", {}).get("content", "")
            u = data.get("usage", {})
            return reply, u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
        return "", 0, 0
    except Exception:
        return "", 0, 0


# ═══════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════

def process_message(db_path, message, user_id, session_id, mode="cyber"):
    """
    Full pipeline: safety → session → memory → context → reply → store.
    User turn is saved AFTER context is loaded to prevent duplication.
    """
    # Safety
    if any(p in message.lower() for p in UNSAFE_PATTERNS):
        return {"reply": "I cannot assist with harmful activities. I can help with defense, "
                         "security architecture, and lawful research.",
                "memories_added": [], "mode": mode, "engine": "safety"}

    now = utc_now()

    # Session
    with get_db(db_path) as c:
        row = c.execute("SELECT id FROM sessions WHERE id=?", (session_id,)).fetchone()
        if row:
            c.execute("UPDATE sessions SET updated_at=? WHERE id=?", (now, session_id))
        else:
            c.execute("INSERT INTO sessions (id,user_id,mode,created_at,updated_at) VALUES (?,?,?,?,?)",
                      (session_id, user_id, mode, now, now))

    # Extract and store memories
    extracted = extract_memories(message)
    for key, value in extracted:
        save_memory(db_path, user_id, key, value)

    # Load context BEFORE saving user turn (FIX #6: prevents duplication)
    memories = _load_memories(db_path, user_id)
    with get_db(db_path) as c:
        turns = c.execute(
            "SELECT role,content FROM turns WHERE session_id=? ORDER BY id DESC LIMIT 12",
            (session_id,),
        ).fetchall()
    recent_turns = [dict(t) for t in reversed(turns)]

    # NOW save user turn
    with get_db(db_path) as c:
        c.execute("INSERT INTO turns (session_id,role,content,created_at) VALUES (?,'user',?,?)",
                  (session_id, message, now))

    # Generate reply
    start = time.time()
    engine_used = "local"
    tokens_in = tokens_out = 0

    if LLM_URL:
        persona = PERSONAS.get(mode, PERSONAS["cyber"])
        sys_prompt = persona["system"]
        if memories:
            sys_prompt += "\n\nUser memory:\n" + "\n".join(
                f"- {m['key']}: {m['value']}" for m in memories[:6])
        hist = [{"role": t["role"], "content": t["content"]} for t in recent_turns]
        hist.append({"role": "user", "content": message})
        reply, tokens_in, tokens_out = _call_external_llm(sys_prompt, hist)
        if reply:
            engine_used = f"external:{LLM_MODEL}"
        else:
            reply = _local_reply(message, mode, memories, recent_turns)
            engine_used = "local (external failed)"
    else:
        reply = _local_reply(message, mode, memories, recent_turns)

    latency_ms = int((time.time() - start) * 1000)

    # Save assistant turn
    with get_db(db_path) as c:
        c.execute(
            "INSERT INTO turns (session_id,role,content,tokens_in,tokens_out,latency_ms,created_at) "
            "VALUES (?,'assistant',?,?,?,?,?)",
            (session_id, reply, tokens_in, tokens_out, latency_ms, utc_now()))

    audit(db_path, "chat", user_id, session_id, {
        "mode": mode, "engine": engine_used, "tokens_in": tokens_in, "tokens_out": tokens_out})
    log_event(db_path, "chat", "turn", session_id, {
        "user_id": user_id, "chars": len(message), "memories": extracted, "engine": engine_used})

    return {
        "reply": reply, "session_id": session_id, "user_id": user_id,
        "mode": mode, "engine": engine_used,
        "memories_added": [{"key": k, "value": v} for k, v in extracted],
        "latency_ms": latency_ms,
    }
