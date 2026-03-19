"""
QC OS — Identity Provider Manager v4.3
========================================
Manages conversation backend: local_symbolic_core, ollama, vllm_local, auto.
Real health checks and model listing for Ollama and vLLM.
"""
from __future__ import annotations

import os

import requests as http

from core.database import audit
from . import store

OLLAMA_BASE = os.getenv("QC_OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_TIMEOUT = int(os.getenv("QC_OLLAMA_TIMEOUT_SECONDS", "10"))
VLLM_BASE = os.getenv("QC_VLLM_BASE_URL", "http://127.0.0.1:8000")
VLLM_TIMEOUT = int(os.getenv("QC_VLLM_TIMEOUT_SECONDS", "10"))

ALLOWED_PROVIDERS = ("local_symbolic_core", "ollama", "vllm_local", "auto")


def get_provider(db_path) -> dict:
    return store.get_provider_config(db_path)


def set_provider(db_path, provider: str, model: str | None = None) -> dict:
    if provider not in ALLOWED_PROVIDERS:
        raise ValueError(f"provider must be one of {ALLOWED_PROVIDERS}")
    config = store.set_provider_config(db_path, provider, model=model)
    audit(db_path, "provider_switch", "admin", provider, {"model": model})
    return config


def get_provider_status(db_path) -> dict:
    current = get_provider(db_path)
    ollama = ollama_health()
    vllm = vllm_health()
    return {
        "current": current,
        "available": list(ALLOWED_PROVIDERS),
        "ollama_reachable": ollama.get("reachable", False),
        "vllm_reachable": vllm.get("reachable", False),
    }


# ── Ollama ────────────────────────────────────────────────────

def ollama_health() -> dict:
    try:
        r = http.get(f"{OLLAMA_BASE}/api/tags", timeout=OLLAMA_TIMEOUT)
        if r.status_code == 200:
            return {"reachable": True, "status": "healthy", "base_url": OLLAMA_BASE}
        return {"reachable": False, "status": f"http_{r.status_code}", "base_url": OLLAMA_BASE}
    except Exception as e:
        return {"reachable": False, "status": str(e), "base_url": OLLAMA_BASE}


def ollama_models() -> dict:
    try:
        r = http.get(f"{OLLAMA_BASE}/api/tags", timeout=OLLAMA_TIMEOUT)
        if r.status_code != 200:
            return {"models": [], "error": f"http_{r.status_code}"}
        data = r.json()
        models = [{"name": m.get("name"), "size": m.get("size"),
                    "modified_at": m.get("modified_at")}
                   for m in data.get("models", [])]
        return {"models": models}
    except Exception as e:
        return {"models": [], "error": str(e)}


def ollama_pull(model: str) -> dict:
    try:
        r = http.post(f"{OLLAMA_BASE}/api/pull",
                       json={"name": model, "stream": False},
                       timeout=300)
        if r.status_code == 200:
            return {"ok": True, "model": model, "status": "pulled"}
        return {"ok": False, "model": model, "error": f"http_{r.status_code}"}
    except Exception as e:
        return {"ok": False, "model": model, "error": str(e)}


# ── vLLM ──────────────────────────────────────────────────────

def vllm_health() -> dict:
    try:
        r = http.get(f"{VLLM_BASE}/health", timeout=VLLM_TIMEOUT)
        if r.status_code == 200:
            return {"reachable": True, "status": "healthy", "base_url": VLLM_BASE}
        return {"reachable": False, "status": f"http_{r.status_code}", "base_url": VLLM_BASE}
    except Exception as e:
        return {"reachable": False, "status": str(e), "base_url": VLLM_BASE}
