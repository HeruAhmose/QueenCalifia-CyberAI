"""Pytest fixtures for QueenCalifia CyberAI."""

from __future__ import annotations

import uuid
import hashlib
import json
import os
import sys

# Ensure repo root is importable under all pytest import modes
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dataclasses import dataclass
from typing import Any, Dict

import pytest

def _maybe_flush_redis() -> None:
    url = os.environ.get("QC_REDIS_URL", "").strip()
    if not url:
        return
    try:
        from core.redis_client import get_redis
        r = get_redis()
        r.flushdb()
    except Exception:
        return


from api.gateway import SecurityConfig, create_security_api


class DummyMesh:
    def get_mesh_status(self) -> Dict[str, Any]:
        return {"status": "ok"}

    def get_active_threats(self) -> Dict[str, Any]:
        return {"threats": []}

    def ingest_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {"accepted": True}

    def get_iocs(self) -> Dict[str, Any]:
        return {"iocs": []}

    def add_ioc(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        return {"added": True, "ioc": ioc}

    def add_iocs(self, iocs: list[Dict[str, Any]]) -> Dict[str, Any]:
        return {"added": len(iocs)}


class DummyVuln:
    def scan_target(self, target: str, scan_type: str = "full"):
        class _Scan:
            scan_id = "local-scan-1"

            def to_dict(self):
                return {"scan_id": self.scan_id, "target": target, "scan_type": scan_type}

        return _Scan()

    def submit_scan(self, target: str, scan_type: str = "full") -> Dict[str, Any]:
        return {"scan_id": "job-1", "status": "queued", "target": target, "scan_type": scan_type}

    def get_scan_job(self, scan_id: str):
        return {"scan_id": scan_id, "status": "queued"}

    def get_status(self):
        return {"status": "ok"}

    def get_remediation_templates(self):
        return {"templates": []}

    def scan_webapp(self, url: str):
        return {"url": url, "findings": []}


class DummyIncident:
    def __init__(self, incident_id: str, title: str, description: str):
        self.incident_id = incident_id
        self.title = title
        self.description = description

    def to_dict(self):
        return {"incident_id": self.incident_id, "title": self.title, "description": self.description}


class DummyIR:
    def __init__(self):
        self._evidence = {}
        self._incidents = {}

    def list_incidents(self):
        return []

    def create_incident(
        self,
        *,
        title: str,
        description: str,
        severity=None,
        category=None,
        source_events=None,
        attack_chain_id=None,
        affected_assets=None,
        indicators=None,
        mitre_techniques=None,
        auto_respond: bool = True,
    ):
        incident_id = "inc-1"
        inc = DummyIncident(incident_id, title, description)
        self._incidents[incident_id] = inc
        return inc

    def get_incident_report(self, incident_id: str):
        inc = self._incidents.get(incident_id)
        if not inc:
            return None
        return {"incident_id": incident_id, "title": inc.title, "description": inc.description, "actions": []}

    def approve_action(self, incident_id: str, action_id: str, approver: str):
        return True

    def deny_action(self, incident_id: str, action_id: str, approver: str, reason: str):
        return True

    def rollback_action(self, incident_id: str, action_id: str, actor: str, reason: str):
        return True

    def list_evidence(self, incident_id: str):
        return list(self._evidence.get(incident_id, []))

    def add_evidence(
        self,
        *,
        incident_id: str,
        evidence_type: str,
        source: str,
        storage_location: str,
        hash_sha256: str,
        size_bytes: int = 0,
        notes: str = "",
        collector: str = "test",
    ):
        ev_id = f"ev-{uuid.uuid4().hex[:6]}"
        ev = {
            "evidence_id": ev_id,
            "evidence_type": evidence_type,
            "source": source,
            "storage_location": storage_location,
            "hash_sha256": hash_sha256,
            "size_bytes": int(size_bytes or 0),
            "notes": notes,
            "collector": collector,
            "tombstoned": False,
            "chain_of_custody": [{"timestamp": "now", "actor": collector, "action": "ADDED", "details": ""}],
        }
        self._evidence.setdefault(incident_id, []).append(ev)
        return ev

    def get_evidence(self, incident_id: str, evidence_id: str):
        for ev in self._evidence.get(incident_id, []):
            if ev["evidence_id"] == evidence_id:
                return ev
        raise KeyError("evidence not found")

    def tombstone_evidence(self, *, incident_id: str, evidence_id: str, actor: str, reason: str = ""):
        ev = self.get_evidence(incident_id, evidence_id)
        ev["tombstoned"] = True
        ev["tombstoned_by"] = actor
        ev["tombstone_reason"] = reason
        return ev

    def get_status(self):
        return {"status": "ok"}


def _ensure_redis_prefix() -> None:
    if not os.environ.get("QC_REDIS_URL", "").strip():
        return
    if os.environ.get("QC_REDIS_PREFIX", "").strip():
        return
    os.environ["QC_REDIS_PREFIX"] = f"qc:test:{uuid.uuid4().hex}:"

def _make_keys_json(api_key: str, pepper: str) -> str:
    key_hash = hashlib.sha256((api_key + pepper).encode()).hexdigest()
    data = {
        "version": 1,
        "keys": [
            {
                "key_hash": key_hash,
                "role": "admin",
                "permissions": ["read", "write", "execute", "admin"],
                "rate_limit": 240,
                "created_at": "2026-02-05T00:00:00Z",
                "description": "test key",
                "revoked": False,
            }
        ],
    }
    return json.dumps(data)


@pytest.fixture()
def app_factory(tmp_path, monkeypatch):
    def _make(require_api_key: bool = True, production: bool = False):
        monkeypatch.setenv("QC_PRODUCTION", "1" if production else "0")
        monkeypatch.setenv("QC_LOG_FORMAT", "plain")
        monkeypatch.setenv("QC_AUDIT_LOG_FILE", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("QC_API_KEY_PEPPER", "pepper-test")
        monkeypatch.setenv("QC_AUDIT_HMAC_KEY", "hmac-test")
        if "QC_REDIS_URL" not in os.environ:
            monkeypatch.delenv("QC_REDIS_URL", raising=False)
        if "QC_BUDGET_ENABLED" not in os.environ:
            monkeypatch.setenv("QC_BUDGET_ENABLED", "0")

        if require_api_key:
            monkeypatch.setenv("QC_API_KEYS_JSON", _make_keys_json("test-api-key", "pepper-test"))
        else:
            monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)

        cfg = SecurityConfig(require_api_key=require_api_key, rate_limit_requests_per_minute=120)
        app = create_security_api(DummyMesh(), DummyVuln(), DummyIR(), config=cfg)
        app.testing = True
        return app

    return _make

@pytest.fixture(scope="session", autouse=True)
def redis_prefix_and_flush_session():
    _ensure_redis_prefix()
    _maybe_flush_redis()

@pytest.fixture(autouse=True)
def redis_flush_each_test():
    _maybe_flush_redis()
    yield
    _maybe_flush_redis()