"""
QC OS — Cyber Mission Memory v4.3
===================================
Mission CRUD, findings attachment, remediation generation and safe apply.
All actions are audit-logged. Apply is non-destructive.
"""
from __future__ import annotations

import json

from core.database import audit, utc_now
from . import store


def create_mission(db_path, name: str, objective: str) -> dict:
    mission = store.create_mission(db_path, name, objective)
    audit(db_path, "mission_create", "admin", str(mission["id"]), {"name": name})
    return {"id": mission["id"], "name": mission["name"], "objective": mission["objective"], "status": mission["status"]}


def list_missions(db_path) -> list[dict]:
    return store.list_missions(db_path)


def get_mission(db_path, mission_id: int) -> dict | None:
    return store.get_mission(db_path, mission_id)


def add_finding(db_path, mission_id: int, severity: str, summary: str,
                details: dict | None = None) -> dict:
    finding = store.create_finding(db_path, mission_id, severity, summary, details)
    audit(db_path, "finding_add", "admin", str(finding["id"]),
          {"mission_id": mission_id, "severity": severity})
    return {"id": finding["id"], "mission_id": mission_id, "severity": severity, "summary": summary}


def generate_remediation(db_path, mission_id: int) -> dict:
    """Generate a remediation package from all findings in a mission."""
    findings = store.list_findings_for_mission(db_path, mission_id)
    findings = sorted(
        findings,
        key=lambda f: {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(f["severity"], 5),
    )

    if not findings:
        return {"error": "no findings to remediate", "mission_id": mission_id}

    # Build remediation steps from findings
    steps = []
    for fd in findings:
        details = json.loads(fd.get("details_json", "{}"))
        step = {
            "finding_id": fd["id"],
            "severity": fd["severity"],
            "summary": fd["summary"],
            "details": details,
            "action": _suggest_action(fd["severity"], fd["summary"]),
            "priority": {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(fd["severity"], 5),
        }
        steps.append(step)

    package = {
        "mission_id": mission_id,
        "generated_at": utc_now(),
        "findings_count": len(findings),
        "steps": steps,
        "execution_mode": "paper",
        "requires_admin_apply": True,
    }

    created = store.create_remediation_package(db_path, mission_id, package)
    package["package_id"] = created["id"]

    audit(db_path, "remediation_generate", "system", str(mission_id),
          {"findings": len(findings), "package_id": package["package_id"]})
    return package


def apply_remediation(db_path, mission_id: int) -> dict:
    """Non-destructive apply: marks package as applied, logs audit trail."""
    pkg = store.get_latest_unapplied_remediation(db_path, mission_id)
    if not pkg:
        return {"error": "no unapplied remediation package found", "mission_id": mission_id}

    updated = store.mark_remediation_applied(db_path, pkg["id"])
    now = updated["applied_at"]
    package_data = json.loads(updated["package_json"])
    audit(db_path, "remediation_apply", "admin", str(mission_id),
          {"package_id": updated["id"], "steps": len(package_data.get("steps", []))})

    return {
        "applied": True,
        "package_id": updated["id"],
        "mission_id": mission_id,
        "applied_at": now,
        "steps_applied": len(package_data.get("steps", [])),
        "execution_mode": "non_destructive",
        "note": "Remediation marked as applied. Actual system changes require manual execution.",
    }


def _suggest_action(severity: str, summary: str) -> str:
    """Generate remediation action suggestion based on severity and summary."""
    low = summary.lower()
    if "patch" in low or "update" in low or "version" in low:
        return "Apply security patches and verify versions against known CVE databases."
    if "config" in low or "misconfigur" in low:
        return "Review and harden configuration against CIS benchmarks."
    if "credential" in low or "password" in low or "auth" in low:
        return "Rotate affected credentials and enforce MFA."
    if "firewall" in low or "port" in low or "exposed" in low:
        return "Review firewall rules and close unnecessary exposed ports."
    if "encrypt" in low or "tls" in low or "ssl" in low:
        return "Enforce TLS 1.3 minimum and review certificate chain."
    if severity == "critical":
        return "Immediate investigation required. Isolate affected systems and escalate."
    if severity == "high":
        return "Schedule immediate remediation within 24-48 hours."
    if severity == "medium":
        return "Add to sprint backlog for remediation within current cycle."
    return "Document and monitor. Review in next security assessment."
