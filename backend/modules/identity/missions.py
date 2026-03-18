"""
QC OS — Cyber Mission Memory v4.3
===================================
Mission CRUD, findings attachment, remediation generation and safe apply.
All actions are audit-logged. Apply is non-destructive.
"""
from __future__ import annotations

import json

from core.database import get_db, utc_now, audit, json_dumps


def create_mission(db_path, name: str, objective: str) -> dict:
    with get_db(db_path) as c:
        cur = c.execute(
            "INSERT INTO identity_missions (name,objective,status,created_at) VALUES (?,?,'open',?)",
            (name, objective, utc_now()),
        )
        mid = cur.lastrowid
    audit(db_path, "mission_create", "admin", str(mid), {"name": name})
    return {"id": mid, "name": name, "objective": objective, "status": "open"}


def list_missions(db_path) -> list[dict]:
    with get_db(db_path) as c:
        missions = c.execute(
            "SELECT * FROM identity_missions ORDER BY id DESC"
        ).fetchall()
        result = []
        for m in missions:
            d = dict(m)
            d["findings_count"] = c.execute(
                "SELECT COUNT(*) as cnt FROM identity_findings WHERE mission_id=?", (m["id"],)
            ).fetchone()["cnt"]
            d["has_remediation"] = c.execute(
                "SELECT COUNT(*) as cnt FROM identity_remediation WHERE mission_id=?", (m["id"],)
            ).fetchone()["cnt"] > 0
            result.append(d)
    return result


def get_mission(db_path, mission_id: int) -> dict | None:
    with get_db(db_path) as c:
        m = c.execute("SELECT * FROM identity_missions WHERE id=?", (mission_id,)).fetchone()
        if not m:
            return None
        d = dict(m)
        d["findings"] = [dict(f) for f in c.execute(
            "SELECT * FROM identity_findings WHERE mission_id=? ORDER BY id", (mission_id,)
        ).fetchall()]
        d["remediation_packages"] = [dict(r) for r in c.execute(
            "SELECT * FROM identity_remediation WHERE mission_id=? ORDER BY id DESC", (mission_id,)
        ).fetchall()]
    return d


def add_finding(db_path, mission_id: int, severity: str, summary: str,
                details: dict | None = None) -> dict:
    valid_sev = ("info", "low", "medium", "high", "critical")
    if severity not in valid_sev:
        raise ValueError(f"severity must be one of {valid_sev}")

    with get_db(db_path) as c:
        # Verify mission exists
        m = c.execute("SELECT id FROM identity_missions WHERE id=?", (mission_id,)).fetchone()
        if not m:
            raise ValueError(f"mission {mission_id} not found")
        cur = c.execute(
            "INSERT INTO identity_findings (mission_id,severity,summary,details_json,created_at) "
            "VALUES (?,?,?,?,?)",
            (mission_id, severity, summary, json_dumps(details or {}), utc_now()),
        )
    audit(db_path, "finding_add", "admin", str(cur.lastrowid),
          {"mission_id": mission_id, "severity": severity})
    return {"id": cur.lastrowid, "mission_id": mission_id, "severity": severity, "summary": summary}


def generate_remediation(db_path, mission_id: int) -> dict:
    """Generate a remediation package from all findings in a mission."""
    with get_db(db_path) as c:
        findings = c.execute(
            "SELECT * FROM identity_findings WHERE mission_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
            (mission_id,),
        ).fetchall()

        if not findings:
            return {"error": "no findings to remediate", "mission_id": mission_id}

        # Build remediation steps from findings
        steps = []
        for f in findings:
            fd = dict(f)
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

        cur = c.execute(
            "INSERT INTO identity_remediation (mission_id,package_json,applied,created_at) VALUES (?,?,0,?)",
            (mission_id, json_dumps(package), utc_now()),
        )
        package["package_id"] = cur.lastrowid

    audit(db_path, "remediation_generate", "system", str(mission_id),
          {"findings": len(findings), "package_id": package["package_id"]})
    return package


def apply_remediation(db_path, mission_id: int) -> dict:
    """Non-destructive apply: marks package as applied, logs audit trail."""
    with get_db(db_path) as c:
        pkg = c.execute(
            "SELECT * FROM identity_remediation WHERE mission_id=? AND applied=0 ORDER BY id DESC LIMIT 1",
            (mission_id,),
        ).fetchone()

        if not pkg:
            return {"error": "no unapplied remediation package found", "mission_id": mission_id}

        now = utc_now()
        c.execute(
            "UPDATE identity_remediation SET applied=1, applied_at=? WHERE id=?",
            (now, pkg["id"]),
        )

        # Update mission status
        c.execute(
            "UPDATE identity_missions SET status='in_progress' WHERE id=? AND status='open'",
            (mission_id,),
        )

    package_data = json.loads(pkg["package_json"])
    audit(db_path, "remediation_apply", "admin", str(mission_id),
          {"package_id": pkg["id"], "steps": len(package_data.get("steps", []))})

    return {
        "applied": True,
        "package_id": pkg["id"],
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
