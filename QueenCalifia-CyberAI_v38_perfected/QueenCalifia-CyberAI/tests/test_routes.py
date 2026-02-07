from __future__ import annotations


def test_routes_registered(app_factory):
    app = app_factory(require_api_key=False)
    rules = {r.rule for r in app.url_map.iter_rules()}

    expected = {
        "/api/health",
        "/api/ready",
        "/api/mesh/status",
        "/api/threats/active",
        "/api/events/ingest",
        "/api/iocs",
        "/api/iocs/bulk",
        "/api/vulns/scan",
        "/api/vulns/scan/<scan_id>",
        "/api/vulns/status",
        "/api/vulns/remediation",
        "/api/vulns/webapp",
        "/api/incidents",
        "/api/incidents/<incident_id>",
        "/api/incidents/<incident_id>/approve/<action_id>",
        "/api/incidents/<incident_id>/deny/<action_id>",
        "/api/incidents/<incident_id>/rollback/<action_id>",
        "/api/ir/status",
        "/api/infra/spki-log",
        "/api/dashboard",
    }

    missing = expected - rules
    assert not missing, f"Missing route(s): {sorted(missing)}"
