from __future__ import annotations


def test_evidence_crud(app_factory):
    app = app_factory(require_api_key=True)
    c = app.test_client()
    headers = {"X-QC-API-Key": "test-api-key"}

    r = c.post("/api/incidents", json={"title": "t", "description": "d"}, headers=headers)
    assert r.status_code in (200, 201)
    incident_id = r.get_json()["data"]["incident_id"]

    r = c.post(
        f"/api/incidents/{incident_id}/evidence",
        json={
            "evidence_type": "log_capture",
            "source": "sensor-1",
            "storage_location": "s3://bucket/key",
            "hash_sha256": "abc",
            "size_bytes": 123,
            "notes": "note",
        },
        headers=headers,
    )
    assert r.status_code == 200
    ev = r.get_json()["data"]
    ev_id = ev["evidence_id"]

    r = c.get(f"/api/incidents/{incident_id}/evidence", headers=headers)
    assert r.status_code == 200
    assert any(x["evidence_id"] == ev_id for x in r.get_json()["data"])

    r = c.get(f"/api/incidents/{incident_id}/evidence/{ev_id}", headers=headers)
    assert r.status_code == 200
    assert r.get_json()["data"]["evidence_id"] == ev_id

    r = c.delete(
        f"/api/incidents/{incident_id}/evidence/{ev_id}",
        json={"reason": "test"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.get_json()["data"]["tombstoned"] is True
