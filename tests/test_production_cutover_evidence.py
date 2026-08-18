from __future__ import annotations

import os

import pytest

from scripts.postgres_database_manifest import (
    build_database_manifest,
    verify_database_manifest,
)
from scripts.verify_production_cutover_evidence import verify_evidence_bundle


HEX = "a" * 64


def _bundle():
    artifacts = [
        {"name": name, "status": "captured", "sha256": HEX}
        for name in (
            "primary-runtime-db",
            "evolution-db",
            "threat-intelligence-db",
            "live-scanner-db",
            "api-keys",
            "audit-log",
            "spki",
        )
    ]
    dispositions = [
        {"kind": kind, "verified": True, "evidence_sha256": HEX}
        for kind in (
            "api-keys",
            "audit-log",
            "spki",
            "vulnerability",
            "live-scanner",
        )
    ]
    return {
        "kind": "queen-califia-production-cutover-evidence",
        "version": 1,
        "environment": "production",
        "source_capture": {
            "captured_before_pod_replacement": True,
            "api_pod_uid": "11111111-2222-3333-4444-555555555555",
            "api_image_digest": "sha256:" + HEX,
            "artifacts": artifacts,
        },
        "runtime_migration": {"verified": True, "manifest_sha256": HEX},
        "dispositions": dispositions,
        "target_database": {
            "empty_before_import": True,
            "whole_database_manifest_sha256": HEX,
        },
        "backup_restore": {
            "separate_restore_database": True,
            "restore_verified": True,
            "dump_sha256": HEX,
            "source_manifest_sha256": HEX,
            "restored_manifest_sha256": HEX,
        },
        "post_cutover_authority": {
            "postgresql_probe_verified": True,
            "celery_redis_probe_verified": True,
            "legacy_writes_disabled_verified": True,
        },
        "source_retention": {
            "legacy_sources_preserved": True,
            "legacy_bindings_removed": False,
        },
    }


def test_cutover_evidence_accepts_complete_secret_free_bundle():
    result = verify_evidence_bundle(_bundle())
    assert result["verified"] is True
    assert result["eligible_for_legacy_binding_removal_review"] is True
    assert result["ha_authorized"] is False
    assert len(result["evidence_sha256"]) == 64


def test_cutover_evidence_requires_live_scanner_capture_before_replacement():
    bundle = _bundle()
    bundle["source_capture"]["captured_before_pod_replacement"] = False
    with pytest.raises(RuntimeError, match="captured_before_pod_replacement"):
        verify_evidence_bundle(bundle)


def test_cutover_evidence_requires_all_source_authorities():
    bundle = _bundle()
    bundle["source_capture"]["artifacts"] = [
        item
        for item in bundle["source_capture"]["artifacts"]
        if item["name"] != "live-scanner-db"
    ]
    with pytest.raises(RuntimeError, match="missing source artifact evidence"):
        verify_evidence_bundle(bundle)


def test_cutover_evidence_preserves_verified_absence_without_fake_disposition():
    bundle = _bundle()
    for item in bundle["source_capture"]["artifacts"]:
        if item["name"] == "spki":
            item.clear()
            item.update(
                {
                    "name": "spki",
                    "status": "verified-absent",
                    "checked": True,
                    "absence_reason": "SPKI evidence file did not exist in the frozen source pod",
                }
            )
    for disposition in bundle["dispositions"]:
        if disposition["kind"] == "spki":
            disposition.clear()
            disposition.update(
                {"kind": "spki", "status": "not-applicable-source-absent"}
            )
    assert verify_evidence_bundle(bundle)["verified"] is True


def test_cutover_evidence_rejects_fake_disposition_for_absent_source():
    bundle = _bundle()
    for item in bundle["source_capture"]["artifacts"]:
        if item["name"] == "spki":
            item.clear()
            item.update(
                {
                    "name": "spki",
                    "status": "verified-absent",
                    "checked": True,
                    "absence_reason": "not present",
                }
            )
    with pytest.raises(RuntimeError, match="preserve verified source absence"):
        verify_evidence_bundle(bundle)


def test_cutover_evidence_rejects_restore_manifest_mismatch():
    bundle = _bundle()
    bundle["backup_restore"]["restored_manifest_sha256"] = "b" * 64
    with pytest.raises(RuntimeError, match="source/restored"):
        verify_evidence_bundle(bundle)


def test_cutover_evidence_rejects_raw_database_urls_and_secret_fields():
    bundle = _bundle()
    bundle["operator_note"] = "postgresql://queen:password@db.example/queen"
    with pytest.raises(RuntimeError, match="forbidden credential/connection"):
        verify_evidence_bundle(bundle)

    bundle = _bundle()
    bundle["password"] = "should-never-be-recorded"
    with pytest.raises(RuntimeError, match="forbidden secret-bearing field"):
        verify_evidence_bundle(bundle)


def test_cutover_evidence_does_not_authorize_binding_removal_already_performed():
    bundle = _bundle()
    bundle["source_retention"]["legacy_bindings_removed"] = True
    with pytest.raises(RuntimeError, match="legacy_bindings_removed must remain false"):
        verify_evidence_bundle(bundle)


def test_whole_database_manifest_detects_post_manifest_mutation():
    url = os.getenv("QC_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("QC_TEST_POSTGRES_URL is required for PostgreSQL contract")

    import psycopg
    from psycopg import sql

    table = "qc_cutover_manifest_contract"
    table_ident = sql.Identifier(table)
    with psycopg.connect(url) as conn:
        conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(table_ident))
        conn.execute(
            sql.SQL(
                "CREATE TABLE {} (id BIGINT PRIMARY KEY, payload TEXT NOT NULL)"
            ).format(table_ident)
        )
        conn.execute(
            sql.SQL(
                "INSERT INTO {} (id, payload) VALUES (%s, %s), (%s, %s)"
            ).format(table_ident),
            (1, "alpha", 2, "beta"),
        )

    try:
        manifest = build_database_manifest(url)
        assert table in manifest["tables"]
        assert manifest["tables"][table]["rows"] == 2
        assert verify_database_manifest(manifest, url)["verified"] is True

        with psycopg.connect(url) as conn:
            conn.execute(
                sql.SQL("UPDATE {} SET payload=%s WHERE id=%s").format(table_ident),
                ("tampered", 2),
            )

        with pytest.raises(RuntimeError, match="does not match source database manifest"):
            verify_database_manifest(manifest, url)
    finally:
        with psycopg.connect(url) as conn:
            conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(table_ident))
