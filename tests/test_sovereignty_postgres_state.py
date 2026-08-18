import os
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from sovereignty.approvals import PostgresApprovalStore, build_default_approval_store
from sovereignty.audit_chain import PostgresAuditChain, build_default_audit_chain
from sovereignty.schemas import ApprovalSignature, SignatureAlg


@pytest.fixture()
def postgres_url():
    url = os.environ.get("QC_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("QC_TEST_POSTGRES_URL is not configured")
    with psycopg.connect(url) as conn:
        conn.execute("DROP TABLE IF EXISTS qc_used_nonces")
        conn.execute("DROP TABLE IF EXISTS qc_approval_records")
        conn.execute("DROP TABLE IF EXISTS qc_audit_chain")
    return url


def _signature(name: str) -> ApprovalSignature:
    return ApprovalSignature(
        approver_id=name,
        key_id=f"{name}-key",
        alg=SignatureAlg.ed25519,
        signature_b64="A" * 88,
    )


def test_default_builders_select_postgresql(postgres_url, monkeypatch):
    monkeypatch.setenv("QC_DATABASE_URL", postgres_url)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert isinstance(build_default_approval_store(), PostgresApprovalStore)
    assert isinstance(build_default_audit_chain(), PostgresAuditChain)


def test_nonce_replay_is_atomic_across_replicas(postgres_url):
    stores = [PostgresApprovalStore(postgres_url) for _ in range(12)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda store: store.mark_nonce_used("shared-replay-nonce"), stores))
    assert results.count(True) == 1
    assert results.count(False) == 11


def test_signature_updates_do_not_lose_concurrent_approvers(postgres_url):
    seed = PostgresApprovalStore(postgres_url)
    record = seed.create(tenant_id="tenant", decision_hash="a" * 64, requested_by="requester")
    sigs = [_signature(f"approver-{i}") for i in range(8)]

    def add(sig):
        PostgresApprovalStore(postgres_url).add_signature(record.approval_id, sig)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add, sigs))

    restored = PostgresApprovalStore(postgres_url).get(record.approval_id)
    assert restored is not None
    assert {sig.approver_id for sig in restored.signatures} == {sig.approver_id for sig in sigs}


def test_audit_chain_serializes_multi_replica_appends(postgres_url):
    chains = [PostgresAuditChain(postgres_url) for _ in range(12)]

    def append(item):
        index, chain = item
        return chain.append({"event": "parallel", "writer": index})

    with ThreadPoolExecutor(max_workers=12) as pool:
        entries = list(pool.map(append, enumerate(chains)))

    assert sorted(entry.sequence for entry in entries) == list(range(12))
    restored = PostgresAuditChain(postgres_url)
    valid, bad_index = restored.verify()
    exported = restored.export_chain()
    assert restored.length == 12
    assert valid and bad_index is None
    assert [entry["sequence"] for entry in exported] == list(range(12))
    for index, entry in enumerate(exported):
        expected_prev = "0" * 64 if index == 0 else exported[index - 1]["chain_hash"]
        assert entry["prev_chain_hash"] == expected_prev
