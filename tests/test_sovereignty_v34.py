"""
tests/test_sovereignty_v34.py — v3.4 Security Hardening Tests
===============================================================
Tests for:
  - Ed25519 asymmetric approval signing & verification
  - Executor full crypto approval pipeline
  - Audit hash chain tamper evidence
  - Hybrid signature enforcement (classical+PQ)
  - Idempotency guard requirement for containment
  - Approval lifecycle (create, sign, revoke, expire, replay)
  - Backward compatibility with legacy HMAC module
"""
import time
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sovereignty.schemas import (
    ActionRequest, ApprovalRecord, ApprovalSignature, ModelDecision,
    ProposedAction, RiskLevel, SignatureAlg, HybridSignaturePolicy,
)
from sovereignty.approvals import (
    DUAL_APPROVAL_ACTIONS, InMemoryApprovalStore, KeyRegistry, PublicKeyRecord,
    _approval_message, _b64e, check_hybrid_requirement, requires_dual_approval,
    sign_approval_ed25519, verify_signature,
)
from sovereignty.audit_chain import (
    GENESIS_HASH, AuditChain, AuditEntry, compute_chain_hash, compute_record_hash,
)
from sovereignty.executor import SovereigntyError, SovereigntyExecutor, stable_hash


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _keygen(name):
    priv = Ed25519PrivateKey.generate()
    pub_b64 = _b64e(priv.public_key().public_bytes_raw())
    return {"private": priv, "pub_b64": pub_b64, "key_id": f"{name}-key", "owner": name}


@pytest.fixture
def alice():
    return _keygen("alice")

@pytest.fixture
def bob():
    return _keygen("bob")

@pytest.fixture
def carol():
    return _keygen("carol")

@pytest.fixture
def registry(alice, bob, carol):
    return KeyRegistry([
        PublicKeyRecord(key_id=u["key_id"], alg=SignatureAlg.ed25519, owner_id=u["owner"], public_key_b64=u["pub_b64"])
        for u in (alice, bob, carol)
    ])

@pytest.fixture
def store():
    return InMemoryApprovalStore()

@pytest.fixture
def decision():
    return ModelDecision(
        action=ProposedAction.contain_host, confidence=0.95, risk=RiskLevel.high,
        summary="Contain compromised host", rationale="IOC match with C2 callback",
    )

@pytest.fixture
def dhash(decision):
    return stable_hash(decision.model_dump())

def _sign(user, dhash, nonce):
    return sign_approval_ed25519(
        private_key=user["private"], key_id=user["key_id"],
        approver_id=user["owner"], decision_hash=dhash, nonce=nonce,
    )

def _executor(store, registry, audit_records=None, idemp=lambda r: False, hybrid=None):
    recs = audit_records if audit_records is not None else []
    return SovereigntyExecutor(
        audit_write_fn=lambda r: recs.append(r),
        action_dispatch_fn=lambda r: {"status": "ok"},
        approval_store=store, key_registry=registry,
        idempotency_check_fn=idemp,
        hybrid_policy=hybrid,
    )

def _req(decision, actor_id="exec-admin", approval_id=None, dry_run=False, env="prod"):
    return ActionRequest(
        decision=decision, actor_id=actor_id, actor_role="admin",
        environment=env, tenant_id="t1", dry_run=dry_run, approval_id=approval_id,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Ed25519 SIGNATURE VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestEd25519Signatures:

    def test_sign_produces_valid_signature(self, alice, registry):
        sig = _sign(alice, "a" * 64, "nonce-123456789")
        assert sig.alg == SignatureAlg.ed25519
        assert verify_signature(key_registry=registry, decision_hash="a" * 64, nonce="nonce-123456789", sig=sig)

    def test_wrong_decision_hash_fails(self, alice, registry):
        sig = _sign(alice, "a" * 64, "n1")
        assert not verify_signature(key_registry=registry, decision_hash="b" * 64, nonce="n1", sig=sig)

    def test_wrong_nonce_fails(self, alice, registry):
        sig = _sign(alice, "c" * 64, "correct")
        assert not verify_signature(key_registry=registry, decision_hash="c" * 64, nonce="wrong", sig=sig)

    def test_unknown_key_fails(self, alice, registry):
        sig = sign_approval_ed25519(
            private_key=alice["private"], key_id="unknown-key",
            approver_id="alice", decision_hash="d" * 64, nonce="n",
        )
        assert not verify_signature(key_registry=registry, decision_hash="d" * 64, nonce="n", sig=sig)

    def test_wrong_owner_fails(self, alice, registry):
        """Signature claims bob but uses alice's key."""
        sig = sign_approval_ed25519(
            private_key=alice["private"], key_id=alice["key_id"],
            approver_id="bob", decision_hash="e" * 64, nonce="n",
        )
        assert not verify_signature(key_registry=registry, decision_hash="e" * 64, nonce="n", sig=sig)

    def test_tampered_signature_fails(self, alice, registry):
        sig = _sign(alice, "f" * 64, "n")
        tampered = ApprovalSignature(
            approver_id=sig.approver_id, key_id=sig.key_id,
            alg=sig.alg, signature_b64=_b64e(b"\x00" * 64),
        )
        assert not verify_signature(key_registry=registry, decision_hash="f" * 64, nonce="n", sig=tampered)

    def test_two_users_same_approval(self, alice, bob, registry):
        for user in (alice, bob):
            sig = _sign(user, "g" * 64, "shared-nonce")
            assert verify_signature(key_registry=registry, decision_hash="g" * 64, nonce="shared-nonce", sig=sig)

    def test_pq_without_hook_fails(self, registry):
        sig = ApprovalSignature(approver_id="alice", key_id="pq-key", alg=SignatureAlg.dilithium3, signature_b64=_b64e(b"\x00" * 128))
        assert not verify_signature(key_registry=registry, decision_hash="h" * 64, nonce="n", sig=sig)


# ═══════════════════════════════════════════════════════════════════════════════
# APPROVAL STORE LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════════

class TestApprovalLifecycle:

    def test_create_approval(self, store):
        rec = store.create(tenant_id="t1", decision_hash="a" * 64, requested_by="alice")
        assert rec.approval_id and rec.nonce and rec.expires_at > time.time()

    def test_add_signature(self, store, bob):
        rec = store.create(tenant_id="t1", decision_hash="b" * 64, requested_by="alice")
        sig = _sign(bob, rec.decision_hash, rec.nonce)
        updated = store.add_signature(rec.approval_id, sig)
        assert len(updated.signatures) == 1

    def test_duplicate_approver_alg_rejected(self, store, bob):
        rec = store.create(tenant_id="t1", decision_hash="c" * 64, requested_by="alice")
        sig = _sign(bob, rec.decision_hash, rec.nonce)
        store.add_signature(rec.approval_id, sig)
        with pytest.raises(ValueError, match="already signed"):
            store.add_signature(rec.approval_id, sig)

    def test_revoke(self, store):
        rec = store.create(tenant_id="t1", decision_hash="d" * 64, requested_by="alice")
        assert store.revoke(rec.approval_id)
        assert store.get(rec.approval_id).revoked

    def test_add_sig_to_revoked_fails(self, store, bob):
        rec = store.create(tenant_id="t1", decision_hash="e" * 64, requested_by="alice")
        store.revoke(rec.approval_id)
        with pytest.raises(ValueError, match="revoked"):
            store.add_signature(rec.approval_id, _sign(bob, rec.decision_hash, rec.nonce))

    def test_nonce_single_use(self, store):
        assert store.mark_nonce_used("n1")
        assert not store.mark_nonce_used("n1")

    def test_get_nonexistent(self, store):
        assert store.get("nope") is None

    def test_revoke_nonexistent(self, store):
        assert not store.revoke("nope")


# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTOR CRYPTO VERIFICATION — FULL PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecutorCryptoVerification:

    def test_happy_path_dual_approval(self, store, registry, alice, bob, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.add_signature(rec.approval_id, _sign(bob, dhash, rec.nonce))
        ex = _executor(store, registry)
        result = ex.execute(_req(decision, actor_id="exec-admin", approval_id=rec.approval_id, dry_run=False))
        assert result["status"] == "executed"

    def test_missing_approval_id_blocked(self, store, registry, decision):
        with pytest.raises(SovereigntyError, match="Approval required"):
            _executor(store, registry).execute(_req(decision, approval_id=None))

    def test_invalid_approval_id_blocked(self, store, registry, decision):
        with pytest.raises(SovereigntyError, match="Invalid approval_id"):
            _executor(store, registry).execute(_req(decision, approval_id="fake"))

    def test_revoked_blocked(self, store, registry, alice, bob, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.revoke(rec.approval_id)
        with pytest.raises(SovereigntyError, match="revoked"):
            _executor(store, registry).execute(_req(decision, approval_id=rec.approval_id, dry_run=False))

    def test_expired_blocked(self, store, registry, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol", ttl_sec=0)
        time.sleep(0.01)
        with pytest.raises(SovereigntyError, match="expired"):
            _executor(store, registry).execute(_req(decision, approval_id=rec.approval_id))

    def test_hash_mismatch_blocked(self, store, registry, alice, bob, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash="z" * 64, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, "z" * 64, rec.nonce))
        with pytest.raises(SovereigntyError, match="hash mismatch"):
            _executor(store, registry).execute(_req(decision, approval_id=rec.approval_id))

    def test_two_person_rule_blocks_requester(self, store, registry, alice, bob, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.add_signature(rec.approval_id, _sign(bob, dhash, rec.nonce))
        with pytest.raises(SovereigntyError, match="Two-person rule"):
            _executor(store, registry).execute(_req(decision, actor_id="carol", approval_id=rec.approval_id, dry_run=False))

    def test_nonce_replay_blocked(self, store, registry, alice, bob, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.add_signature(rec.approval_id, _sign(bob, dhash, rec.nonce))
        ex = _executor(store, registry)
        req = _req(decision, approval_id=rec.approval_id, dry_run=False)
        ex.execute(req)
        with pytest.raises(SovereigntyError, match="replay"):
            ex.execute(req)

    def test_insufficient_signatures_blocked(self, store, registry, alice, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        with pytest.raises(SovereigntyError, match="Insufficient"):
            _executor(store, registry).execute(_req(decision, approval_id=rec.approval_id, dry_run=False))

    def test_executor_sig_excluded(self, store, registry, alice, bob, decision, dhash):
        """If executor is also a signer, their sig doesn't count."""
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.add_signature(rec.approval_id, _sign(bob, dhash, rec.nonce))
        with pytest.raises(SovereigntyError, match="Insufficient"):
            _executor(store, registry).execute(_req(decision, actor_id="alice", approval_id=rec.approval_id, dry_run=False))

    def test_dev_single_approval_ok(self, store, registry, alice, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        req = ActionRequest(
            decision=decision, actor_id="exec", actor_role="admin",
            environment="dev", tenant_id="t1", dry_run=False, approval_id=rec.approval_id,
        )
        result = _executor(store, registry).execute(req)
        assert result["status"] in ("executed", "dry_run")

    def test_dry_run_with_approval(self, store, registry, alice, bob, decision, dhash):
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.add_signature(rec.approval_id, _sign(bob, dhash, rec.nonce))
        result = _executor(store, registry).execute(_req(decision, approval_id=rec.approval_id, dry_run=True))
        assert result["status"] == "dry_run"

    def test_audit_records_have_actor_id(self, store, registry):
        recs = []
        ex = _executor(store, registry, recs)
        req = ActionRequest(
            decision=ModelDecision(action=ProposedAction.recommend, confidence=0.5, summary="T", rationale="T"),
            actor_id="test-42", actor_role="analyst", environment="dev", tenant_id="t1",
        )
        ex.execute(req)
        assert any(r.get("actor_id") == "test-42" for r in recs)


# ═══════════════════════════════════════════════════════════════════════════════
# IDEMPOTENCY GUARD REQUIREMENT
# ═══════════════════════════════════════════════════════════════════════════════

class TestIdempotencyGuard:

    def test_containment_requires_idempotency_fn(self, store, registry, alice, bob, decision, dhash):
        """Containment without idempotency_check_fn configured is blocked."""
        rec = store.create(tenant_id="t1", decision_hash=dhash, requested_by="carol")
        store.add_signature(rec.approval_id, _sign(alice, dhash, rec.nonce))
        store.add_signature(rec.approval_id, _sign(bob, dhash, rec.nonce))
        # Executor WITHOUT idempotency_check_fn
        ex = SovereigntyExecutor(
            audit_write_fn=lambda r: None,
            action_dispatch_fn=lambda r: {"ok": True},
            approval_store=store, key_registry=registry,
            idempotency_check_fn=None,  # missing!
        )
        with pytest.raises(SovereigntyError, match="Idempotency guard required"):
            ex.execute(_req(decision, approval_id=rec.approval_id, dry_run=False))

    def test_recommend_ok_without_idempotency(self, store, registry):
        """Non-containment actions work without idempotency guard."""
        ex = SovereigntyExecutor(
            audit_write_fn=lambda r: None,
            approval_store=store, key_registry=registry,
            idempotency_check_fn=None,
        )
        req = ActionRequest(
            decision=ModelDecision(action=ProposedAction.recommend, confidence=0.5, summary="T", rationale="T"),
            actor_role="analyst", environment="dev", tenant_id="t1",
        )
        result = ex.execute(req)
        assert result["status"] == "executed"


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT HASH CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditChain:

    def test_empty_verifies(self):
        assert AuditChain().verify() == (True, None)

    def test_single_entry(self):
        c = AuditChain()
        e = c.append({"event": "test"})
        assert e.sequence == 0 and e.prev_chain_hash == GENESIS_HASH
        assert c.length == 1

    def test_chain_linkage(self):
        c = AuditChain()
        e1 = c.append({"e": 1})
        e2 = c.append({"e": 2})
        assert e2.prev_chain_hash == e1.chain_hash

    def test_10_entries_verify(self):
        c = AuditChain()
        for i in range(10):
            c.append({"i": i})
        assert c.verify() == (True, None)

    def test_tampered_record_detected(self):
        c = AuditChain()
        c.append({"e": 1}); c.append({"e": 2}); c.append({"e": 3})
        orig = c._entries[1]
        c._entries[1] = AuditEntry(
            sequence=orig.sequence, timestamp=orig.timestamp,
            record={"e": "TAMPERED"}, record_hash=orig.record_hash,
            prev_chain_hash=orig.prev_chain_hash, chain_hash=orig.chain_hash,
        )
        valid, idx = c.verify()
        assert not valid and idx == 1

    def test_broken_linkage_detected(self):
        c = AuditChain()
        c.append({"e": 1}); c.append({"e": 2})
        orig = c._entries[1]
        c._entries[1] = AuditEntry(
            sequence=orig.sequence, timestamp=orig.timestamp,
            record=orig.record, record_hash=orig.record_hash,
            prev_chain_hash="0" * 64, chain_hash=orig.chain_hash,
        )
        assert c.verify()[0] is False

    def test_verify_single_entry(self):
        c = AuditChain()
        c.append({"e": 1}); c.append({"e": 2})
        assert c.verify_entry(0) and c.verify_entry(1) and not c.verify_entry(99)

    def test_export(self):
        c = AuditChain()
        c.append({"e": 1}); c.append({"e": 2})
        exp = c.export_chain()
        assert len(exp) == 2 and "chain_hash" in exp[0]

    def test_head_hash_updates(self):
        c = AuditChain()
        assert c.head_hash == GENESIS_HASH
        e = c.append({"e": 1})
        assert c.head_hash == e.chain_hash

    def test_different_algs_different_hashes(self):
        c256 = AuditChain(hash_alg="sha256")
        c512 = AuditChain(hash_alg="sha512")
        c256.append({"same": True}); c512.append({"same": True})
        assert c256.head_hash != c512.head_hash

    def test_persist_callback(self):
        persisted = []
        c = AuditChain(persist_fn=lambda e: persisted.append(e))
        c.append({"test": 1})
        assert len(persisted) == 1

    def test_executor_chains_records(self, store, registry):
        chain = AuditChain()
        ex = SovereigntyExecutor(
            audit_write_fn=lambda r: None, approval_store=store,
            key_registry=registry, audit_chain=chain,
        )
        ex.execute(ActionRequest(
            decision=ModelDecision(action=ProposedAction.recommend, confidence=0.5, summary="T", rationale="T"),
            actor_role="analyst", environment="dev", tenant_id="t1",
        ))
        assert chain.length > 0 and chain.verify() == (True, None)


# ═══════════════════════════════════════════════════════════════════════════════
# HYBRID SIGNATURE POLICY
# ═══════════════════════════════════════════════════════════════════════════════

class TestHybridPolicy:

    def test_hybrid_not_required_by_default(self):
        ok, _ = check_hybrid_requirement([], "alice")
        assert ok

    def test_hybrid_missing_classical(self):
        pol = HybridSignaturePolicy(require_hybrid=True)
        sigs = [ApprovalSignature(approver_id="alice", key_id="k", alg=SignatureAlg.dilithium3, signature_b64="a" * 64)]
        ok, reason = check_hybrid_requirement(sigs, "alice", pol)
        assert not ok and "classical" in reason.lower()

    def test_hybrid_missing_pq(self):
        pol = HybridSignaturePolicy(require_hybrid=True)
        sigs = [ApprovalSignature(approver_id="alice", key_id="k", alg=SignatureAlg.ed25519, signature_b64="a" * 64)]
        ok, reason = check_hybrid_requirement(sigs, "alice", pol)
        assert not ok and "pq" in reason.lower()

    def test_hybrid_satisfied(self):
        pol = HybridSignaturePolicy(require_hybrid=True)
        sigs = [
            ApprovalSignature(approver_id="alice", key_id="k1", alg=SignatureAlg.ed25519, signature_b64="a" * 64),
            ApprovalSignature(approver_id="alice", key_id="k2", alg=SignatureAlg.dilithium3, signature_b64="b" * 64),
        ]
        ok, _ = check_hybrid_requirement(sigs, "alice", pol)
        assert ok


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemaModels:

    def test_actor_id_on_request(self):
        req = ActionRequest(
            decision=ModelDecision(action=ProposedAction.recommend, confidence=0.5, summary="T", rationale="T"),
            actor_id="user-123", actor_role="analyst", environment="dev", tenant_id="t1",
        )
        assert req.actor_id == "user-123"

    def test_actor_id_defaults_empty(self):
        req = ActionRequest(
            decision=ModelDecision(action=ProposedAction.recommend, confidence=0.5, summary="T", rationale="T"),
            actor_role="analyst", environment="dev", tenant_id="t1",
        )
        assert req.actor_id == ""

    def test_approval_record(self):
        rec = ApprovalRecord(approval_id="t", tenant_id="t1", decision_hash="a" * 64, requested_by="a", nonce="n" * 8)
        assert not rec.revoked and rec.hash_alg == "sha256"

    def test_signature_alg_enum(self):
        assert SignatureAlg.ed25519.value == "ed25519"
        assert SignatureAlg.dilithium3.value == "dilithium3"


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE + KEY REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class TestConvenience:

    def test_requires_dual_prod_containment(self):
        for a in DUAL_APPROVAL_ACTIONS:
            assert requires_dual_approval(a, "prod")

    def test_requires_dual_not_dev(self):
        for a in DUAL_APPROVAL_ACTIONS:
            assert not requires_dual_approval(a, "dev")

    def test_requires_dual_not_recommend(self):
        assert not requires_dual_approval("recommend", "prod")

    def test_stable_hash_deterministic(self):
        assert stable_hash({"a": 1}) == stable_hash({"a": 1})
        assert len(stable_hash({"a": 1})) == 64

    def test_stable_hash_key_order(self):
        assert stable_hash({"z": 1, "a": 2}) == stable_hash({"a": 2, "z": 1})

    def test_registry_register_get_remove(self):
        r = KeyRegistry()
        k = PublicKeyRecord(key_id="k", alg=SignatureAlg.ed25519, owner_id="a", public_key_b64="dGVzdA==")
        r.register(k)
        assert r.get("k", SignatureAlg.ed25519) is not None
        assert r.remove("k", SignatureAlg.ed25519)
        assert r.get("k", SignatureAlg.ed25519) is None
        assert not r.remove("k", SignatureAlg.ed25519)


# ═══════════════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY — LEGACY HMAC
# ═══════════════════════════════════════════════════════════════════════════════

class TestLegacyHMAC:

    def test_imports(self):
        from sovereignty.crypto_approval import ApprovalStore, ApprovalSignature, DualApprovalResult
        assert callable(ApprovalStore)

    def test_sign_and_verify(self):
        from sovereignty.crypto_approval import ApprovalStore
        s = ApprovalStore()
        tok = s.sign("act-1", "hash", "admin_a", "admin")
        ok, _ = s.verify_single(tok, "act-1", "hash")
        assert ok

    def test_dual_approval(self):
        from sovereignty.crypto_approval import ApprovalStore
        s = ApprovalStore()
        ta = s.sign("act-2", "h", "admin_a", "admin")
        tb = s.sign("act-2", "h", "admin_b", "admin")
        result = s.verify_dual("act-2", "h", ta, tb)
        assert result.approved
