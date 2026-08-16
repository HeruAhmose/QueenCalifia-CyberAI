import json
import logging
import os
import stat

from api.gateway import APIKeyStore


def test_dev_bootstrap_never_logs_raw_keys(tmp_path, monkeypatch, caplog):
    key_store = tmp_path / "keys.json"
    bootstrap_file = tmp_path / "bootstrap-secrets.json"
    monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("QC_API_KEY", raising=False)
    monkeypatch.delenv("QC_ADMIN_KEY", raising=False)
    monkeypatch.delenv("QC_PRODUCTION", raising=False)
    monkeypatch.setenv("QC_BOOTSTRAP_KEYS_FILE", str(bootstrap_file))

    with caplog.at_level(logging.WARNING, logger="queencalifia.api"):
        store = APIKeyStore(str(key_store), "test-pepper")

    payload = json.loads(bootstrap_file.read_text(encoding="utf-8"))
    raw_keys = list(payload["keys"].values())
    assert len(raw_keys) == 3
    assert all(len(value) == 64 for value in raw_keys)
    assert all(store.validate(value) is not None for value in raw_keys)
    assert all(value not in caplog.text for value in raw_keys)
    assert str(bootstrap_file) in caplog.text
    assert stat.S_IMODE(os.stat(bootstrap_file).st_mode) == 0o600

    persisted = json.loads(key_store.read_text(encoding="utf-8"))
    persisted_text = json.dumps(persisted)
    assert all(value not in persisted_text for value in raw_keys)


def test_bootstrap_refuses_to_overwrite_existing_secret_file(tmp_path, monkeypatch):
    key_store = tmp_path / "keys.json"
    bootstrap_file = tmp_path / "bootstrap-secrets.json"
    bootstrap_file.write_text("do-not-overwrite", encoding="utf-8")
    monkeypatch.delenv("QC_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("QC_API_KEY", raising=False)
    monkeypatch.delenv("QC_ADMIN_KEY", raising=False)
    monkeypatch.delenv("QC_PRODUCTION", raising=False)
    monkeypatch.setenv("QC_BOOTSTRAP_KEYS_FILE", str(bootstrap_file))

    try:
        APIKeyStore(str(key_store), "test-pepper")
    except RuntimeError as exc:
        assert "Refusing to overwrite existing secrets" in str(exc)
    else:
        raise AssertionError("Expected bootstrap overwrite protection to fail closed")

    assert bootstrap_file.read_text(encoding="utf-8") == "do-not-overwrite"
    assert not key_store.exists()
