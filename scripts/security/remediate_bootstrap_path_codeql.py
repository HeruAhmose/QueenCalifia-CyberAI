from pathlib import Path

path = Path("api/gateway.py")
text = path.read_text(encoding="utf-8")

old_call = '''        bootstrap_path = (os.environ.get("QC_BOOTSTRAP_KEYS_FILE", "") or "").strip()
        if not bootstrap_path:
            bootstrap_path = self.file_path + ".bootstrap.json"
        self._persist_bootstrap_secrets(
            bootstrap_path,
            {"admin": admin, "analyst": analyst, "reader": reader},
        )
'''
new_call = '''        bootstrap_path = "keys.bootstrap.json"
        self._persist_bootstrap_secrets(
            {"admin": admin, "analyst": analyst, "reader": reader},
        )
'''
if old_call not in text:
    raise SystemExit("Expected environment-controlled bootstrap path block not found")
text = text.replace(old_call, new_call, 1)

old_helper = '''    def _persist_bootstrap_secrets(self, file_path: str, keys: Dict[str, str]) -> None:
        """Write one-time bootstrap credentials without exposing them to logs."""
        directory = os.path.dirname(file_path) or "."
        os.makedirs(directory, exist_ok=True)
        payload = {
            "created_at": _utcnow(),
            "warning": "Move these credentials to a secret manager, then delete this file.",
            "keys": dict(keys),
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(file_path, flags, 0o600)
        except FileExistsError as exc:
            raise RuntimeError(
                f"Bootstrap credential file already exists: {file_path}. "
                "Refusing to overwrite existing secrets."
            ) from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.write("\\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                os.chmod(file_path, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(file_path)
            except OSError:
                pass
            raise
'''
new_helper = '''    def _persist_bootstrap_secrets(self, keys: Dict[str, str]) -> None:
        """Write one-time bootstrap credentials without exposing them to logs."""
        file_path = "keys.bootstrap.json"
        payload = {
            "created_at": _utcnow(),
            "warning": "Move these credentials to a secret manager, then delete this file.",
            "keys": dict(keys),
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(file_path, flags, 0o600)
        except FileExistsError as exc:
            raise RuntimeError(
                "Bootstrap credential file already exists: keys.bootstrap.json. "
                "Refusing to overwrite existing secrets."
            ) from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.write("\\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                os.chmod(file_path, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(file_path)
            except OSError:
                pass
            raise
'''
if old_helper not in text:
    raise SystemExit("Expected bootstrap persistence helper not found")
text = text.replace(old_helper, new_helper, 1)
path.write_text(text, encoding="utf-8")

test = Path("tests/test_api_key_bootstrap_secrets.py")
t = test.read_text(encoding="utf-8")
t = t.replace('    bootstrap_file = tmp_path / "bootstrap-secrets.json"\n', '    bootstrap_file = tmp_path / "keys.bootstrap.json"\n    monkeypatch.chdir(tmp_path)\n')
t = t.replace('    monkeypatch.setenv("QC_BOOTSTRAP_KEYS_FILE", str(bootstrap_file))\n', '')
t = t.replace('    assert str(bootstrap_file) in caplog.text\n', '    assert "keys.bootstrap.json" in caplog.text\n')
test.write_text(t, encoding="utf-8")
