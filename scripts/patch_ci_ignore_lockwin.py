from pathlib import Path
import re

wf = Path(".github/workflows/ci.yml")
if not wf.exists():
    print("SKIP: .github/workflows/ci.yml not found.")
    raise SystemExit(0)

s = wf.read_text(encoding="utf-8")

# If the workflow runs scripts/lock.sh --check, ensure we only diff the Linux lockfiles afterwards.
pattern = r"(?m)^\s*-\s*run:\s*\./scripts/lock\.sh\s+--check\s*$"
if re.search(pattern, s) and "git diff --exit-code -- requirements.lock requirements-dev.lock" not in s:
    s = re.sub(
        pattern,
        "- run: ./scripts/lock.sh --check\n"
        "      - run: git diff --exit-code -- requirements.lock requirements-dev.lock",
        s,
        count=1
    )
    wf.write_text(s, encoding="utf-8")
    print("OK: CI patched to diff only requirements.lock + requirements-dev.lock (ignores *.lock.win).")
else:
    print("OK: CI already compatible (or lock.sh --check not present).")
