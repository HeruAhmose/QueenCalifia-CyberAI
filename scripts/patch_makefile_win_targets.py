from pathlib import Path

mf = Path("Makefile")
if not mf.exists():
    raise SystemExit("Makefile not found in current directory.")

s = mf.read_text(encoding="utf-8")

block = "\n\n.PHONY: test-win lock-win\n" \
        "test-win:\n" \
        "\t@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dev_setup_windows.ps1\n\n" \
        "lock-win:\n" \
        "\t@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dev_setup_windows.ps1 -LockOnly\n"

if "test-win:" not in s:
    s = s.rstrip() + block + "\n"
    mf.write_text(s, encoding="utf-8")
    print("OK: Added test-win/lock-win targets to Makefile.")
else:
    print("OK: Makefile already has test-win target; no changes made.")
