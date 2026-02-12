from pathlib import Path
import re

mf = Path("Makefile")
if not mf.exists():
    raise SystemExit("Makefile not found.")

s = mf.read_text(encoding="utf-8")

# Add a POWERSHELL selector block once
selector = r"""
ifeq ($(OS),Windows_NT)
PWSH_EXE := $(firstword $(shell where pwsh 2>NUL))
ifeq ($(PWSH_EXE),)
POWERSHELL := powershell
else
POWERSHELL := pwsh
endif
else
POWERSHELL := pwsh
endif
""".strip() + "\n\n"

if "POWERSHELL :=" not in s and "PWSH_EXE :=" not in s:
    s = selector + s

targets = r"""
.PHONY: lock-win test-win up-win

lock-win:
@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/dev_setup_windows.ps1 -LockOnly

# Optional flags:
#   make test-win FRONTEND_TESTS=1 INSTALL_NODE=1
test-win:
@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/dev_setup_windows.ps1 $(if $(FRONTEND_TESTS),-RunFrontendTests,) $(if $(INSTALL_NODE),-InstallNode,)

# Optional:
#   make up-win BUILD=1
up-win:
@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File scripts/up_windows.ps1 $(if $(BUILD),-Build,)
""".strip() + "\n"

if "test-win:" not in s:
    s = s.rstrip() + "\n\n" + targets + "\n"

mf.write_text(s, encoding="utf-8")
print("OK: Makefile patched (pwsh fallback + win targets).")
