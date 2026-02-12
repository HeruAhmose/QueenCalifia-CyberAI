import re
from pathlib import Path

MAKEFILE = Path("Makefile")
if not MAKEFILE.exists():
    raise SystemExit("Makefile not found in current directory.")

s = MAKEFILE.read_text(encoding="utf-8")

# Ensure PYTHON variable exists
if "PYTHON ?=" not in s:
    s = "PYTHON ?= python\n\n" + s

# Use python -m pytest (more reliable on Windows)
s = re.sub(r"(?m)^\tpytest\b", "\t@$(PYTHON) -m pytest", s)

guard_block = (
    "test-guard:\n"
    "\t@$(PYTHON) -c \"import os,sys; "
    "url=(os.getenv('QC_REDIS_URL') or '').strip(); "
    "tls=(os.getenv('QC_REDIS_TLS') or '').strip().lower(); "
    "pin=(os.getenv('QC_REDIS_SPKI_PIN') or os.getenv('QC_REDIS_SPKI_PINS') or '').strip(); "
    "need_tls=bool(pin); "
    "has_tls=url.lower().startswith('rediss://') or tls in ('1','true','yes','y','on'); "
    "bad=need_tls and not has_tls; "
    "(print('ERROR: SPKI pinning requires TLS. Set QC_REDIS_URL=rediss://... or QC_REDIS_TLS=1 (or unset QC_REDIS_SPKI_PIN).', file=sys.stderr) if bad else None); "
    "sys.exit(1 if bad else 0)\"\n"
)

# Replace existing test-guard recipe (TAB-indented lines)
if re.search(r"(?m)^test-guard:\s*\n(?:\t.*\n)*", s):
    s = re.sub(r"(?m)^test-guard:\s*\n(?:\t.*\n)*", guard_block, s)
else:
    s = s.rstrip() + "\n\n" + guard_block

MAKEFILE.write_text(s, encoding="utf-8")
print("OK: Patched Makefile for Windows-safe test-guard.")
