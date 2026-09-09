from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"unexpected {label} shape: expected exactly one match, found {text.count(old)}")
    return text.replace(old, new, 1)


# 1. Retire the obsolete root Python lock interface and repair the malformed Makefile escape.
makefile = Path("Makefile")
text = makefile.read_text(encoding="utf-8")
help_lines = (
    '\t@echo "  make lock          - generate requirements.lock + requirements-dev.lock with hashes (Docker required)"\n'
    '\t@echo "  make lock-upgrade  - same as lock, but upgrades within constraints"\n'
)
text = replace_once(text, help_lines, "", "Makefile lock help")
lock_targets = (
    "\nlock:\n"
    "\t@./scripts/lock.sh\n\n"
    "lock-upgrade:\n"
    "\t@QC_LOCK_UPGRADE=1 ./scripts/lock.sh\n"
)
text = replace_once(text, lock_targets, "\n", "Makefile lock targets")
broken = "\n" + r"\1" + "\n.PHONY: kind-ingress-e2e\n"
text = replace_once(text, broken, "\n.PHONY: kind-ingress-e2e\n", "Makefile literal backreference")
makefile.write_text(text, encoding="utf-8")

# 2. Make Argo CD Image Updater readiness resilient to chart deployment naming.
bootstrap = Path("scripts/bootstrap/bootstrap_cluster.sh")
text = bootstrap.read_text(encoding="utf-8")
old = "kubectl -n argocd-image-updater rollout status deploy/argocd-image-updater --timeout=10m"
new = "kubectl -n argocd-image-updater rollout status deployment -l app.kubernetes.io/instance=argocd-image-updater --timeout=10m"
bootstrap.write_text(replace_once(text, old, new, "Image Updater readiness check"), encoding="utf-8")

# 3. Align the Windows bootstrap with the dependency contract used by CI and Docker.
windows = Path("scripts/dev/python_bootstrap_windows.ps1")
text = windows.read_text(encoding="utf-8")
text = replace_once(
    text,
    "  - Installs requirements.txt and (optionally) requirements-dev.txt.\n",
    "  - Installs backend/requirements.txt and, with -Dev, bootstrap requirements plus pytest.\n",
    "Windows bootstrap description",
)
old_param_order = '''Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [switch] $Dev,
  [switch] $Recreate,
  [string] $Python = "python",
  [string] $RepoRoot
)
'''
new_param_order = '''param(
  [switch] $Dev,
  [switch] $Recreate,
  [string] $Python = "python",
  [string] $RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
'''
text = replace_once(text, old_param_order, new_param_order, "Windows parameter block")
start_marker = '  if (Test-Path "requirements.txt") {'
end_marker = '  Write-Info "done"'
start = text.find(start_marker)
end = text.find(end_marker, start)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("unexpected Windows dependency install block")
replacement = (
    '  $backendReq = Join-Path $root "backend\\requirements.txt"\n'
    '  if (-not (Test-Path $backendReq)) { throw "backend requirements not found: $backendReq" }\n'
    '  Write-Info "installing backend/requirements.txt"\n'
    '  Exec $venvPy @("-m","pip","install","-r",$backendReq)\n\n'
    '  if ($Dev) {\n'
    '    $bootstrapReq = Join-Path $root "scripts\\bootstrap\\requirements.txt"\n'
    '    if (-not (Test-Path $bootstrapReq)) { throw "bootstrap requirements not found: $bootstrapReq" }\n'
    '    Write-Info "installing bootstrap requirements and pytest"\n'
    '    Exec $venvPy @("-m","pip","install","-r",$bootstrapReq,"pytest")\n'
    '  }\n\n'
)
text = text[:start] + replacement + text[end:]
windows.write_text(text, encoding="utf-8")

# 4. Remove the retired lock generation path; active auditing is backend/requirements.txt.
for obsolete in (Path(".github/workflows/deps-refresh.yml"), Path("scripts/lock.sh")):
    if not obsolete.exists():
        raise SystemExit(f"expected obsolete path missing: {obsolete}")
    obsolete.unlink()

# 5. Remove temporary validation scaffolding from the final branch diff.
for temporary in (
    Path(".github/workflows/verify-maintenance-repair.yml"),
    Path(".github/scripts/apply_qc_maintenance_repair.py"),
):
    if temporary.exists():
        temporary.unlink()
