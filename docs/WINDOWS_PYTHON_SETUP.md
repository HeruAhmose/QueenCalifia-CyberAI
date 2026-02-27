# Windows Python Setup

If `pytest` or `flask` import errors occur locally, it's usually because the virtual environment
wasn't created or requirements weren't installed.

## One command

From the repo root:

```powershell
pwsh -File scripts/dev/python_bootstrap_windows.ps1 -Dev -Recreate
```

Then:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

## Common gotcha

If you see a `>>>` prompt, you are inside the **Python REPL**.
Exit it first:

```text
exit()
```

Then run PowerShell commands again.
