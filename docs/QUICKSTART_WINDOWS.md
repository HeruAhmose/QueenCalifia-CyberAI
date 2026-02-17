# Windows Quickstart (PowerShell)

These steps assume your repo is at:

`C:\Users\Student\Downloads\QueenCalifia-CyberAI`

## 1) Open PowerShell in the repo root

```powershell
Set-Location "C:\Users\Student\Downloads\QueenCalifia-CyberAI"
```

Confirm you see `app.py`, `requirements.txt`, `frontend\`:

```powershell
Get-ChildItem
```

## 2) Bootstrap Python + dependencies

This creates/refreshes a local virtualenv at `.venv` and installs dependencies.

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev\python_bootstrap_windows.ps1 -Dev -Recreate
```

If you see a `>>>` prompt, you're accidentally inside the Python REPL.
Type `exit()` (or press `Ctrl+Z` then `Enter`) to return to PowerShell, then rerun the command above.

## 3) Run backend API

```powershell
.\.venv\Scripts\python.exe app.py
```

Default: `http://localhost:8000` (see console output).

## 4) Run tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## 5) Run frontend (dashboard)

In a new terminal:

```powershell
Set-Location "C:\Users\Student\Downloads\QueenCalifia-CyberAI\frontend"
npm install
npm run dev
```

Vite will print the URL (typically `http://localhost:5173`).

## 6) (Optional) Enable full pre-push checks

Fast mode runs by default. To run the full test suite on push:

```powershell
$env:QC_PREPUSH_FULL = "1"
git push
```

To make missing tools fail the push instead of warn:

```powershell
$env:QC_PREPUSH_STRICT = "1"
git push
```
