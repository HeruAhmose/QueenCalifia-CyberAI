# Training scripts on Windows (PowerShell)

## 1. One clone only

Use **one** repo folder that has **`git remote`** → `HeruAhmose/QueenCalifia-CyberAI` (e.g. `C:\Users\Student\Downloads\QueenCalifia-CyberAI`).  

If you keep assets under **`C:\Users\Student\Downloads\QCMAIN`**, that tree may **not** be one git repo — see **[`QCMAIN_WORKSPACE.md`](QCMAIN_WORKSPACE.md)**.

If `scripts\qc_perpetual_learner.py` is missing, you are in the wrong folder or behind `main`:

```powershell
cd <your-repo-root>
git pull origin main
Test-Path .\scripts\qc_perpetual_learner.py   # should be True
```

## 2. API key safety

- Set `QC_API_KEY` in the **same PowerShell session** before running Python. **Never** commit it or paste it into chat.
- If a key was exposed, **rotate it in the Render dashboard** (new key → update Render env → update your shell).

```powershell
$env:QC_API_KEY = '<paste-new-key-from-render>'
```

## 3. UTF-8 console (clean banners)

```powershell
chcp 65001 | Out-Null
$env:PYTHONUTF8 = '1'
```

## 4. Wake Render (optional)

If the first request times out, open in a browser once:

`https://queencalifia-cyberai.onrender.com/healthz`

Or in PowerShell:

```powershell
Invoke-WebRequest -Uri "https://queencalifia-cyberai.onrender.com/healthz" -UseBasicParsing -TimeoutSec 90
```

## 5. Run sovereign training (helper script)

From **repo root**:

```powershell
.\scripts\run_training_advanced.ps1
```

Or with options:

```powershell
.\scripts\run_training_advanced.ps1 -Phase all -HealthTimeout 90 -HealthRetries 5
.\scripts\run_training_advanced.ps1 -Phase infrastructure
```

Manual equivalent:

```powershell
python .\scripts\qc_sovereign_training.py --phase advanced --health-timeout 90 --health-retries 5
```

Environment overrides (optional):

| Variable | Meaning |
|----------|---------|
| `QC_TRAINING_HEALTH_TIMEOUT` | Default seconds for `/healthz` (default 60 in code) |
| `QC_TRAINING_HEALTH_RETRIES` | Default retry count (default 3) |
| `QC_BASE_URL` | API root (default Render production URL) |

## 6. Perpetual learner (needs key)

```powershell
$env:QC_API_KEY = '<your-key>'
python .\scripts\qc_perpetual_learner.py --workers 16
```

## 7. Offline learning (no network)

```powershell
python .\scripts\qc_offline_learning.py --corpus scripts\offline_corpus\sample_scan.json --synthetic 40
```

## 8. Don’t paste instructions as commands

Only run lines that are valid PowerShell (`cd`, `$env:...`, `python`, `git`, `.\scripts\...`). Explanatory sentences are not commands.

## 9. CORS note

`Invoke-WebRequest` may show `Access-Control-Allow-Origin: http://localhost:3000` on API responses. Browser apps still need your **Firebase / dashboard origin** listed in **`QC_CORS_ORIGINS`** on Render.
