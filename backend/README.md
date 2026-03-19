# Backend

This directory is the Render-facing backend service entrypoint.

## What it does

- `app.py` is the WSGI entry used by Render (`gunicorn app:app`).
- That file loads the repo-root `app.py` security gateway and mounts the dashboard blueprints for:
  - `/api/chat`
  - `/api/market`
  - `/api/forecast`
  - `/api/identity`

## Important files

- `app.py`: Render entrypoint and blueprint composition
- `requirements.txt`: backend/runtime Python dependencies
- `.env.example`: local development environment template
- `modules/`: chat, market, forecast, identity, and optional quantum modules
- `core/`: backend-side auth, settings, and SQLite helpers used by dashboard modules

## Deployment notes

- Render uses `render.yaml` from the repo root.
- Persistent runtime data should live on the mounted disk at `/var/data`.
- The current Render profile intentionally runs a single Gunicorn worker because async vulnerability scan jobs are stored in process memory. This avoids cross-worker `scan not found` polling failures.
- If you later enable shared queue/state via Redis + Celery, you can scale web workers back out safely.
- The main QC app state and evolution memory are configured through:
  - `QC_DB_PATH`
  - `QC_EVOLUTION_DB`
  - `QC_MEMORY_BACKUP_DIR`

## Local run

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
gunicorn app:app --bind 0.0.0.0:5000
```
