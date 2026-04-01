# Contributing

## Development
- Use Python 3.12+
- Run locally with Docker Compose (`docker compose up --build`)
- Run tests with `python -m pytest -q`
- Run the frontend production build with `cd frontend && npm run build`
- Follow the proprietary license and provenance posture described in `LICENSE` and `THIRD_PARTY_NOTICES.md`

## Pull Requests
- Keep changes focused
- Add/extend tests for behavior changes
- Ensure CI passes
- Do not vendor external repository source into this codebase without explicit written approval and provenance documentation
- Contributions are presumed confidential and repo-owned unless a separate written agreement says otherwise

## Security-Sensitive Changes
- Follow the scan allowlist policy
- Avoid introducing new persistent secret storage on the frontend
- Keep Render/GCS dashboard deploy docs (`docs/DEPLOY_DASHBOARD_GCS.md`) and README in sync with actual auth and persistence behavior
