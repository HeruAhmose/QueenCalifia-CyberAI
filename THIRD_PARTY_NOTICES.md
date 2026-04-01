## Third-Party Notices

Queen Califia CyberAI repository source is intended to remain repo-owned and
proprietary unless a file explicitly states otherwise.

This repository does use third-party software as dependencies, build tools,
frameworks, runtimes, and hosted services. Those third-party components are not
vendored into the repository as copied upstream source unless explicitly noted.

Examples in current use include:

- Python packages installed from `backend/requirements.txt`
- JavaScript packages installed from `frontend/package.json`
- Google Cloud Storage (dashboard static hosting; optional legacy Firebase Hosting config in repo)
- Render
- Redis, Celery, Gunicorn, Flask, React, Vite, and related ecosystem tooling

Each third-party dependency remains subject to its own license terms from its
respective owner. This file does not modify or replace those licenses.

Operational provenance posture:

- Queen Califia CyberAI application code is original to this repository unless
  a file explicitly states otherwise.
- Third-party software is consumed as dependencies and services, not as copied
  external repository source, unless separately documented.
- No third-party dependency license grants any rights to the repo-owned source
  beyond what applicable law or a separate written agreement allows.
