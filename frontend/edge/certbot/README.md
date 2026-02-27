# Certbot (ACME) profile

This folder contains scripts used by the optional `certbot` service in `docker-compose.prod.edge.yml`.

- `run.sh` issues the first certificate if missing, then runs a renewal loop.
- `deploy-hook.sh` copies the live cert material into the shared edge cert volume and the edge container will reload nginx automatically.

Required env:
- `QC_DOMAIN` (e.g. `example.com`)
- `QC_EMAIL`  (Let's Encrypt account email)

Optional env:
- `QC_LETSENCRYPT_STAGING=1` to use Let's Encrypt staging (avoids rate limits during testing)
- `QC_CERTBOT_RENEW_INTERVAL_SECONDS=43200` (12h)
