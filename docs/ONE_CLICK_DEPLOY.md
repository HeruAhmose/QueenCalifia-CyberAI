# One-click-ish deployment

You can't truly do *zero setup* (DNS + secrets always exist), but you **can** make deployment a single click from GitHub
or a single command locally.

## Option 1: GitHub Actions "Deploy" button (recommended)

1. Create a small Linux VM (Ubuntu 22.04/24.04), open inbound **80/443**, and point `QC_DOMAIN` DNS to the VM.
2. Create an SSH key for GitHub Actions and add the public key to `~/.ssh/authorized_keys` on the VM user.
3. In GitHub repo → **Settings → Secrets and variables → Actions**, add secrets:

- `DEPLOY_HOST` (e.g. `203.0.113.10`)
- `DEPLOY_USER` (e.g. `ubuntu`)
- `DEPLOY_SSH_PRIVATE_KEY` (private key contents)
- `QC_DOMAIN` (e.g. `example.com`)
- `QC_EMAIL` (for Let's Encrypt)
- `QC_API_KEY_PEPPER` (long random)
- `QC_AUDIT_HMAC_KEY` (long random)

Optional:
- `DEPLOY_SSH_PORT`
- `QC_CORS_ORIGINS`
- `QC_PROXY_TRUSTED_HOPS`

4. Run Actions → **Deploy VM** → **Run workflow**. Choose ACME on/off and the git ref.

## Option 2: Local "one command" deploy (Windows)

```powershell
$env:QC_API_KEY_PEPPER="..."; $env:QC_AUDIT_HMAC_KEY="..."
powershell -ExecutionPolicy Bypass -File scripts/deploy/deploy_one_click.ps1 -Host 203.0.113.10 -User ubuntu -KeyPath C:\path\id_ed25519 -Domain example.com -Email you@example.com -Acme
```

## Notes

- ACME requires inbound port 80 reachable and correct DNS.
- For staging certificates, set `QC_LETSENCRYPT_STAGING=1` in `.env`.
