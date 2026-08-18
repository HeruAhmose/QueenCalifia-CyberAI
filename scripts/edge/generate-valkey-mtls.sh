#!/usr/bin/env bash
set -euo pipefail

ROOT="${QC_EDGE_STATE_ROOT:-/srv/queen-califia}"
PKI="${ROOT}/pki/valkey"
DAYS="${QC_EDGE_PKI_DAYS:-397}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo); private-key ownership is set explicitly." >&2
  exit 1
fi

install -d -m 0755 -o root -g root "$PKI"
umask 077

if find "$PKI" -mindepth 1 -maxdepth 1 -type f | grep -q .; then
  echo "Refusing to overwrite existing Valkey PKI at $PKI" >&2
  exit 2
fi

openssl genrsa -out "$PKI/ca.key" 4096
openssl req -x509 -new -sha256 -key "$PKI/ca.key" -days "$DAYS" \
  -subj "/CN=QueenCalifia Sovereign Edge Valkey CA" -out "$PKI/ca.crt"

issue_cert() {
  local name="$1" usage="$2" owner="$3" san="$4"
  openssl genrsa -out "$PKI/${name}.key" 3072
  openssl req -new -sha256 -key "$PKI/${name}.key" -subj "/CN=queen-califia-${name}" -out "$PKI/${name}.csr"
  cat >"$PKI/${name}.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=${usage}
${san}
EOF
  openssl x509 -req -sha256 -in "$PKI/${name}.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
    -CAcreateserial -days "$DAYS" -extfile "$PKI/${name}.ext" -out "$PKI/${name}.crt"
  rm -f "$PKI/${name}.csr" "$PKI/${name}.ext"
  chown "$owner" "$PKI/${name}.key" "$PKI/${name}.crt"
  chmod 0440 "$PKI/${name}.key"
  chmod 0444 "$PKI/${name}.crt"
}

# Official Valkey images currently run the daemon as UID/GID 999; application containers use 10001.
issue_cert server serverAuth 999:999 "subjectAltName=DNS:valkey"
issue_cert health clientAuth 999:999 "subjectAltName=DNS:queen-califia-valkey-health"
issue_cert api clientAuth 10001:10001 "subjectAltName=DNS:queen-califia-api"
issue_cert worker clientAuth 10001:10001 "subjectAltName=DNS:queen-califia-worker"

chown root:root "$PKI/ca.key" "$PKI/ca.crt" "$PKI/ca.srl"
chmod 0400 "$PKI/ca.key"
chmod 0444 "$PKI/ca.crt"
chmod 0400 "$PKI/ca.srl"

for cert in ca server health api worker; do
  openssl x509 -in "$PKI/${cert}.crt" -noout -subject -issuer -dates -fingerprint -sha256
 done

echo "Valkey mTLS PKI created at $PKI"
echo "CA private key remains host-root-only and must be backed up encrypted; never commit this directory."
