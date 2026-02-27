#!/bin/sh
set -eu

TOKEN="${QC_METRICS_TOKEN:-metrics-dev}"
RW_URL="${QC_PROM_REMOTE_WRITE_URL:-}"
RW_BEARER="${QC_PROM_REMOTE_WRITE_BEARER_TOKEN:-}"
RW_USER="${QC_PROM_REMOTE_WRITE_BASIC_USER:-}"
RW_PASS="${QC_PROM_REMOTE_WRITE_BASIC_PASSWORD:-}"

mkdir -p /etc/prometheus

# Base config (inject metrics token into scrape auth)
sed "s|__QC_METRICS_TOKEN__|${TOKEN}|g" /etc/prometheus/prometheus.yml.tmpl > /etc/prometheus/prometheus.yml

# Optional remote_write (top-level)
if [ -n "${RW_URL}" ]; then
  echo "" >> /etc/prometheus/prometheus.yml
  echo "remote_write:" >> /etc/prometheus/prometheus.yml
  echo "  - url: \"${RW_URL}\"" >> /etc/prometheus/prometheus.yml

  # Prometheus remote_write supports http_config (authorization/basic_auth/etc).
  if [ -n "${RW_BEARER}" ]; then
    echo "    authorization:" >> /etc/prometheus/prometheus.yml
    echo "      type: Bearer" >> /etc/prometheus/prometheus.yml
    echo "      credentials: \"${RW_BEARER}\"" >> /etc/prometheus/prometheus.yml
  elif [ -n "${RW_USER}" ]; then
    echo "    basic_auth:" >> /etc/prometheus/prometheus.yml
    echo "      username: \"${RW_USER}\"" >> /etc/prometheus/prometheus.yml
    echo "      password: \"${RW_PASS}\"" >> /etc/prometheus/prometheus.yml
  fi
fi

exec /bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus
