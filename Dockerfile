FROM python:3.12-slim

LABEL maintainer="Tamerian Materials - Jon"
LABEL description="Queen Califia Quantum CyberAI - Defense-Grade Cybersecurity Platform"

# Security: use a deterministic numeric non-root runtime identity so
# orchestrators can enforce runAsNonRoot without image-user ambiguity.
RUN groupadd --system --gid 10001 queencalifia \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin queencalifia

WORKDIR /app

ARG QC_USE_LOCK=0

# Install dependencies
COPY backend/requirements.txt ./requirements.txt
RUN if [ "$QC_USE_LOCK" = "1" ]; then \
      echo "requirements.lock is not maintained for the root image; disable QC_USE_LOCK or add a locked backend requirements artifact."; \
      exit 2; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

# Copy application
COPY . .

# Runtime state, including the default SQLite path, must remain writable.
RUN mkdir -p /app/data /app/backend/data \
    && chown -R 10001:10001 /app

USER 10001:10001

# Environment
ENV QC_PORT=5000
ENV QC_HOST=0.0.0.0
ENV QC_PRODUCTION=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz')"

# Production WSGI server (not Flask dev server)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
