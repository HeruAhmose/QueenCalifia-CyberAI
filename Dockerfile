FROM python:3.12-slim

LABEL maintainer="Tamerian Materials - Jon"
LABEL description="Queen Califia Quantum CyberAI - Defense-Grade Cybersecurity Platform"

# Security: run as non-root
RUN groupadd -r queencalifia && useradd -r -g queencalifia -d /app -s /sbin/nologin queencalifia

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set ownership
RUN chown -R queencalifia:queencalifia /app

# Switch to non-root user
USER queencalifia

# Environment
ENV QC_PORT=5000
ENV QC_HOST=0.0.0.0
ENV QC_PRODUCTION=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')"

# Production WSGI server (not Flask dev server)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
