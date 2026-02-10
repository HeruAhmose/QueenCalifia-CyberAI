.PHONY: help up down logs test test-backend test-frontend test-redis smoketest hooks test-backend-redis-auto

# One-time (per make invocation) Redis TLS scheme consistency warnings.
# Set QC_SUPPRESS_TLS_WARNINGS=1 to silence.
QC_TLS_WARNINGS_ONCE := 1
ifneq ($(filter 1 true True,$(QC_SUPPRESS_TLS_WARNINGS)),1)
ifneq ($(filter test test-guard,$(MAKECMDGOALS)),)
  ifneq ($(findstring rediss://,$(QC_REDIS_URL)),)
    ifeq ($(strip $(QC_REDIS_TLS)),)
      $(warning [make test][warn] QC_REDIS_URL is rediss:// but QC_REDIS_TLS is not enabled. (Scheme implies TLS; typically OK.))
    else ifeq ($(QC_REDIS_TLS),0)
      $(warning [make test][warn] QC_REDIS_URL is rediss:// but QC_REDIS_TLS is not enabled. (Scheme implies TLS; typically OK.))
    endif
  endif
  ifneq ($(findstring redis://,$(QC_REDIS_URL)),)
    ifneq ($(filter 1 true True,$(QC_REDIS_TLS)),)
      $(warning [make test][warn] QC_REDIS_TLS=1 but QC_REDIS_URL is redis://. Consider using rediss:// for clarity.)
    endif
  endif
endif
endif

help:
	@echo "Targets:"
	@echo "  make up            - docker compose up --build (Dashboard: http://localhost:5173)"
	@echo "  make down          - docker compose down -v"
	@echo "  make logs          - docker compose logs -f"
	@echo "  make test          - run backend + frontend unit tests (auto-runs Redis-mode backend tests (prefers reachable QC_REDIS_URL; falls back to Docker Redis; skips cleanly otherwise); set QC_SKIP_REDIS_TESTS=1 to skip)"
	@echo "  make test-redis    - run backend tests in Redis mode (requires Redis running)"
	@echo "  make smoketest     - run Grafana webhook provisioned-contact-point smoke test (requires Docker)"
	@echo "  make dev           - run backend locally (--no-auth, --debug)"
	@echo "  make dev-frontend  - run frontend Vite dev server locally"
	@echo "  make hooks         - install git hooks (core.hooksPath=.githooks)"
	@echo "  make prod-up       - docker compose (production) up --build -d (Dashboard: http://localhost:8080)"
	@echo "  make prod-edge-up  - docker compose (edge TLS) up --build -d (HTTPS: https://localhost:8443)"
	@echo "  make prod-edge-acme-up - docker compose (edge TLS + ACME) up --build -d (requires QC_DOMAIN/QC_EMAIL)"
	@echo "  make prod-down     - docker compose (production) down -v"
	@echo "  make lock          - generate requirements.lock + requirements-dev.lock with hashes (Docker required)"
	@echo "  make lock-upgrade  - same as lock, but upgrades within constraints"
	@echo ""
	@echo "  Windows / PowerShell:  make help-win"

up:
	@if [ ! -f .env ]; then cp .env.example .env; echo "📋 Created .env from .env.example"; fi
	docker compose up --build
	@echo ""
	@echo "  ✅ Queen Califia is running!"
	@echo "  Dashboard:  http://localhost:5173"
	@echo "  API:        http://localhost:5000"
	@echo "  Grafana:    http://localhost:3000"
	@echo "  Jaeger:     http://localhost:16686"
	@echo "  Prometheus: http://localhost:9090"
	@echo ""

down:
	docker compose down -v

logs:
	docker compose logs -f

dev:
	@if [ ! -f .env ]; then cp .env.example .env; echo "📋 Created .env from .env.example"; fi
	QC_NO_AUTH=1 python app.py --no-auth --debug

dev-frontend:
	cd frontend && npm install && npm run dev

test-backend:
	python -m pytest -q


test-backend-redis-auto:
	@if [ "$${QC_SKIP_REDIS_TESTS:-0}" = "1" ]; then \
		echo "Skipping Redis-mode backend tests (QC_SKIP_REDIS_TESTS=1)"; \
	elif [ -n "$${QC_REDIS_URL:-}" ] && python scripts/redis_ping.py "$${QC_REDIS_URL}" >/dev/null 2>&1; then \
		echo "Using reachable local Redis at $$QC_REDIS_URL for Redis-mode backend tests..."; \
		QC_REDIS_URL="$$QC_REDIS_URL" QC_FORCE_REDIS_RATE_LIMIT=1 QC_BUDGET_ENABLED=1 QC_FORCE_REDIS_BUDGET=1 python -m pytest -q; \
	elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		NAME="qc-test-redis-$$(date +%s)"; \
		echo "Docker detected; running Redis-mode backend tests using $$NAME..."; \
		docker run -d --rm -p 0:6379 --name "$$NAME" redis:7-alpine >/dev/null; \
		PORT="$$(docker port "$$NAME" 6379/tcp | head -n1 | sed 's/.*://')"; \
		if [ -z "$$PORT" ]; then echo "Failed to discover Redis port"; docker stop "$$NAME" >/dev/null 2>&1 || true; exit 1; fi; \
		trap 'docker stop "$$NAME" >/dev/null 2>&1 || true' EXIT; \
		QC_REDIS_URL="redis://localhost:$$PORT/0" QC_FORCE_REDIS_RATE_LIMIT=1 QC_BUDGET_ENABLED=1 QC_FORCE_REDIS_BUDGET=1 python -m pytest -q; \
	else \
		echo "No reachable local Redis (QC_REDIS_URL) and Docker not available; skipping Redis-mode backend tests."; \
	fi

test-frontend:
	cd frontend && npm install && npm test

test: test-guard test-backend test-backend-redis-auto test-frontend
.PHONY: test-guard
test-guard:
	@# Guard: SPKI pinning requires TLS (rediss:// or QC_REDIS_TLS=1)
	@if [ -n "$$QC_REDIS_TLS_SPKI_SHA256" ]; then \
	  URL="$${QC_REDIS_URL:-redis://localhost:6379/0}"; \
	  case "$$URL" in \
	    rediss://*) : ;; \
	    *) TLS="$${QC_REDIS_TLS:-0}"; \
	       if [ "$$TLS" != "1" ] && [ "$$TLS" != "true" ] && [ "$$TLS" != "True" ]; then \
	         echo "[make test] QC_REDIS_TLS_SPKI_SHA256 is set but TLS is not enabled. Use rediss:// or set QC_REDIS_TLS=1."; \
	         exit 1; \
	       fi ;; \
	  esac; \
	fi

test-redis:
	QC_REDIS_URL=redis://localhost:6379/0 QC_FORCE_REDIS_RATE_LIMIT=1 QC_BUDGET_ENABLED=1 QC_FORCE_REDIS_BUDGET=1 python -m pytest -q

smoketest:
	@QC_ALERT_WEBHOOK_URL=$${QC_ALERT_WEBHOOK_URL:-http://webhook-receiver:8080/webhook} \
	QC_ALERT_WEBHOOK_BEARER_TOKEN=$${QC_ALERT_WEBHOOK_BEARER_TOKEN:?set QC_ALERT_WEBHOOK_BEARER_TOKEN} \
	docker compose --profile smoketest up --build --abort-on-container-exit --exit-code-from grafana-smoketest

hooks:
	git config core.hooksPath .githooks
	@echo "Installed hooks path: .githooks"


.PHONY: spki-pin
spki-pin:
	@python scripts/redis_spki_pin.py --url "$(URL)" $(if $(JSON),--json,) $(if $(PEM),--print-pem,) $(if $(REDACT),--redact-pem,)
	@# Guard: CA bundle implies TLS must be enabled
	@if [ -n "$$QC_REDIS_TLS_CA" ]; then \
	  URL="$${QC_REDIS_URL:-redis://localhost:6379/0}"; \
	  case "$$URL" in \
	    rediss://*) : ;; \
	    *) TLS="$${QC_REDIS_TLS:-0}"; \
	       if [ "$$TLS" != "1" ] && [ "$$TLS" != "true" ] && [ "$$TLS" != "True" ]; then \
	         echo "[make test] QC_REDIS_TLS_CA is set but TLS is not enabled. Use rediss:// or set QC_REDIS_TLS=1."; \
	         exit 1; \
	       fi ;; \
	  esac; \
	fi
	@# Guard: Insecure TLS requires SPKI pinning
	@if [ "${QC_REDIS_TLS_INSECURE:-0}" = "1" ] || [ "${QC_REDIS_TLS_INSECURE:-0}" = "true" ] || [ "${QC_REDIS_TLS_INSECURE:-0}" = "True" ]; then \
	  if [ -z "$$QC_REDIS_TLS_SPKI_SHA256" ]; then \
	    echo "[make test] QC_REDIS_TLS_INSECURE=1 is set but QC_REDIS_TLS_SPKI_SHA256 is unset. Refuse insecure TLS without SPKI pinning."; \
	    exit 1; \
	  fi; \
	fi


.PHONY: spki-pin-runbook
spki-pin-runbook:
	@set -e; \
	if [ -n "$(URL)" ]; then \
	  ./scripts/spki_pin_runbook.sh --url "$(URL)" $(if $(JSON),--json,) $(if $(PEM),--print-pem,) $(if $(REDACT),--redact-pem,) $(if $(OUT),--out "$(OUT)",); \
	else \
	  if [ -z "$(HOST)" ] || [ -z "$(PORT)" ]; then \
	    echo "Usage: make spki-pin-runbook URL=rediss://host:port/0 [JSON=1 OUT=...] OR HOST=... PORT=..."; \
	    exit 2; \
	  fi; \
	  ./scripts/spki_pin_runbook.sh "$(HOST)" "$(PORT)" $(if $(JSON),--json,) $(if $(PEM),--print-pem,) $(if $(REDACT),--redact-pem,) $(if $(OUT),--out "$(OUT)",); \
	fi


# ──────────────────────────────────────────────────────────────
# Windows / PowerShell targets  (suffix: -win)
# Usage:  make test-win   OR   make -f Makefile dev-win
# Requires: Python venv activated, pip, npm on PATH.
# ──────────────────────────────────────────────────────────────
.PHONY: help-win test-win test-backend-win test-frontend-win dev-win dev-frontend-win hooks-win lock-win lock-upgrade-win

help-win:
	@echo "Targets (Windows / PowerShell):"
	@echo "  make test-win          - install deps + run backend + frontend tests"
	@echo "  make test-backend-win  - run backend pytest only"
	@echo "  make test-frontend-win - run frontend tests only"
	@echo "  make dev-win           - run backend locally (no-auth, debug)"
	@echo "  make dev-frontend-win  - run frontend Vite dev server"
	@echo "  make hooks-win         - install git hooks"
	@echo "  make lock-win          - pip-compile lock files (requires pip-tools)"
	@echo "  make lock-upgrade-win  - pip-compile lock files with --upgrade"

test-backend-win:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	python -m pytest -q

test-frontend-win:
	cd frontend && npm install && npm test

test-win: test-backend-win test-frontend-win

dev-win:
	set QC_NO_AUTH=1 && python app.py --no-auth --debug

dev-frontend-win:
	cd frontend && npm install && npm run dev

hooks-win:
	git config core.hooksPath .githooks
	@echo "Installed hooks path: .githooks"

lock-win:
	pip install pip-tools
	pip-compile --generate-hashes --strip-extras -o requirements.lock requirements.in
	pip-compile --generate-hashes --strip-extras -o requirements-dev.lock requirements-dev.in

lock-upgrade-win:
	pip install pip-tools
	pip-compile --upgrade --generate-hashes --strip-extras -o requirements.lock requirements.in
	pip-compile --upgrade --generate-hashes --strip-extras -o requirements-dev.lock requirements-dev.in


lock:
	@./scripts/lock.sh

lock-upgrade:
	@QC_LOCK_UPGRADE=1 ./scripts/lock.sh

prod-up:
	@if [ ! -f .env ]; then cp .env.example .env; echo "📋 Created .env from .env.example"; fi
	docker compose -f docker-compose.prod.yml up --build -d
	@echo ""
	@echo "  ✅ Queen Califia (prod) is running!"
	@echo "  Dashboard:  http://localhost:$${QC_DASHBOARD_PORT:-8080}"
	@echo ""

prod-down:
	docker compose -f docker-compose.prod.yml down -v


prod-edge-up:
	@if [ ! -f .env ]; then cp .env.example .env; echo "📋 Created .env from .env.example"; fi
	docker compose -f docker-compose.prod.edge.yml up --build -d
	@echo ""
	@echo "  ✅ Edge (TLS) is running!"
	@echo "  HTTPS: https://localhost:${QC_HTTPS_PORT:-8443}"
	@echo ""

prod-edge-acme-up:
	@if [ ! -f .env ]; then cp .env.example .env; echo "📋 Created .env from .env.example"; fi
	docker compose -f docker-compose.prod.edge.yml --profile acme up --build -d
	@echo ""
	@echo "  ✅ Queen Califia edge (ACME) is running!"
	@echo "  HTTPS: https://localhost:$${QC_HTTPS_PORT:-8443}"
	@echo ""
prod-edge-down:
	docker compose -f docker-compose.prod.edge.yml down -v


preflight-prod:
	./scripts/preflight_prod.sh


k8s-validate:
	@echo "Validating Helm + Kustomize manifests..."
	helm lint ./helm/queen-califia -f ./helm/queen-califia/ci-values.yaml
	helm template qc ./helm/queen-califia -f ./helm/queen-califia/ci-values.yaml >/tmp/qc-helm-rendered.yaml
	kustomize build k8s/ >/tmp/qc-kustomize-rendered.yaml
	@echo "Rendered manifests written to /tmp/qc-helm-rendered.yaml and /tmp/qc-kustomize-rendered.yaml"




.PHONY: kind-ingress-e2e
kind-ingress-e2e: ## Run Ingress E2E test (port-forward ingress-nginx) against the current kind context
	./scripts/ci/kind_ingress_e2e.sh
