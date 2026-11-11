# SentinelX developer commands. Run `make help` for the list.

SHELL := /bin/bash
.DEFAULT_GOAL := help

UV      ?= uv
PNPM    ?= pnpm
COMPOSE ?= docker compose
WEB     := apps/web

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------------------- setup
.PHONY: env install
env: ## Create .env with random secrets (never overwrites)
	python3 scripts/generate_env.py

install: ## Install backend (uv) and frontend (pnpm) dependencies
	$(UV) sync --all-packages
	cd $(WEB) && $(PNPM) install --frozen-lockfile

# --------------------------------------------------------------------------- quality
.PHONY: lint format typecheck test test-integration test-e2e check security
lint: ## Lint backend and frontend
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	cd $(WEB) && $(PNPM) lint

format: ## Auto-format backend code
	$(UV) run ruff check --fix .
	$(UV) run ruff format .

typecheck: ## Static type checks (mypy strict + tsc)
	$(UV) run mypy apps/api/app apps/api/tests apps/api/migrations workers security-engine
	cd $(WEB) && $(PNPM) typecheck

test: ## Unit/API tests (no infrastructure required)
	$(UV) run pytest
	cd $(WEB) && $(PNPM) test

test-integration: ## Integration tests (needs PostgreSQL + Redis via SENTINELX_* env)
	$(UV) run pytest -m integration

test-all: ## Full backend suite with the coverage gate (needs PostgreSQL + Redis)
	$(UV) run pytest -m "" --cov

test-e2e: ## Playwright E2E against a running stack (E2E_BASE_URL, default :8080)
	cd $(WEB) && $(PNPM) test:e2e

security: ## Local security checks (bandit, pip-audit, pnpm audit)
	$(UV) run bandit -q -c pyproject.toml -r apps/api/app workers/sentinelx_workers security-engine/sentinelx_security
	$(UV) export --frozen --all-packages --no-dev --no-emit-workspace --format requirements.txt -o .requirements-audit.txt -q
	$(UV) run pip-audit --strict --disable-pip --require-hashes -r .requirements-audit.txt; rc=$$?; rm -f .requirements-audit.txt; exit $$rc
	cd $(WEB) && $(PNPM) audit --audit-level high

check: lint typecheck test security ## Everything CI runs without infrastructure

# --------------------------------------------------------------------------- local dev
.PHONY: dev-api dev-web dev-worker
dev-api: ## Run the API with auto-reload (needs reachable PostgreSQL/Redis)
	$(UV) run uvicorn app.main:create_app --factory --reload --app-dir apps/api --host 127.0.0.1 --port 8000

dev-worker: ## Run a Celery worker locally
	$(UV) run celery -A sentinelx_workers.celery_app:celery_app worker --loglevel=INFO

dev-web: ## Run the Vite dev server (proxies /api to 127.0.0.1:8000)
	cd $(WEB) && $(PNPM) dev

# --------------------------------------------------------------------------- docker
.PHONY: up down logs ps build smoke clean admin
build: ## Build container images
	$(COMPOSE) build

up: ## Start the full stack in the background and wait until healthy
	$(COMPOSE) up -d --build --wait

down: ## Stop the stack (keeps volumes)
	$(COMPOSE) down

logs: ## Follow logs from all services
	$(COMPOSE) logs -f --tail=100

ps: ## Show service status
	$(COMPOSE) ps

admin: ## Create the first administrator (prompts for email and password)
	@read -p "Admin email: " email; $(COMPOSE) exec api sentinelx-admin create-admin --email "$$email"

smoke: ## Verify the running stack end to end (readiness through Nginx + worker task)
	@curl -fsS http://127.0.0.1:8080/api/v1/health/ready && echo
	@$(COMPOSE) exec -T worker celery -A sentinelx_workers.celery_app:celery_app call system.ping >/dev/null && echo "worker: task accepted"

clean: ## Stop the stack and DELETE volumes (all local data)
	$(COMPOSE) down -v
