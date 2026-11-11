# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-11-10 — Phase 1: Foundation

### Added
- Monorepo: uv workspace (`apps/api`, `workers`) and pnpm-managed `apps/web`.
- FastAPI application factory with versioned `/api/v1` router and OpenAPI
  (disabled in production).
- Typed configuration with `pydantic-settings`, secret types and production guards.
- Liveness and readiness endpoints (PostgreSQL + Redis, concurrent, time-bounded).
- Async SQLAlchemy 2 engine, declarative base with naming conventions, Alembic
  (async) with a baseline revision.
- Structured JSON logging with correlation IDs, sensitive-key and URL-credential
  redaction.
- Consistent error envelope; unhandled errors return a generic 500 with request ID.
- Security headers, trusted-host allowlist, opt-in CORS allowlist.
- Celery worker with JSON-only serialization, time limits and a `system.ping` task.
- React 19 + TypeScript SPA: design tokens, app shell, typed Zod-validated API
  client, TanStack Query, System Status page on live data, 404 page.
- Docker images (non-root, multi-stage) and hardened Docker Compose stack with an
  internal backend network.
- CI: lint, strict typing, unit/API/integration tests, frontend build,
  Gitleaks, Bandit, Semgrep, pip-audit, pnpm audit; container build, Trivy, compose
  smoke and Playwright E2E; Dependabot.
- Documentation: architecture & ADRs, roadmap, database proposal, API, security,
  threat model, scanning policy, testing, deployment.
