# Deployment & Docker Strategy

## Local stack (Docker Compose)

Requirements: Docker Engine 24+ with the Compose v2 plugin.

```bash
make env     # create .env with random secrets (refuses to overwrite)
make up      # build images, run migrations, start everything, wait for health
make admin   # create the first administrator (prompts for email and password)
make smoke   # readiness through Nginx + enqueue a worker task
```

Open <http://localhost:8080>. API docs (non-production only):
<http://localhost:8000/api/docs>.

### Startup order

`postgres` (healthy) → `migrate` (`alembic upgrade head`, must exit 0) →
`redis` (healthy) → `api` + `worker` → `api` healthy → `web`.

### Services

| Service | Image | Published | Hardening |
|---------|-------|-----------|-----------|
| `web` | `sentinelx/web` (nginx-unprivileged) | `127.0.0.1:8080` | non-root, read-only FS, `cap_drop: ALL`, `no-new-privileges`, limits |
| `api` | `sentinelx/api` | `127.0.0.1:8000` | non-root (uid 10001), read-only FS, `cap_drop: ALL`, `no-new-privileges`, limits |
| `worker` | `sentinelx/api` (Celery command) | — | same as API; `backend` network only (no egress) |
| `migrate` | `sentinelx/api` (Alembic) | — | same as API; one-shot |
| `postgres` | `postgres:17.11-alpine3.24` | — | SCRAM auth, internal network, limits |
| `redis` | `redis:7.4.12-alpine3.22` | — | password, protected mode, `noeviction`, internal network, limits |

### Images

* **API/worker:** multi-stage build with `uv` and the frozen lockfile; runtime
  stage contains only the virtualenv, Alembic config and migrations; runs as
  uid/gid 10001; no compilers or package managers.
* **Web:** Node 24 build stage (`pnpm install --frozen-lockfile`, `vite build`);
  runtime is unprivileged Nginx serving static assets and proxying `/api`.

### Configuration

All configuration comes from environment variables (see `.env.example`).
Compose builds the database and Redis URLs from `POSTGRES_*`/`REDIS_PASSWORD`, so
secrets are defined once. Production deployments should inject secrets from a
secret manager (Docker/Kubernetes secrets, Vault, cloud KMS) instead of a file.

## Production considerations (beyond Phase 1)

* Terminate TLS in front of Nginx; set `SENTINELX_ENVIRONMENT=production`
  (enables HSTS, disables API docs, rejects placeholder secrets).
* Pin images by digest; sign and scan images in the release pipeline.
* Run `migrate` as a separate, gated release step.
* Use managed PostgreSQL with backups/PITR and Redis with persistence.
* Client IPs (rate limiting, audit) come from `X-Forwarded-For` only when the
  request originates from the Nginx container (`FORWARDED_ALLOW_IPS=172.30.10.10`,
  fixed address on the `frontend` network). Adjust it to your proxy/load balancer.
* Configure a production email backend before enabling password reset; the
  `console` backend is rejected when `SENTINELX_ENVIRONMENT=production`.
* Redis receives its password on the command line, which is visible to processes
  inside its container; use a mounted ACL/config file in production.

## CI/CD

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | PRs, pushes to `main` | backend lint & types, backend tests (coverage), integration (PostgreSQL + Redis services, migrations up/down/check), frontend lint/types/tests/build, security (Gitleaks, Bandit, pip-audit, Semgrep, pnpm audit) |
| `containers.yml` | pushes to `main`, PRs touching infrastructure/lockfiles | build images, Trivy scan, compose up (`--wait`), readiness via Nginx, worker task round trip, Playwright E2E |
| Dependabot | weekly | GitHub Actions, uv, npm, Docker base images |

All third-party actions are pinned to full commit SHAs, workflows default to
`contents: read`, and checkout does not persist credentials. A release workflow
(tagging, release notes, image publishing) is planned for Phase 12.
