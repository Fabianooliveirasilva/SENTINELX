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
| `worker` | `sentinelx/api` (Celery command) | — | same as API; `backend` network only (no egress); consumes `celery` + `orchestrator` queues and runs the embedded beat schedule (stale-job expiry) |
| `scanner-zap` | `sentinelx/scanner` (Celery, `scans.zap` queue, concurrency 1) | — | same as `scanner`; also on `zap-net`; hosts the egress guard ZAP must use (port 8899) |
| `intel` | `sentinelx/api` (Celery, `intel` queue) | — | same as API; `backend` + `intel-egress`; reaches only the NVD API and the CISA KEV feed |
| `zap` | `zaproxy/zap-stable:2.17.0` (daemon) | — | `zap-net` only (internal, no egress); API key; read-only FS with tmpfs home; `cap_drop: ALL`; 2 GiB limit |
| `scanner` | `sentinelx/scanner` (Celery, `scans` queue) | — | non-root (uid 10002), read-only FS, `cap_drop: ALL`, `no-new-privileges`, CPU/memory/PID limits; **no DB URL or secret key**; `backend` + `scan-egress` networks |
| `migrate` | `sentinelx/api` (Alembic) | — | same as API; one-shot |
| `postgres` | `postgres:17.11-alpine3.24` | — | SCRAM auth, internal network, limits |
| `redis` | `redis:7.4.12-alpine3.22` | — | password, protected mode, `noeviction`, internal network, limits |

### Images

* **API/worker:** multi-stage build with `uv` and the frozen lockfile; runtime
  stage contains only the virtualenv, Alembic config and migrations; runs as
  uid/gid 10001; no compilers or package managers.
* **Scanner:** same Python build, runtime adds Debian's `nmap`, CA certificates,
  the Nuclei binary and a template release (both downloaded with `ADD --checksum`
  against pinned SHA-256 values; bump `NUCLEI_*` build args together with their
  hashes); runs as uid/gid 10002 from `/tmp`; unprivileged TCP connect scans
  only, so no capabilities are granted.
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
* **Scanner egress.** Put the `scan-egress` network behind an egress firewall or
  proxy that blocks RFC 1918, link-local, loopback and cloud-metadata ranges, and
  give the scanner its own Redis ACL user restricted to the queue keys. The scope
  engine already refuses those destinations in-process; the network control is
  defense in depth against a compromised scanner binary.
* Scan tuning: `SENTINELX_SCAN_TIMEOUT_SECONDS`, `SENTINELX_SCAN_QUEUE_TIMEOUT_SECONDS`,
  `SENTINELX_MAX_CONCURRENT_SCANS_PER_PROJECT`, `SENTINELX_MAX_DAILY_SCANS_PER_PROJECT`
  (API/worker) and `SENTINELX_PASSIVE_SOURCES_ENABLED` (scanner);
  `SENTINELX_ZAP_SCAN_TIMEOUT_SECONDS` (default 900). `ZAP_API_KEY` is generated
  by `make env` and shared only by `zap` and `scanner-zap`.
* **Intel egress.** Restrict `intel-egress` to `services.nvd.nist.gov` and
  `www.cisa.gov` (HTTPS) with an egress proxy or firewall. Set
  `SENTINELX_NVD_API_KEY` (free) to raise the NVD limit from 5 to 50 requests per
  30 seconds; `SENTINELX_INTEL_ENABLED=false` disables all feed traffic.
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
