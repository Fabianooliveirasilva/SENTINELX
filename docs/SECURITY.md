# SentinelX Security Controls

References: [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
(design reference) and [OWASP Top 10](https://owasp.org/www-project-top-ten/)
(risk reference). For reporting vulnerabilities see the root [SECURITY.md](../SECURITY.md).
The threat analysis behind these controls is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Control status

| Control | Status | Where |
|---------|--------|-------|
| Secrets via environment, never in code; `SecretStr`; generated `.env` with mode 0600 | Implemented | `app/core/config.py`, `scripts/generate_env.py` |
| Production guards (placeholder secrets rejected, docs disabled, JSON logs) | Implemented | `Settings._enforce_production_hardening` |
| Strict security headers (CSP, framing, nosniff, referrer, COOP/CORP, HSTS in prod) | Implemented | `app/middleware/security_headers.py`, Nginx snippet |
| CORS allowlist (off by default, no wildcard) | Implemented | `Settings.cors_allowed_origins` |
| Host header allowlist | Implemented | `TrustedHostMiddleware` |
| Error handling without information leakage | Implemented | `app/core/errors.py`, `RequestContextMiddleware` |
| Log redaction (sensitive keys, URL credentials, tracebacks) | Implemented | `app/core/logging.py` |
| Correlation IDs (validated inbound, generated otherwise) | Implemented | `app/middleware/request_context.py` |
| Input validation (Pydantic), SQL via ORM/bound parameters only | Implemented (foundation) | — |
| Celery JSON-only serialization, time limits | Implemented | `workers/sentinelx_workers/celery_app.py` |
| Container hardening (non-root, `cap_drop: ALL`, `no-new-privileges`, read-only FS, resource limits) | Implemented | `docker-compose.yml`, Dockerfiles |
| Network segmentation (internal backend network, localhost-only published ports) | Implemented | `docker-compose.yml` |
| Secret scanning, SAST, dependency audit, image scanning in CI | Implemented | `.github/workflows/` |
| Argon2id, rotating refresh tokens with reuse detection, RBAC, CSRF, lockout, rate limiting, append-only audit log | Implemented | [AUTHENTICATION.md](AUTHENTICATION.md) |
| Tenant isolation (project-scoped queries, 404 for foreign resources) | Implemented | `app/repositories/projects.py` |
| Trusted proxy configuration (client IP from Nginx only) | Implemented | `docker-compose.yml` (`FORWARDED_ALLOW_IPS`) |
| Production e-mail backend (SMTP with STARTTLS/TLS and verified certificates) | Implemented | `app/services/email.py` |
| Alert webhooks: SSRF-safe delivery (per-delivery policy check, IP pinning, no redirects), HMAC signatures, encrypted secrets | Implemented | `app/services/notifications.py`, [THREAT_MODEL.md](THREAT_MODEL.md) T28–T29 |
| Multi-factor authentication | Planned | Phase 12 |
| SSRF/scope enforcement, DNS rebinding and redirect defenses | Implemented | [SCANNING_POLICY.md](SCANNING_POLICY.md), `security-engine/` |
| Scanner sandboxing and egress restriction | Implemented | Phases 4–5 |
| AI prompt-injection defenses and data minimization | Planned | Phase 9 |

## Quality gates (CI)

* No failing tests (unit, API, integration, E2E).
* No secrets detected (Gitleaks, full history).
* No Bandit or Semgrep findings at the configured rulesets.
* No known vulnerabilities in locked Python dependencies (pip-audit, strict).
* No high/critical vulnerabilities in frontend dependencies (pnpm audit).
* No fixable critical vulnerabilities in container images (Trivy).
* Migrations apply, round-trip, and match the models (`alembic check`).
* The compose stack starts healthy and serves real readiness data.

Automated scanners not reporting issues is **not** evidence that the system is
secure; manual review remains part of every phase.
