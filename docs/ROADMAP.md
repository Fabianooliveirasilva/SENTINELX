# SentinelX Roadmap

Each phase ends with: implementation, passing tests, security review, updated
documentation and an explicit approval before the next phase starts.

## Phase overview

| # | Phase | Key deliverables | Status |
|---|-------|------------------|--------|
| 1 | Foundation & architecture | Monorepo, API/worker/web skeletons, PostgreSQL, Redis, Docker Compose, health checks, logging, test foundations, CI | **Delivered** |
| 2 | Identity, access & tenancy | Users, Argon2id, access + rotating refresh tokens, session revocation, password reset, RBAC (Admin / Security Analyst / Viewer), projects, audit log, rate limiting, CSRF, login UI | **Delivered** |
| 3 | Assets & scope enforcement | Asset inventory (domain, subdomain, IP, web app, API endpoint, service), authorization records, scope engine (DNS rebinding, private ranges, IPv6, redirects, SSRF), asset history, inventory UI | **Delivered** |
| 4 | Scan orchestration & reconnaissance | Job model & states, scanner interface (`validate_scope/execute/normalize_results/handle_errors/record_evidence`), sandbox runner, DNS analyzer, passive subdomain discovery, TLS analyzer, Nmap safe profiles, technology fingerprinting | **Delivered** |
| 5 | Vulnerability assessment | OWASP ZAP baseline (active only with explicit authorization), Nuclei curated/pinned templates, HTTP security checks, findings normalization, evidence, lifecycle states | **Delivered** |
| 6 | Threat intelligence | NVD sync with rate limits and caching, CVE/CWE/CPE, version-range matching with confidence, provenance | **Delivered** |
| 7 | Risk engine | Deterministic, versioned, explainable risk model; configurable weights | Planned |
| 8 | Monitoring & events | Event ingestion, alerts, timeline, filters, notification abstraction (email/webhook ready) | Planned |
| 9 | AI security analyst | Anthropic provider abstraction, structured outputs, prompt versioning, prompt-injection defenses, budgets, deterministic fallback | Planned |
| 10 | Reporting | PDF + JSON reports with scope, methodology, evidence, tool versions, AI content labeled | Planned |
| 11 | Dashboard & UX completion | Dashboard on real data, remaining pages, accessibility pass | Planned |
| 12 | Hardening & release | Metrics/observability, ZAP against SentinelX itself, container hardening review, release workflow, final docs | Planned |

## Mapping to the project success checklist

| Success criterion | Phase |
|-------------------|-------|
| Authentication and RBAC working | 2 ✅ |
| Registration and validation of authorized assets | 3 ✅ |
| DNS reconnaissance and TLS analysis | 4 ✅ |
| Functional Nmap integration | 4 ✅ |
| Functional OWASP ZAP integration | 5 ✅ |
| Controlled Nuclei integration | 5 ✅ |
| CVE lookup and correlation | 6 ✅ |
| Functional risk engine | 7 |
| Monitoring and event history | 8 |
| Anthropic API integration | 9 |
| PDF and JSON reports | 10 |
| Dashboard fed by real data | 11 |
| Working Docker Compose | 1 (foundation) → extended every phase |
| CI/CD with quality gates | 1 (foundation) → extended every phase |
| Unit, integration and E2E tests | 1 (foundation) → extended every phase |
| Complete documentation in English | 1 (foundation) → completed in 12 |

## Phase 1 acceptance criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Monorepo with API, workers and web app, one lockfile per ecosystem | `uv.lock`, `apps/web/pnpm-lock.yaml` |
| 2 | FastAPI app factory with versioned `/api/v1` router and OpenAPI (non-prod) | `tests/api/test_http_behaviour.py` |
| 3 | Typed, validated configuration; unsafe values rejected; production guards | `tests/unit/test_config.py` |
| 4 | Liveness and readiness endpoints; readiness checks DB + Redis with timeouts, 503 on failure, no internal details leaked | `tests/api/test_health.py`, `tests/integration/` |
| 5 | Async database connectivity and Alembic baseline migration (upgrade, downgrade, `alembic check`) | CI `backend-integration` job |
| 6 | Structured JSON logging with correlation IDs and secret redaction | `tests/unit/test_logging.py` |
| 7 | Consistent error envelope; unhandled errors return a generic 500 with request ID and security headers | `tests/api/test_http_behaviour.py` |
| 8 | Celery worker with safe defaults and a verifiable task | `workers/tests/`, compose smoke step |
| 9 | React + TypeScript SPA with design tokens, router, data layer and a page fed by real backend data | Vitest suite, Playwright E2E |
| 10 | Docker Compose: hardened services, internal backend network, health-gated startup, migrations before app start | `containers.yml` workflow, `make up && make smoke` |
| 11 | CI: lint, types, tests, build, secret scanning, SAST, dependency audit, image scan, compose smoke + E2E | `.github/workflows/` |
| 12 | Documentation: architecture, roadmap, database proposal, threat model, scanning policy, security, testing, deployment | `docs/` |

## Phase 2 — delivered

See [AUTHENTICATION.md](AUTHENTICATION.md) for the full design. Acceptance criteria:

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Argon2id hashing, password policy, uniform timing for unknown accounts | `tests/unit/test_security_primitives.py`, `test_auth.py` |
| 2 | Short-lived access tokens; invalid/expired/`alg=none`/wrong-audience tokens rejected | `test_auth.py::test_invalid_access_tokens_are_rejected` |
| 3 | Refresh rotation with reuse detection revoking the session family | `test_refresh_token_reuse_revokes_the_whole_session` |
| 4 | CSRF on cookie-authenticated endpoints, bound to the session | `test_refresh_requires_matching_csrf_token`, `test_csrf_token_is_bound_to_its_session` |
| 5 | Logout, session listing/revocation, forced sign-out, immediate invalidation on password change / deactivation | `test_auth.py`, `test_rbac_users.py` |
| 6 | Password reset: single use, expiring, no account enumeration | `test_password_reset_*` |
| 7 | Lockout and rate limiting with `Retry-After` | `test_account_locks_after_repeated_failures`, `TestLoginRateLimit` |
| 8 | Server-side RBAC for every endpoint; DB seed equals code catalog; no mass assignment | `test_rbac_users.py` |
| 9 | Project isolation: non-members get 404; membership management | `test_projects_audit.py` |
| 10 | Append-only audit log with request correlation | `test_audit_log_is_append_only`, `test_audit_log_records_and_filters_actions` |
| 11 | UI: login, reset, guards, users & roles, projects, audit, account; RBAC-aware navigation | Vitest suite, Playwright `auth-rbac.spec.ts` |

## Phase 3 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Asset types domain, subdomain, IP, web application, API endpoint, service with strict normalization (IDNA, canonical IPs, origins) and per-project uniqueness | `security-engine/tests`, `test_assets_scope.py` |
| 2 | Internal, special-use, numeric-ambiguous and metadata targets cannot be registered | `test_unsafe_or_malformed_assets_are_rejected` |
| 3 | Immutable authorization records (window, techniques, subdomains, IP ranges) with revocation and audit history | `test_authorization_lifecycle_and_history` |
| 4 | Authorization limits: window, range breadth, public ranges only, intrusive = admin + active (DB constraint too) | `test_authorization_validation`, `test_database_enforces_authorization_invariants` |
| 5 | Deny-by-default scope engine: no domain-implies-IP assumption, DNS-rebinding, IPv4-in-IPv6, redirects, lab networks | `test_engine.py` (139 engine tests) |
| 6 | `POST /projects/{id}/scope/check` explains every decision; rate limited; project isolated | `test_scope_check_*` |
| 7 | UI: inventory, asset detail with eligibility, authorizations and history, scope check tool | Vitest `assets.test.tsx`, Playwright `assets-scope.spec.ts` |

**Design notes.** CIDR *assets* were left out on purpose: authorizations carry IP
ranges, but assets are concrete hosts so that scans never fan out over whole
networks. Asset history is served from the append-only audit log rather than a
second history table.

## Phase 4 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | `scan_jobs` / `scan_results` / `scan_evidence` persisted in PostgreSQL with states `pending → queued → running → completed \| failed \| cancelled`; `POST /projects/{id}/scans` returns `202` + job | `test_scan_lifecycle_end_to_end` |
| 2 | Scanner interface `validate_scope / execute / normalize_results / handle_errors / record_evidence`; scope re-evaluated with fresh DNS at execution, scanners receive pinned IPs only | `test_scope_is_rechecked_at_execution_time`, `test_rebinding_domain_is_denied_at_execution`, `test_executor.py` |
| 3 | Scanner sandbox: separate Celery app/queue and container (non-root, no capabilities, read-only FS, CPU/memory/PID limits, no DB credentials or secret key), process recycled after every scan | `test_sandbox_configuration_is_isolated`, Containers workflow |
| 4 | Scanners: DNS posture (SPF/DMARC/CAA), passive CT subdomain discovery with provenance, TLS analyzer, Nmap TCP-connect safe profiles, HTTP technology fingerprinting + security headers — all tested with recorded fixtures or local servers | `test_scanners.py` |
| 5 | Per-project concurrency and daily quotas, user cancellation, platform-wide emergency stop with resume, stale-job expiry | `test_concurrency_quota`, `test_cancel_queued_scan`, `test_emergency_stop`, `test_stale_jobs_expire` |
| 6 | UI: scans list, scan configuration (only eligible scanners/profiles), execution details (scope decision, observations, evidence as inert text), emergency stop | Vitest `scans.test.tsx` |

**Design notes.** Scanner output is stored as *observations*, not findings:
findings, severity and lifecycle arrive in Phase 5. Discovered subdomains are
never scanned automatically — they need their own registration and authorization.
Network-level egress filtering of the sandbox (allowing only the pinned
addresses) is enforced in-process by the scope engine today; a host/egress-proxy
firewall is listed under production hardening in [DEPLOYMENT.md](DEPLOYMENT.md).

## Phase 5 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Findings with stable fingerprints, severity, confidence, CWE, remediation, references; occurrences as evidence trail; status lifecycle with history and audit | `test_findings.py` (API), `security-engine/tests/test_findings.py` |
| 2 | Deterministic, versioned rules map Phase 4 observations (TLS, HTTP headers, DNS/e-mail, exposed services) to findings; re-scans update, regressions reopen, absent issues auto-resolve per scanner + profile; analyst suppressions respected | `test_auto_resolution_and_regression`, `test_triage_and_suppression` |
| 3 | Egress guard: only the authorized host:port, pinned IPs, no DNS, budgets, denied destinations recorded | `security-engine/tests/test_egress.py` |
| 4 | Nuclei: pinned and checksum-verified binary/templates, allowlisted directories, http protocol only, excluded tags, no interactsh, behind the guard | `test_vuln_scanners.py` (guard probed while the tool runs) |
| 5 | ZAP: isolated daemon reachable only through the guard; scoped context; bounded spider; passive rules; active scan only in the `full` profile, which requires an intrusive authorization | `test_vuln_scanners.py`, `test_intrusive_profile_requires_an_intrusive_authorization`, Containers workflow |
| 6 | UI: Findings tab (severity summary, filters), finding detail (evidence, references, history), triage with mandatory reasons, findings delta on scan details | Vitest `findings.test.tsx`, Playwright |

**Limitations.** Real ZAP and Nuclei executions are exercised only in the
Containers workflow (the development host cannot run them); adapters are tested
against recorded API responses and JSONL output. ZAP authenticated scanning and
API-definition import (OpenAPI) are not implemented yet.

## Phase 6 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | NVD CVE API 2.0 client: pagination, API key, NVD rate-limit spacing, bounded retries/backoff, 120-day window splitting, size caps, defensive parsing (rejected CVEs, bad CPEs, non-https references) | `security-engine/tests/test_intel.py` (real NVD responses as fixtures) |
| 2 | CPE 2.3 parsing (escapes) and version-range matching with inclusive/exclusive bounds; pre-release vs patch suffixes (`1.0rc1 < 1.0`, `1.0.2k > 1.0.2`, `8.9p1 > 8.9`) | `test_compare_versions`, `test_range_matching_respects_every_bound` |
| 3 | Software inventory from HTTP, Nmap `-sV` and Nuclei tech matches, curated CPE mapping; versionless or unmapped components never correlated | `test_inventory_extraction`, `test_versionless_components_never_match` |
| 4 | CVE findings through the standard lifecycle (`tentative`, CVSS-based severity, KEV noted); upgrades auto-resolve; late NVD refresh re-correlates existing inventory | `test_scan_correlates_versions_and_resolves_after_upgrade`, `test_late_nvd_refresh_recorrelates_existing_inventory` |
| 5 | CISA KEV catalog applied to stored CVEs; feed and per-product sync state with errors | `test_cve_search_detail_kev_and_status`, `test_refresh_errors_are_recorded_not_raised` |
| 6 | Dedicated `intel` worker with feed-only egress; beat schedules product refresh (6 h) and KEV (24 h) | `test_intel_tasks_run_on_their_own_queue`, Containers workflow |
| 7 | UI: Threat Intel page (sources, tracked products, CVE search with KEV filter), CVE detail (ranges, KEV, references), project Software tab, CVE links from findings | Vitest `intelligence.test.tsx`, Playwright |

**Live verification.** A local lab server announcing `Apache/2.4.49` was scanned
through the real pipeline; the intel worker fetched 956 CVEs for
`apache:http_server` and `wordpress:wordpress` from the live NVD API and produced
93 tentative CVE findings. Spot checks against NVD data: CVE-2021-41773 and
CVE-2021-42013 (2.4.49 listed) matched; CVE-2021-40438 (≤ 2.4.48) and
CVE-2017-9798 correctly did not.

**Limitations.** No EPSS score yet; CPE mapping is a curated table (unknown
products are inventoried but not correlated); configurations combining an
application with a required platform (`AND` nodes) are evaluated on the
vulnerable application criterion only.

## Phase 7 proposal — Risk engine

* Deterministic, versioned risk model (`risk_model_version`) computing a 0–100
  score per finding from: base severity/CVSS, confidence, CISA KEV, EPSS (FIRST
  API, optional), asset criticality and exposure, finding age, and evidence type.
* Every score stored with its factor breakdown and a plain-language explanation;
  re-scored when inputs change; history kept.
* Configurable weights per platform (admin), with validation and audit.
* Project risk posture: aggregated score, top risks, trend over time.
* UI: risk column and sort on findings, factor breakdown on finding detail,
  project risk overview.
