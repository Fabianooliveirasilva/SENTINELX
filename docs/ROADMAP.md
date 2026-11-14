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
| 7 | Risk engine | Deterministic, versioned, explainable risk model; configurable weights | **Delivered** |
| 8 | Monitoring & events | Event ingestion, alerts, timeline, filters, notification abstraction (email/webhook ready) | **Delivered** |
| 9 | AI security analyst | Anthropic provider abstraction, structured outputs, prompt versioning, prompt-injection defenses, budgets, deterministic fallback | **Delivered** |
| 10 | Reporting | PDF + JSON reports with scope, methodology, evidence, tool versions, AI content labeled | **Delivered** |
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
| Functional risk engine | 7 ✅ |
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

## Phase 7 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Deterministic, versioned model: CVSS/severity base, confidence, asset criticality and exposure, KEV, EPSS, exposure window; factor contributions sum to the score | `security-engine/tests/test_risk.py` |
| 2 | Scores and explanations stored on findings; history row only on real changes; rescoring on scan, correlation, asset context, intel (KEV/EPSS) and daily | `test_findings_are_scored_and_sorted_by_risk`, `test_asset_context_changes_rescore`, `test_cve_findings_use_cvss_kev_and_epss`, `test_daily_rescoring_adds_the_exposure_window` |
| 3 | Admin-configurable, bounded, audited weights with immediate rescoring and reset | `test_weights_are_admin_only_validated_audited_and_rescore`, `test_weights_validation` |
| 4 | Project posture (never below the worst issue, robust to noise), top risks, daily snapshots and 30-day trend; suppression lowers posture immediately | `test_bands_and_posture`, `test_project_posture_top_risks_and_trend` |
| 5 | FIRST EPSS client (batched, defensive) and daily sync for CVEs in active findings | `test_epss_*`, live smoke |
| 6 | UI: risk column, sort and band filter on findings; factor breakdown and score history on finding detail; project Risk tab; Risk Model page (read-only for non-admins) | Vitest `risk.test.tsx`, `findings.test.tsx`, Playwright |

**Live verification.** On the Phase 6 lab project (Apache 2.4.49, WordPress 6.4.2)
the intel worker fetched live EPSS scores for 93 CVEs and the daily task rescored
105 findings; KEV-listed CVEs with high EPSS ranked first, each with a factor
breakdown such as *"Critical risk (100/100): starts at 91 from CVSS 9.1; known
exploited +20.0, confidence −18.2, exploit prediction +15.0."*

## Phase 8 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | `security_events` timeline written in the same transaction as the change: new/reopened/resolved findings, analyst status changes, risk-band changes, new CISA KEV listings, certificate expiry, scan completed/failed/cancelled/scope-denied, emergency stop/resume, asset and authorization changes, skipped schedules | `test_scans_and_findings_populate_the_timeline`, `test_failed_scans_triage_and_emergency_stop_are_events`, `test_kev_listing_emits_an_event_once`, `test_risk_band_changes_are_events` |
| 2 | Timeline API with type, minimum severity, asset and period filters; 7-day severity summary; project isolation | same tests, `test_timeline_is_project_isolated` |
| 3 | Per-project alert rules (event types, severity floor, optional asset, channels) with quiet periods; suppressed repeats are recorded, not sent | `test_rules_match_severity_type_and_quiet_period`, `test_rule_matching` |
| 4 | Notification outbox delivered by a dedicated `notifier` worker: e-mail (new SMTP backend, STARTTLS/TLS, verified certificates) and HMAC-signed webhooks; retries with exponential backoff, permanent failure on 4xx, delivery log | `test_webhook_delivery_is_signed_and_pinned`, `test_failed_deliveries_retry_with_backoff_then_give_up`, `test_smtp_sender_uses_starttls_and_strips_header_injection` |
| 5 | Webhook SSRF defenses: https only in production (re-checked per delivery), every resolved address policy-checked, request pinned to the checked IP with original Host/SNI, no redirects, no proxies, bodies never read; signing secrets generated server-side, shown once, encrypted at rest, never audited | `test_webhook_refuses_internal_destinations`, `test_channel_validation_and_secret_handling`, `test_production_refuses_cleartext_webhooks_at_delivery` |
| 6 | Scheduled scans run through the interactive request path as their owner: membership, permission, authorization window, quotas and emergency stop re-checked on every run; skipped runs recorded and emitted; claim-before-run, no catch-up bursts | `test_schedules_start_scans_with_owner_authority`, `test_schedules_skip_when_controls_forbid_the_scan` |
| 7 | New permission `alerts:manage` (admin, analyst) seeded by migration `0008`; RBAC catalog and database stay in sync | `test_database_rbac_seed_matches_code_catalog`, `test_alert_configuration_permissions` |
| 8 | UI: project Events (timeline, filters, severity tiles), Alerts (rules, channels with one-time secret reveal, delivery log) and Schedules tabs | Vitest `monitoring.test.tsx`, Playwright `monitoring.spec.ts` |

**Live verification.** With the real API, Celery beat, the orchestrator/notifier
worker and the scanner sandbox running locally, a schedule started an HTTP scan
through beat, the scan produced six findings and timeline events, and the alert
rule (minimum severity *medium*) delivered only the *medium* finding — by e-mail
and by webhook to a LAN receiver, whose `X-SentinelX-Signature` verified with the
channel secret.

**Fixed along the way.** The live test exposed a race present since Phase 4: the
API published a scan's Celery chain before marking the job `queued`, so a fast
worker could skip it. Jobs are now queued before publishing (fixed on the Phase 4
branch and merged upward, with a regression test that runs a concurrent worker).

**Limitations.** Schedules use fixed intervals (1 hour to 90 days) rather than cron
expressions. An e-mail channel with several recipients is retried as a whole, so a
partial SMTP failure can repeat the message to recipients that already got it.
Alert rules match event type, severity and asset; richer conditions (risk band,
KEV only, tags) can be expressed through event types today and may be added later.
Compose, the `notifier` container and its egress network are verified in CI only.

## Phase 9 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Five analysis kinds — finding analysis (explanation, impact, remediation, investigation steps), scan summary, scan comparison, executive summary, technical summary — returned as jobs and polled | `test_without_a_provider_analyses_are_deterministic`, `test_scan_comparison`, Vitest `ai.test.tsx` |
| 2 | Provider abstraction with an Anthropic implementation (official SDK, `claude-opus-5-5`, structured outputs, adaptive thinking at a configured effort, server-side refusal fallback, cached system prompt, no tools) | `test_anthropic_provider_request_shape_and_result` (real SDK against a mock transport) |
| 3 | Optional: without a provider, over budget, on refusal, timeout, rate limit, truncation, invalid output or a queue outage, a deterministic analysis with the same schema and a recorded reason | `test_provider_failures_fall_back_deterministically`, `test_queue_outage_and_stale_jobs`, `test_daily_token_budget`, `test_anthropic_provider_failures_map_to_safe_reasons` |
| 4 | Data minimization: asset values, hosts (including any host in a URL), IPv4/IPv6 addresses and e-mail addresses pseudonymized before sending and restored for display; credential-looking values redacted; evidence bounded | `test_pseudonymizer_*`, `test_hosts_inside_urls_*`, `test_untrusted_text_*`, `test_model_output_is_minimized_validated_and_restored` |
| 5 | Prompt-injection defenses: scanner-derived text delimited and labelled untrusted, versioned system rules, schema-constrained output, no tool execution, output rendered as text | same tests; hostile-banner fixture; Vitest renders `<script>` literally |
| 6 | Evidence binding: every claim carries a basis (confirmed evidence / scanner hypothesis / external intelligence / AI recommendation) and references; unknown references removed, unsupported bases downgraded, claims naming CVEs outside the assessment data dropped, every correction recorded as a warning | `test_validator_enforces_references_bases_and_known_cves` |
| 7 | Cost and token controls: per-request output cap, timeout and single retry, per-project daily token budget, identical-request reuse (24 h), token and cost accounting per analysis, usage endpoint | `test_identical_requests_reuse_results_unless_refreshed`, `test_daily_token_budget` |
| 8 | Isolation and accountability: dedicated `ai` worker on its own queue and egress network, the only container with the API key; `ai:use` to request and review, `findings:read` to read; human review recorded and audited | compose check, `test_permissions_and_project_isolation`, `test_human_review_is_recorded` |
| 9 | UI: AI panel on finding and scan pages (with scan comparison), project AI analyst page with usage, executive/technical summaries and history; provider, model, prompt version and review state always visible | Vitest `ai.test.tsx`, Playwright `ai.spec.ts` |

**Live verification.** With the real API and Celery worker, an analysis requested
with the provider switched on but no API key travelled API → `ai` queue → worker
and completed deterministically (`ai_not_configured`) without any outbound call.
The Anthropic request itself is verified against the official SDK with a mock
transport. **No live call to the Anthropic API was made**: the development host
has no API key, and a live run is billed — it needs the operator's key.

**Limitations.** Hostnames that appear in free text without a URL scheme and are
not registered assets are not pseudonymized. The budget check is not atomic:
concurrent requests can overshoot the daily budget by at most one request each.
The model output is validated for references, bases and CVE identifiers, not for
the factual accuracy of every sentence; human review remains required.

## Phase 10 — delivered

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Project and single-scan reports in PDF and machine-readable JSON (versioned `sentinelx-report/1.0` document — the single source for both formats) | `test_json_report_contents_and_integrity`, `test_pdf_report` |
| 2 | Contents: executive summary, assessment scope, authorization references, methodology, scan dates, assets, findings (severity, confidence, risk and explanation, CWE, CVE/CVSS/KEV/EPSS, timestamps, description, remediation, references), severity distribution, technical evidence (bounded), risk prioritization, remediation plan, limitations, tool versions | same tests; PDF inspected page by page on a live lab scan |
| 3 | Automated findings and AI commentary clearly separated: AI content only from analyses a person reviewed, in its own section, labelled with provider, model, prompt version and reviewer; deterministic summaries labelled as such | `test_ai_commentary_only_when_reviewed_and_labelled` |
| 4 | Asynchronous generation on the orchestrator worker (database only), size cap, checksum (SHA-256) and size stored; downloads served with the checksum header, `Content-Disposition: attachment` and `no-store`; requests, downloads and deletions audited | integration tests, `test_report_task_is_registered` |
| 5 | Untrusted text cannot alter the PDF: everything is escaped before ReportLab's paragraph markup, evidence uses a non-parsing block; no images, links or URIs can be injected; rendering is deterministic | `test_pdf_is_valid_and_markup_in_data_stays_text`, `test_pdf_rendering_is_deterministic` |
| 6 | Scope options (project or scan, closed findings, evidence, reviewed AI) and permissions: `reports:generate` to create/delete, `reports:read` to list/download; project isolation | `test_scan_scope_and_resolved_findings`, `test_permissions_isolation_and_lifecycle` |
| 7 | UI: Reports tab with builder, history (status, size, SHA-256), authenticated download | Vitest `reports.test.tsx`, Playwright `reports.spec.ts` (downloads the PDF and checks it) |

**Live verification.** On a LAN lab web application, a real HTTP scan produced six
findings; a reviewed executive summary and a PDF report were generated by the
worker and downloaded through the API with a matching SHA-256. Inspecting the PDF
page by page found two defects that tests had not caught — the remediation plan
was ordered from least to most urgent, and timestamps were unreadable ISO strings
— both fixed and covered by new tests.

**Limitations.** Reports include at most 500 findings (the highest-risk ones,
noted in the report) and two evidence excerpts per finding. Content is stored in
PostgreSQL (≤ 25 MB per report); there is no retention policy yet. PDFs are not
digitally signed; integrity relies on the stored SHA-256.

## Phase 11 proposal — Dashboard & UX completion

* Dashboard on real data: total assets, active scans, critical vulnerabilities,
  risk distribution, posture score and trend, recent findings, scan activity,
  asset exposure, remediation progress (Recharts, accessible, light/dark-safe).
* Remaining pages from the master plan reviewed for completeness (Reconnaissance
  overview, Vulnerability management across projects, Threat Intelligence,
  Settings), consistent loading / empty / error states.
* Accessibility pass (keyboard navigation, focus, contrast, ARIA labels) and
  responsive layout checks; visual review of every page.
