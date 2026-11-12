---
name: add-scanner
description: Checklist for adding or changing a scanner/tool integration in SentinelX's security-engine (scope check, sandboxed execution, egress control, normalization, findings, worker config, container image, tests, docs). Use whenever a task adds a new ScannerName, a new scan profile, or changes how an existing scanner runs.
---

# Adding a scanner

Read `docs/SCANNING_POLICY.md` §4 (technique classes), §5 (always prohibited) and §6 (tool rules) first —
only those sections. If the tool needs anything in §5 (exploitation, brute force, DoS, evasion,
stealth, credential attacks), stop and tell the user: it will not be built.

## Contract — `security-engine/sentinelx_security/scanners/base.py`

Subclass `Scanner` and set the ClassVars: `name` (new `ScannerName` member), `technique`
(`PASSIVE` / `ACTIVE` / `INTRUSIVE`), `description`, `supported_asset_types`, `profiles`,
`default_profile`, and `profile_techniques` for any profile stronger than the default technique.

Implement the five steps:

1. `validate_scope` — inherited; it re-runs the scope engine just before execution. Do not bypass it.
2. `execute(ctx)` — touch **only** `ctx.pinned_addresses` (never re-resolve the hostname: DNS rebinding);
   honour `ctx.timeout_seconds`; return `RawOutput(data, tool_versions=…)`.
3. `normalize_results(raw)` — typed `Observation(kind, key, data, attention)`; plain JSON values only.
   Output is untrusted: bound sizes, never execute or render it.
4. `handle_errors` — map to `ScanError(code, safe message)`; no internals, paths or stack traces.
5. `record_evidence` — `Evidence.bounded(...)` only (64 KiB cap).

### External binaries
Use the `ProcessRunner` protocol + `SubprocessRunner` from `scanners/nmap.py`: argv list (never a shell),
`minimal_env()` (worker secrets are never inherited), stdin closed, process group killed on timeout,
output capped. Inject the runner so tests use a fake. Define a `FORBIDDEN_…` set of flags and build
argv only from server-side profiles — users never pass raw options.

### Tools that open their own connections (crawlers, proxies)
Route them through `EgressGuard`/`EgressPolicy` (`sentinelx_security/egress.py`), as `zap.py` does,
so every connection is checked against scope; report `guard.stats.summary()` in evidence.

## Wiring

| Where | What |
|---|---|
| `scanners/base.py` | add the `ScannerName` member |
| `scanners/__init__.py` | import/export, `ScannerConfig` fields, `build_scanners()`, `CATALOG` |
| `findings.py` | `_from_<tool>()` + dispatch in `derive_findings()` if it produces findings (rule id `<tool>.<id>`, severity map, dedup fingerprint) |
| `workers/sentinelx_workers/scanner_app.py` | settings fields → `scanner_config()` |
| `infrastructure/docker/scanner.Dockerfile` | pinned version + checksum-verified download, read-only, non-root |
| `docker-compose.yml` / `.env.example` | new env vars or isolated service (internal network, no extra egress) |

The API (`apps/api/app/services/scans.py`) and the web UI read the catalog — no hard-coded lists there.
`scans.scanner` is `String(32)`, so no migration is needed for a new name.

## Tests (no public hosts, ever)

- `security-engine/tests/` — use a recorded fixture in `tests/fixtures/` (see `nmap_sample.xml`,
  `nuclei_sample.jsonl`, `zap_alerts.json`) with a fake runner/client.
- Must cover: argv contains no `FORBIDDEN_…` flag for every profile; scope denial stops execution;
  only pinned addresses are contacted; timeout kills the process; oversized/malformed output is handled;
  `handle_errors` leaks nothing; findings mapping + dedup.
- API: extend `apps/api/tests/integration/test_scans.py` for the catalog entry and technique gating
  (needs the `local-infra` skill).
- Then `make check`. Docker image changes are verified only in CI.

## Docs (same change)

`docs/SCANNING_POLICY.md` §6 (tool rules), `docs/ARCHITECTURE.md` if a service is added,
`docs/TESTING.md` results table, `README.md` feature table, `CHANGELOG.md`.
