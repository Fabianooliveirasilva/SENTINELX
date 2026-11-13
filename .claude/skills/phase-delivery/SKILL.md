---
name: phase-delivery
description: Start or close a SentinelX roadmap phase following the master prompt's workflow (§15) and Definition of Done (§16) — scope check, verification, docs updates, the end-of-phase report and the approval stop. Use when the user approves/starts a new phase, when a phase's implementation looks finished, or before saying a phase is "complete"/"delivered".
---

# Phase delivery

Phases are listed in `docs/ROADMAP.md` ("Phase overview" table). One phase per branch
`feat/phase-<N>-<topic>`, created from the previous phase branch (see `stacked-branches`).

## A. Starting a phase (only after explicit user approval)

1. Read only the `Phase <N> proposal` section of `docs/ROADMAP.md` and the docs the phase touches.
2. Present to the user, briefly: objective, modules/files involved, data model changes,
   security risks (authz, project isolation, untrusted input, SSRF/egress, secrets in logs),
   numbered acceptance criteria, what is explicitly out of scope.
3. Implement in the smallest coherent units, test-first (`superpowers:test-driven-development`).
   Never ship placeholders, fake success responses or hard-coded metrics; mocks only in tests.

## B. Definition of Done — verify every line before calling the phase complete

- [ ] Every acceptance criterion implemented **and** mapped to a test or a recorded check.
- [ ] Migrations: new Alembic revision upgrades and downgrades cleanly; `alembic check` passes.
- [ ] Authorization: backend-enforced RBAC + project isolation tests for every new endpoint
      (viewer cannot write, other project's IDs return 404).
- [ ] Error handling: consistent error format, no internals leaked; timeouts on external calls.
- [ ] No broken imports, dead routes or unused UI entries; the app still starts.
- [ ] Commands, each run and its output read (start DB/Redis with `local-infra`):
      ```bash
      (cd apps/api && uv run alembic upgrade head && uv run alembic check && uv run alembic downgrade -1 && uv run alembic upgrade head)
      make check                                  # ruff, mypy strict, pytest, vitest, eslint, tsc, bandit, pip-audit, pnpm audit
      uv run pytest -m "" --cov                   # full backend suite + coverage gate
      cd apps/web && pnpm build && pnpm test:e2e  # when UI changed (needs a running API)
      ```
- [ ] Live smoke test of the new flow end to end when feasible (API → worker → DB → UI).
- [ ] Security review of the diff (`/security-review` or `claude-security`), findings fixed or documented.
- [ ] Anything Docker-only (compose, image build, Trivy, real ZAP/Nuclei) marked **"CI only, not run locally"** —
      never reported as passed.

## C. Docs to update in the same branch

| File | Change |
|---|---|
| `docs/ROADMAP.md` | Status → **Delivered** in the overview table; replace `Phase <N> proposal` with `Phase <N> — delivered` (criterion → verification table + **Limitations** paragraph); add `Phase <N+1> proposal` |
| `docs/TESTING.md` | New `Latest results (Phase <N>, local run <YYYY-MM-DD>)` table on top; rename the previous one to `Phase <N-1> results` |
| `CHANGELOG.md` | `## [0.<N>.0] — <date> — Phase <N>: <name>` with Added / Changed / Security (Keep a Changelog) |
| `README.md` | "Project status" banner and the Features table row → ✅ Phase <N> |
| Topic docs | `API.md` (endpoints), `DATABASE.md` (tables/ER), `ARCHITECTURE.md` (new components/ADRs), `THREAT_MODEL.md` / `SCANNING_POLICY.md` / `SECURITY.md` when affected |

Docs are in professional English.

## D. Commit, push, report, STOP

1. Conventional Commits; push the branch; give the PR link
   `https://github.com/Fabianooliveirasilva/SENTINELX/pull/new/<branch>`.
2. Update the phase-status memory (branch, commit, what's next).
3. Report to the user **in Portuguese**, with these sections:
   - **Entregue** — features, in plain terms
   - **Arquivos** — created/changed, grouped by area (links)
   - **Decisões de arquitetura** — and why
   - **Comandos** — how to run/try it
   - **Testes executados e resultados** — real numbers from this run; CI-only items listed separately
   - **Limitações conhecidas**
   - **Próxima fase (proposta)** — scope summary
4. **Stop.** Do not start the next phase until the user explicitly approves it.
