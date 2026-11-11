# Contributing to SentinelX

Thank you for your interest in improving SentinelX.

## Ground rules

* SentinelX is for **authorized** security testing. Contributions that add
  exploitation, brute force, denial of service, evasion or stealth capabilities
  will not be accepted. Read the [scanning policy](docs/SCANNING_POLICY.md).
* Never commit secrets, real customer data or scan results from real targets.
* Tests must never depend on public third-party hosts.

## Development setup

```bash
make install   # Python (uv workspace) + frontend (pnpm) dependencies
make env       # local .env with random secrets
make check     # lint, type checks, tests and security audits
```

## Workflow

1. Create a branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`.
2. Keep changes small and focused; include tests for new behavior and for
   security properties (authorization, input validation, error leakage).
3. Update the relevant documents in `docs/` in the same pull request.
4. Use [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`).
5. Open a pull request; all CI checks must pass before review.

## Code standards

**Python:** Ruff (lint + format), mypy `--strict`, absolute imports only, typed
public functions, no `print`, no bare `except`, no `assert` for validation,
no shell invocation with untrusted input.

**TypeScript:** ESLint `strictTypeChecked`, `tsc` strict with
`noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`; validate every API
response with Zod; accessible components (semantic roles, labels, focus states).

**Database:** every schema change ships as an Alembic revision that upgrades and
downgrades cleanly; `alembic check` must pass.

## Pull request checklist

- [ ] Tests added/updated and passing (`make check`)
- [ ] Security implications considered (authz, input validation, data exposure)
- [ ] Documentation updated
- [ ] No secrets or real target data in code, fixtures or screenshots
