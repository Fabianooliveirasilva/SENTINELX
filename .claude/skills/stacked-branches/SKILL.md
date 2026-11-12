---
name: stacked-branches
description: Propagate a commit through SentinelX's stacked phase branches (feat/phase-N on top of feat/phase-N-1), push them, and check GitHub Actions results without the gh CLI. Use when fixing something on a lower phase, after a PR merges into main, or when asked about CI status of a phase branch.
---

# Stacked phase branches

Each phase lives on `feat/phase-<N>-<topic>`, branched from the previous phase. PRs merge into `main` in order.
A fix belongs on the **lowest** branch that contains the broken code, then flows upward by merge (never rebase pushed branches).

## 1. Find the chain

```bash
git fetch -q origin
git branch --list 'feat/phase-*' --format='%(refname:short)' | sort -t- -k2,2n
git branch --merged origin/main --list 'feat/phase-*'     # already merged: skip these
```

## 2. Fix on the lowest branch

```bash
git switch feat/phase-<low>-…
# edit, then verify only what you touched before committing:
uv run pytest <changed tests> -q && uv run ruff check . && uv run mypy <changed package>
git commit -m "fix(<area>): …"                            # Conventional Commits + attribution lines
```

## 3. Merge upward, one level at a time

For each next branch in order:

```bash
git switch feat/phase-<n+1>-…
git merge --no-edit feat/phase-<n>-…   # message style used here:
# "Merge feat/phase-<n>-… into feat/phase-<n+1>-… (<short reason>)"
```

- On conflict: resolve keeping the higher phase's behaviour plus the fix; run that branch's affected tests.
- Docs that list phase status (`README.md`, `docs/ROADMAP.md`, `docs/TESTING.md`) conflict often — keep the higher phase's text.
- After the last branch, run `make check` on the top branch (it contains everything).

## 4. Push

```bash
git push origin feat/phase-<a>-… feat/phase-<b>-… …       # all touched branches in one push
```

An `agent refused operation` warning from ssh is harmless if the push line shows `->`.

## 5. After a PR merges into main

Merge `origin/main` into the next phase branch, then continue upward as in step 3. If an untracked local
copy of a file now tracked on main (e.g. `CLAUDE.md`) blocks the merge, delete the local copy first.

## 6. Check CI (no gh CLI, public repo API)

CI runs on `pull_request` only, so a branch has no runs until its PR exists.

```bash
R=Fabianooliveirasilva/SENTINELX
curl -s "https://api.github.com/repos/$R/actions/runs?branch=<branch>&per_page=5" \
  | python3 -c 'import json,sys;[print(r["id"],r["name"],r["status"],r["conclusion"],r["head_sha"][:7]) for r in json.load(sys.stdin)["workflow_runs"]]'
curl -s "https://api.github.com/repos/$R/actions/runs/<run_id>/jobs" \
  | python3 -c 'import json,sys;[print(j["id"],j["name"],j["conclusion"]) for j in json.load(sys.stdin)["jobs"]]'
curl -s "https://api.github.com/repos/$R/check-runs/<job_id>/annotations"   # failure details
```

Job logs need admin auth — rely on annotations (`scripts/ci/annotate_failure.py` emits them for compose/Trivy).
Docker-only jobs (compose E2E, Trivy, image build) can only be confirmed here, never locally.

## Rules

- Never force-push, rebase or delete phase branches; never merge a higher phase into a lower one.
- The user opens PRs from `https://github.com/$R/pull/new/<branch>`; give them that link.
- Update the phase status memory after pushing.
