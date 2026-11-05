---
name: steward
description: Repo-specific rules for driving a pull request in claude-utilities to green. Read before acting on a CI failure, review comment or merge conflict on a PR you opened or drive.
---

# Steward - claude-utilities

`CLAUDE.md` is the policy; this file holds only what the PR loop needs at the moment it acts.
Where they disagree, `CLAUDE.md` wins and this file is the bug. Cite a section or a path, never
a count.

## Before any push

- Run `bash _verify/cases/go-checks.sh` (build, vet, gofmt, tests); `.crew/verify.json` maps changed
  paths to suites. Say which ran and which did not.
- Never print or commit a token. A swap replaces only the `claudeAiOauth` block (`CLAUDE.md`, Landmine).
- Never force push. A new dependency or a change past roughly 10 files needs the owner first
  (`CLAUDE.md`, Scope discipline).

## Reading a red check

- This repo has no `.github` workflow yet; the checks are the local gate above and `_verify/smoke.sh`.
- "Not this PR's" needs the same failure on the base commit (`main`), same environment.
- `agents-md-drift` fails when `AGENTS.md` no longer matches `CLAUDE.md`, `.crew/verify.json`,
  `.crew/codemap/**` or `_verify/smoke.sh`; regenerate with the command in that rule's `why`.

## Conventions

- Branches are linear (no merge commits so far); rebase onto `origin/main` rather than merging it in.
- Unrelated problems go in `.work/FINDINGS.md`, not the diff.
- Promotion order and post-deploy proof: `CLAUDE.md`, Promotion.
