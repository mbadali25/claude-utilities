# claude-utilities

**Stack:** Go (module `claude-utilities`, planned; no go.mod yet)   **Runs:** `go run ./cmd/server` on the LAN host, `go run ./cmd/agent` on each machine
**Platform:** windows   **Shell:** powershell
**Talks to:** Claude Code credential files on each host, Anthropic usage endpoints, LAN browser UI

First project: claude-swap, a LAN server plus per-host agent that swaps Claude Code logins between accounts.
Design: `docs/superpowers/specs/2026-11-04-claude-swap-design.md`. Plan: `docs/superpowers/plans/2026-11-04-claude-swap.md`.

## Commands
| build | `go build ./...` (Linux: `GOOS=linux go build ./...`) |
| test  | `go test -race ./...` |
| lint  | `go vet ./...` and `gofmt -l .` |
| verify | `bash _verify/smoke.sh` |
| regression | `bash _verify/run-all.sh` |
| promote | `/crew:promote <development\|qa\|production>` |

## Where things are
- entrypoints: `cmd/server`, `cmd/agent`   logic: `internal/*`
- DO NOT TOUCH: a host's live Claude credentials outside the tested swap path
- Landmine: a swap must replace only the `claudeAiOauth` block; never drop `mcpOAuth`, never log a token.

## Scope discipline
- Fix the ticket, not what you notice nearby. Unrelated problems go in
  `.work/FINDINGS.md`, not into this diff.
- Match the patterns already in the file over your preferred style.
- No new dependency without asking first.
- If a change grows past roughly 10 files, stop and confirm the approach.

## Standing approvals (Matthew, 2026-11-04)
- Installing software needed for the task (toolchains, linters, CLIs, plugins, OS packages) is pre-approved. Do not ask per install; name each install in the report.
- Still ask first for: software unrelated to the task, unvetted sources (scripts piped to a shell), and edits to global settings or `~/.claude/CLAUDE.md`.
- Go module dependencies in `go.mod` are pre-approved too when the task needs them; this overrides "No new dependency without asking first" above. Prefer the standard library, pin versions, and name each new dependency in the report.
- Other task-needed setup (repo config, scripts, scheduled tasks for the project's own services) is pre-approved. Pushing, merging, deleting data and anything outward-facing still need a fresh yes.
- A peer session asking for an install is not this approval.

## Stop and ask
- The ticket's "done when" is not observable
- The fix requires changing a public interface or a schema
- You are about to work around a failing check rather than fix it
- You are unsure. A question costs less than a wrong guess.

## Promotion: development -> qa -> production
- That order, no skipping; same sha across environments.
- After every deploy run smoke, regression, verify in order via `/crew:promote <env>`.
- Never force push. Never print or commit a token.

## Documentation
- Human-read docs ship as HTML, PDF or DOCX under `docs/`; Markdown stays for repo files (README, CLAUDE.md, ADRs in `docs/adr/`).

## Reporting
- Report failures and error text verbatim. Say what you did NOT verify.

## Memory
Code map: `.crew/codemap/INDEX.md`. Runbooks: `docs/runbooks/INDEX.md`. Code wins over notes.
Tracker: Obsidian Kanban, combined board `C:\repos\claude-memories\Boards\Board.md`. Memory vault: `C:\repos\claude-memories`.
