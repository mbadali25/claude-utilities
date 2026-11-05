# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Stack:** Go 1.27 (module `claude-utilities`; deps `golang.org/x/crypto`, `github.com/coder/websocket`)
**Platform:** windows   **Shell:** powershell (on this machine bash and Linux commands run in WSL)
**Talks to:** Claude Code credential files on each host, Anthropic usage endpoint, LAN browser UI

First project: claude-swap, a LAN server plus per-host agent that swaps Claude Code logins between accounts.
Design: `docs/superpowers/specs/2026-11-04-claude-swap-design.md`. Plan: `docs/superpowers/plans/2026-11-04-claude-swap.md`. Manual e2e: `docs/runbooks/claude-swap-e2e.md`.

## Commands
| build | `go build ./...`; cross-build `GOOS=linux go build ./...` and `GOOS=windows go build ./...` |
| test  | `go test -race -count=1 ./...` (CI sets `CGO_ENABLED=1`); one test: `go test -race -run TestName ./internal/hub` |
| lint  | `go vet ./...`, `gofmt -l .` (must print nothing), `golangci-lint run` (v2.15.0 in CI; config `.golangci.yml`, gosec on) |
| verify | `bash _verify/smoke.sh`, `bash _verify/run-all.sh`, `bash _verify/cases/go-checks.sh` (exit 77 = skipped, not passed) |
| server | set `CLAUDESWAP_KEY` (vault passphrase) and `CLAUDESWAP_ADMIN_PASSWORD`, then `go run ./cmd/server --listen host:port [--data-dir DIR]`. `--listen` has no default. Prints the TLS cert sha256 for `--pin`. |
| agent | `go run ./cmd/agent enrol --server https://host:port --pin SHA256HEX` (one-time code via `CLAUDESWAP_ENROL_CODE`, never a flag), then `agent run`; `agent install` registers start-at-login |
| promote | `/crew:promote <development\|qa\|production>` |

## Architecture
The server (`cmd/server`) is one TLS listener: `/ws` for agents, everything else is the admin UI. Agents (`cmd/agent`) dial out, so hosts open no inbound port. Read `internal/hub`, `internal/agent` and `internal/proto` together to follow a flow.
- `hub` owns agent connections, enrolment, host state and swap orchestration. Unknown agents land in Pending connections; an admin approves by matching the fingerprint, or enrols with a single-use code. Agents pin the server cert by sha256.
- `vault` keeps account login blocks in one encrypted file (argon2id + AES-256-GCM). `ownership` is in-memory state of who holds each account's authoritative tokens; the hub uses `sameLineage` (same refresh token) to tell a host's live login from a stored one.
- A swap: the agent validates, writes a journal, backs up, replaces only `claudeAiOauth` via `credfile`, reads back, and rolls back from the backup on failure. On start it settles any leftover journal. Swap write-back refreshes the vault copy.
- `usage` polls the Anthropic usage endpoint for stored accounts. There is no token refresh yet, so an expired token shows "unauthorized".
- `logx` is an allowlist logger: a field key not in `allowed` logs as `[dropped]`, groups are dropped, secret-looking text is redacted. It must not import `proto` (proto imports logx). Add the key to the allowlist when you add a log field.

## Where things are
- entrypoints: `cmd/server`, `cmd/agent`   logic: `internal/*`
- DO NOT TOUCH: a host's live Claude credentials outside the tested swap path
- Landmine: a swap must replace only the `claudeAiOauth` block; never drop `mcpOAuth`, never log a token or an identity (it can be an email).

## Gotchas
- The agent reads the signed-in identity from `~/.claude.json` `oauthAccount` (email, else account uuid), or `$CLAUDE_CONFIG_DIR/.claude.json`. Do not set `CLAUDE_CONFIG_DIR` for the default profile; set it only for a sandbox config dir.
- Keep `CLAUDESWAP_STATE_DIR` and `CLAUDE_CONFIG_DIR` identical at `enrol` and `run`; the logon task passes no environment, so a state dir set only at enrol makes `run` report a missing `agent.json` (see `agent-run.log`).
- Import dedupes by the identity string: a login already stored is refused (`ErrAlreadyStored`), and a host with no `oauthAccount` cannot import.
- Windows Defender may flag unsigned Go test binaries; a vanished or blocked `*.test.exe` is that, not a test failure.
- Session discovery is implemented for Windows only (`~/.claude/sessions/<pid>.json`); the Linux scan is not.

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

## Working style (Matthew, 2026-11-05)
- Every task runs as its own background subagent. Dispatch independent tasks together in one message so they run in parallel.
- Main stays free for Matthew: it coordinates, decides and relays. It does not run hands-on work or wait on workers.
- Each agent brief is self-contained: goal, constraints, return format.
- Sub-agents sit under a manager, not under main. Main only talks to Matthew and dispatches one background manager agent; the manager spawns one sub-agent per task (own worktree where tasks share files), collects results, merges locally and runs the gate.
- Main's turns stay short. After any interruption, resume all cancelled work through the manager without being asked.

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
