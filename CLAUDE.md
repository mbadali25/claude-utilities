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
| set-password | `go run ./cmd/server set-password [--data-dir DIR]` — prompt (no echo at a TTY) or one line of stdin, never a flag. Writes an argon2id hash to `<data-dir>/admin-password.json`, which then wins over `CLAUDESWAP_ADMIN_PASSWORD`. |
| agent | `go run ./cmd/agent enrol --server https://host:port --pin SHA256HEX` (one-time code via `CLAUDESWAP_ENROL_CODE`, never a flag), then `agent run`; `agent install` registers start-at-login |
| promote | `/crew:promote <development\|qa\|production>` |

## Architecture
The server (`cmd/server`) is one TLS listener: `/ws` for agents, everything else is the admin UI. Agents (`cmd/agent`) dial out, so hosts open no inbound port. Read `internal/hub`, `internal/agent` and `internal/proto` together to follow a flow.
- `hub` owns agent connections, enrolment, host state and swap orchestration. Unknown agents land in Pending connections; an admin approves by matching the fingerprint, or enrols with a single-use code. Agents pin the server cert by sha256.
- `vault` keeps account login blocks in one encrypted file (argon2id + AES-256-GCM). `ownership` is in-memory state of who holds each account's authoritative tokens; the hub uses `sameLineage` (same refresh token) to tell a host's live login from a stored one.
- A swap: the agent validates, writes a journal, backs up, replaces only `claudeAiOauth` via `credfile`, reads back, and rolls back from the backup on failure. On start it settles any leftover journal. Swap write-back refreshes the vault copy. One account may be swapped onto any number of hosts (Matthew, 2026-11-06: he uses one account on several systems at once; that sharing a refresh-token lineage logs other hosts out is unproven, not observed): there is no held-elsewhere refusal and no holder or stale-copy swap warning. Only the Active (latest) holder writes back or is adopted, and only when its lineage matches the stored login; a login that matches another stored account is never adopted into this one. The one swap refusal left is "sign in again first" for a rejected stored login.
- Session control: `POST /api/sessions/command` fans one request out to sessions (`internal/hub/control.go`), and the agent decides HOW through a mechanism registry per command (`internal/agent/control.go`). Nothing claims a success it cannot see: `remote_control_enable` returns `unsupported-requires-restart` plus the relaunch command (the inbox has no action for it — `no-mechanism`), `reload_plugins` reaches `delivered` through an opt-in hook and the inbox is never registered for it, and `rename_remote` goes through the inbox when `CLAUDESWAP_EXPERIMENTAL_INBOX=1` (off by default) with relaunch as the fallback for a session with no bridge bound. The rename ceiling is `delivered`, never `done`: the bridge title push is fire-and-forget. The UI calls `reload_plugins` a Nudge ("Delivered (asked, unverified)", with the manual `/reload-plugins` line) and shows a per-host hook-installed indicator (`Report.hookInstalled`, tri-state). `relaunch_remote` is the ONE command that stops a process: session scope, `confirm`, idle-only (hub and agent both check), pid and session id re-verified, `claude` found before the kill, exec args only; it stays `unsupported-requires-restart` until a read-back sees a new `bridgeSessionId`, then `done`/`relaunched`. Tests inject kill/start and never touch a real process; whether resume re-enables the bridge is unproven. See `docs/runbooks/session-control.md`.
- `usage` polls the Anthropic usage endpoint for stored accounts, one account at a time: 25 s global spacing, tiers (active 2 min for held, just-swapped or watched accounts; idle 20 min; backoff capped at 1 h and honouring Retry-After), constants in `usage.DefaultConfig`. A failed poll keeps the last numbers (the page shows "Stale since"). Token refresh is off by default: with `--refresh-tokens --refresh-accounts id1,id2` the server refreshes an expired login through `usage.OAuthRefresher` (POST to `platform.claude.com/v1/oauth/token`; client id `usage.DefaultClientID` is provisional, pending confirmation), only for accounts in the `--refresh-accounts` allowlist (none listed = nothing, fail closed) that also pass `reg.OwnerOf(id).Server` (ownership is in-memory and empty after a restart, so that check is true for every account until a swap or import in the process; the allowlist is the real scope control; effect on other hosts: not observed; unproven), persisting via `vault.ReplaceBlock`, with no retry beyond the 1 h unauthorized backoff. Without the flag an expired token shows "unauthorized". A 401/403 poll failure logs `body_class` (fixed enum from `usage.classifyBody`, markers assumed, never body text). Each refresh logs `action=refresh result=ok|failed`; a failure adds `status_class` (fixed enum from the token call's HTTP status, `usage.StatusClass`).
- `logx` is an allowlist logger: a field key not in `allowed` logs as `[dropped]`, groups are dropped, secret-looking text is redacted. It must not import `proto` (proto imports logx). Add the key to the allowlist when you add a log field.

## Where things are
- entrypoints: `cmd/server`, `cmd/agent`   logic: `internal/*`
- DO NOT TOUCH: a host's live Claude credentials outside the tested swap path
- Landmine: a swap must replace only the `claudeAiOauth` block; never drop `mcpOAuth`, never log a token or an identity (it can be an email).

## Gotchas
- `agent hooks install` bakes `--state-dir` into the hook command because Claude runs hooks without the unit's `CLAUDESWAP_STATE_DIR`. Install from the unit's environment and re-run after upgrading; an old entry without the flag reads the default dir and silently returns `{}`.
- The agent reads the signed-in identity from `~/.claude.json` `oauthAccount` (email, else account uuid), or `$CLAUDE_CONFIG_DIR/.claude.json`. Do not set `CLAUDE_CONFIG_DIR` for the default profile; set it only for a sandbox config dir.
- Keep `CLAUDESWAP_STATE_DIR` and `CLAUDE_CONFIG_DIR` identical at `enrol` and `run`; the logon task passes no environment, so a state dir set only at enrol makes `run` report a missing `agent.json` (see `agent-run.log`).
- Import dedupes by the identity string: a login already stored is refused (`ErrAlreadyStored`), and a host with no `oauthAccount` cannot import.
- Windows Defender may flag unsigned Go test binaries; a vanished or blocked `*.test.exe` is that, not a test failure.
- Session discovery reads `~/.claude/sessions/<pid>.json` on Windows and Linux. Linux liveness comes from `/proc/<pid>/stat` plus a claude marker in `comm` or `cmdline`; the Linux `procStart` format is unverified, so a value that is not a decimal clock-tick count is ignored rather than treated as dead. Other platforms return `ErrNotImplemented`.

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
- Agent calls: always run_in_background:true; never block the main turn.
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
