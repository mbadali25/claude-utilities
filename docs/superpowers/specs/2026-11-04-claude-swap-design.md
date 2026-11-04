# claude-swap design

Date: 2026-11-04. Status: draft for Matthew's approval. Not yet planned or built.

## Intent and why

Matthew runs Claude Code on several Windows and Linux machines and owns several Claude Ultra subscription accounts. Each account has 5-hour and weekly usage limits. When one account runs low, he wants to move a machine to another account without logging out and in by hand on every box.

claude-swap is a small web app on his own local network. It holds his accounts, shows how much usage each has left and when it resets, lists the machines and Claude sessions running, and swaps a machine's login on demand.

## Goals

- Log in to each of Matthew's Claude Ultra accounts from the app.
- Show per account: usage left (5-hour and weekly) and the reset date and time.
- Show every host that runs an agent, and the Claude sessions running on each.
- Swap the active account on a chosen host with one action.
- After a swap, mark that host's running sessions "needs reload" (see Decisions).
- Cheap to run, reliable, one repo, no cloud dependency.

## Non-goals

- No automatic swapping when an account nears its limit. Manual only for now. Leave room to add it later.
- No multi-user support, roles or per-user audit. One owner.
- No public exposure. The server is reachable on the LAN only.
- No support for macOS in version one.

## Anti-goals (failure even if it technically works)

- A swap that leaks a token: into logs, the UI, error messages, process arguments, or unencrypted transit beyond the LAN design below.
- A swap that corrupts a machine's login file or destroys data in it, including the `mcpOAuth` block.
- A swap that leaves a machine unable to log in, with no way back.
- A stored copy of an account's tokens that goes stale because another copy rotated them.

## Constraints

- LAN only. Windows and Linux hosts.
- Cheap and reliable. A single static Go binary per OS, no runtime to install on hosts.
- Agents must work behind host firewalls with no inbound ports.
- Go 1.27 is installed on Matthew's Windows machine. Linux builds are cross-compiled from it with `GOOS=linux go build`. WSL has no Go and does not need it.
- Claude Code's login on each host belongs to the host user, so the agent runs as that user.

## Decisions made by Matthew

1. **Transport:** each agent dials out to the server over a WebSocket. No inbound ports on any host. The agent authenticates with a token, sends heartbeats and reconnects on its own.
2. **Language and layout:** agent and server are both Go, in one repo (`claude-utilities`), sharing protocol types.
3. **Swap trigger:** manual only first. Auto-swap later.
4. **Swap method:** the agent writes the live `claudeAiOauth` block back to the server, then replaces only that block in the host's credentials file. Nothing else in the file changes.
5. **Usage source:** the server polls every account's usage itself, using the stored tokens.
6. **Scope:** only Matthew's own accounts. One owner.
7. **Storage at rest:** the server keeps account tokens in an encrypted file. The key comes from an environment variable at start. Losing the key means re-logging every account.
8. **Server UI sections:**
   - Accounts: log in to each account; usage left; reset date.
   - Hosts and sessions: every host with an agent, and its running Claude sessions.
   - Swap: choose an account for a host; the swap and the plugin reload happen together.
   - Pending connections (added by Decision 13): agents waiting for approval, with Allow and Deny per entry.
9. **Plugin reload:** version one marks each affected running session "needs reload" in the UI. Matthew presses `/reload-plugins` or restarts that session. A separate research item looks for a way to automate this (see Open items).
10. **Multi-machine accounts (decided by Matthew, builder check):** one account may be active on several machines at once. Each account has exactly one token owner: the server, or the machine that most recently swapped it in. Other machines using that account are marked "shared" and may need a re-swap if a refresh rotates the token. This replaces the stricter "one active host per account" reading of the hybrid ownership proposal below.
11. **Day-one hosts (decided by Matthew, builder check):** this Windows desktop (`dadeush-desktop`) and the Linux laptop. Each WSL install is its own host with its own `~/.claude`. Later: `dadeush-buntun` (Linux) and `dadeush-legion` (Windows).
12. **Log redaction is an allowlist (decided by Matthew, 2026-11-04).** The logger emits only allowlisted safe keys and withholds every other attribute. Allowlisted free-text values (message, reason, error) pass through `Redact` and are capped at 256 bytes. A denylist of known secret key names is not enough: a new field name would leak by default.
13. **"Who is trying to connect" approval menu (decided by Matthew, 2026-11-04).** An agent that dials the server with no valid token is not rejected silently. It appears in a **Pending connections** list in the web UI showing host name, OS, source IP, time, and a short fingerprint derived from its hello. The owner clicks **Allow** or **Deny** per entry. Allow issues a per-agent token, delivered over that same pending connection, and the host becomes enrolled. Deny closes the connection and suppresses that fingerprint for a period. This is the default enrolment path. The one-time code stays as an optional pre-approved path (Claude's call, see Builder-check resolutions).

## Builder-visible calls by Claude, not decided by Matthew

These are Claude's proposals. Matthew has not approved them.

1. **Hybrid token ownership.** Each account's tokens have exactly one owner at a time.
   - An idle account (not active on any host) is owned by the server. The server polls its usage and refreshes its tokens.
   - An active account is owned by the host using it. The agent reports that host's current tokens and usage to the server.
   - A swap hands ownership over: the agent writes its live block back to the server first, then the server's copy of the incoming account is written to the host.
   - Update: Matthew's Decision 10 refines this. An account can be active on several machines; its single token owner is the server or the machine that last swapped it in, and the other machines are marked "shared".
   - Why: Decision 5 has the server use stored refresh tokens. If a refresh token rotates on use, a server refresh would invalidate the copy a host is using, and a running Claude Code would also refresh its own token and diverge from the server's copy. One owner at a time avoids both.
   - Whether refresh tokens rotate on use was not confirmed in Claude's documentation. Treat rotation as likely.
2. **Login from the web UI via OAuth is unverified.** The plan is that the server runs the browser OAuth login for each account and stores the result. It is not confirmed that Claude Code's login can be driven from a web page rather than only from the CLI. Fallback: import the `claudeAiOauth` block from a machine that is already logged in to that account.
3. **Session discovery by scanning `claude` processes is unverified.** The plan is that the agent finds running `claude` processes and reports each one's working folder and session id. What an outside process can read from a live Claude process on each OS is untested.

## Verified facts

- Login file locations:
  - Windows: `%USERPROFILE%\.claude\.credentials.json`
  - Linux: `~/.claude/.credentials.json`, file mode 0600
  - WSL has its own separate `~/.claude`.
- Top-level keys in the file: `claudeAiOauth` and `mcpOAuth`.
- `claudeAiOauth` holds these keys: `accessToken`, `refreshToken`, `expiresAt`, `refreshTokenExpiresAt`, `scopes`, `subscriptionType`, `subscriptionTypeSource`, `rateLimitTier`.
- `mcpOAuth` holds one entry per MCP server. A swap must preserve it exactly.
- `CLAUDE_CONFIG_DIR` relocates the config directory, giving one account per directory.
- `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`, a one-year token) outranks the login file. Per the docs it can only make model requests.
- The docs list the default subscription login as the lowest-precedence auth method.
- Documented usage sources cover only the active session's account: `/usage` and the statusline JSON fields `rate_limits.five_hour` and `rate_limits.seven_day`, each with `used_percentage` and `resets_at`.

## Risks

- **Undocumented usage endpoint.** The only way to read usage for every account is `GET https://api.anthropic.com/api/oauth/usage` with the OAuth bearer token. It is undocumented, can change without notice, and can return HTTP 429. Back off on 429, show "last known" with a timestamp, and treat a schema change as a visible error, not a crash.
- **Anthropic's terms.** Anthropic's legal page says developers may not route requests through Free, Pro, Max or Ultra plan credentials on behalf of their users, or collect, store or intermediate Claude.ai credentials. This tool stores and uses subscription credentials. Personal, single-owner use of Matthew's own accounts is the lower-risk reading, because the wording targets third parties serving other users. Matthew accepts this risk knowingly. Do not add multi-user features without revisiting it.
- **Running sessions keep the old token in memory.** After a swap, a running Claude session may keep using its old login until it restarts. Whether a session re-reads the file was not confirmed. This is why Decision 9 uses a "needs reload" badge.
- **Token staleness.** If an account is refreshed by two parties, one copy breaks. The hybrid ownership call above exists to prevent this. If a crash leaves a copy one rotation behind, that account needs a fresh login. Machines marked "shared" (Decision 10) can go stale when the owner refreshes; they then need a re-swap.
- **Concentrated secret.** The server holds every account's login. Encryption at rest, LAN-only binding and an agent auth token are the minimum.
- **Pending-connection surface (Decision 13).** An unauthenticated agent can now open a connection and occupy a list entry. A LAN device could flood the queue, or impersonate a real host's name so the owner approves the wrong machine. The security calls under "Pending connections" below exist for this; the fingerprint match on the new agent's console is the control against impersonation.

## Left to the builder

- Package layout, protocol message shapes and versioning.
- Agent and server authentication details (per-agent token issued by Allow, optional TLS on the LAN) and where each secret lives.
- Fingerprint derivation from the hello (what it hashes, how many characters), as long as the agent can print the same value the UI shows.
- Encrypted file format and cipher choice, as long as the key comes from an environment variable.
- How the agent runs as a service: Windows service or scheduled task, systemd unit on Linux.
- Atomic write and rollback for the credentials file: write temp file, fsync, rename, keep a backup of the previous block, restore on failure. Preserve file mode 0600 on Linux.
- UI: plain HTML served by the Go binary is enough. No front-end framework is required.
- Polling cadence and back-off for the usage endpoint.

## Builder-check resolutions

### Decided by Matthew

- One account may be active on several machines at once. Each account has exactly one token owner: the server, or the machine that most recently swapped it in. Other machines using it are marked "shared" and may need a re-swap if a refresh rotates the token.
- Day-one hosts: this Windows desktop (`dadeush-desktop`) and the Linux laptop. Each WSL install is its own host (own `~/.claude`). Later: `dadeush-buntun` (Linux), `dadeush-legion` (Windows).

### Claude's call, not decided by Matthew

- **Agents and enrollment.** One agent per OS user per host. Default path is Decision 13: the agent dials with no token, lands in Pending connections, and the owner approves it. Optional pre-approved path (Claude's call, not decided by Matthew): the UI generates a one-time code (single use, 10 minutes); an agent that presents a valid code in its hello skips the queue and is enrolled at once. Either path yields a long-lived per-agent token, stored hashed on the server. The UI can revoke that token.
- **Pending connections, security calls (Claude's call, not decided by Matthew).** This is a LAN server holding login tokens, so the approval menu gets these controls:
  1. Viewing the pending list and clicking Allow or Deny require an authenticated admin session. Unauthenticated: HTTP 401.
  2. Allow and Deny are POSTs carrying a CSRF token. Wrong or missing token: HTTP 403, nothing changes.
  3. The queue is capped at 20 entries; a 21st hello is closed with a "queue full" reason. Each source IP may add at most 3 pending entries per 10 minutes; beyond that the connection is closed before it is listed.
  4. A pending entry expires after 10 minutes. An expired entry cannot be approved; the agent must dial again.
  5. A pending connection may send exactly one message, the hello. Any other message before approval drops the connection and removes the entry. A pending connection receives no account, host or session data: only Pending, Approved or Denied.
  6. The fingerprint is derived from the hello (host name, OS and a per-attempt agent nonce). The agent prints it on its console; the UI shows it next to the Allow button and asks the owner to match them before clicking. A LAN device spoofing a host name produces a different fingerprint. The nonce travels inside TLS.
  7. Deny closes the connection and suppresses that fingerprint for 1 hour: a re-dial with the same fingerprint is closed without being listed. A fresh nonce makes a fresh fingerprint, so a legitimate retry still works after the owner changes their mind.
  8. Every Allow and Deny writes one audit log line with allowlisted keys only (action, fingerprint, host name, OS, source IP, result). The issued token never appears in a log, in the UI or in an API response other than the single Approved message to the agent.
- **Spike first (Claude's call, not decided by Matthew).** Plan a spike before the build to verify the three unverified paths: web-UI OAuth login, refresh-token rotation behaviour, and process scanning. Fallback if web login fails: import an account from a machine already logged in; the agent uploads that machine's `claudeAiOauth` block.
- **Account identity (Claude's call, not decided by Matthew).** Use the account or email identifier from `~/.claude.json` (`oauthAccount`) if present, with the spike verifying it. Otherwise use a label the user chooses at import.
- **Swap states (Claude's call, not decided by Matthew).**
  - Unknown live account on a host: prompt to import it before swapping.
  - Agent offline: refuse the swap.
  - Live tokens expired: try a refresh; if that fails, fail the swap and restore the previous block (rollback).
  - Every swap writes a backup of the previous block first.
- **mcpOAuth (Claude's call, not decided by Matthew).** `mcpOAuth` is never swapped (already decided to preserve it). MCP logins may belong to a different account than the active one; document this in the UI and README.
- **v1 done (Claude's call, not decided by Matthew).** Accounts addable (web login or import); usage left and reset date shown per account; hosts and sessions listed; swap works on one Windows and one Linux host; "needs reload" badge per session; encrypted token file; LAN-only; a new agent enrols through the Pending connections panel with a fingerprint match (Decision 13), and Deny suppresses it; logs emit allowlisted keys only (Decision 12).

### Still open

- srl-lin's Linux findings are pending (see Open items).

## Research: automatic reload after a swap (2026-11-04)

Each finding is marked documented, community-reported or inference.

- **Credentials re-read mid-session (documented gap, inference).** The docs do not say whether a running session re-reads `~/.claude/.credentials.json`. They say only that an unrefreshable expired login fails requests with "Login expired - Please run /login". GitHub issue anthropics/claude-code#54443 asked about a re-read after a 401 and was closed as not planned. Inference: assume sessions hold the token in memory. Requirement for the builder: test with a canary session before relying on any re-read.
- **Triggering a reload from outside (documented gap, community-reported).** The docs describe no way to trigger `/reload-plugins` or a re-login from outside a running session: no hook, signal, file watcher or IPC. Feature request #32827 asks for a programmatic `/reload-plugins`. A community-reported SDK control request, `query.reloadPlugins()`, works only for sessions the SDK process itself owns (unverified).
- **How changes reach a running session (documented).** `/reload-plugins` (or a new session) is the only way settings and plugin changes reach a running session, except command-source plugins, which reload themselves.
- **Fresh processes (inference, documented).** A fresh process, including `claude --resume`, reads the current credentials, so a swapped file takes effect there (inference). `-p` cannot `/login`. `--bare` never reads OAuth (documented).
- **Consequence for v1.** After a swap the UI shows each running session on that host as "needs reload". The user runs `/reload-plugins` or restarts that session. Auto-reload options for later: restart the session with `--resume`, or an agent-owned wrapper (tmux or pty) that launches Claude so the agent can restart or drive it.

Sources:
- https://code.claude.com/docs/en/authentication
- https://code.claude.com/docs/en/plugins/loading.md
- https://code.claude.com/docs/en/headless.md
- https://github.com/anthropics/claude-code/issues/54443
- https://claudeissues.com/issue/32827-feature-allow-reload-plugins-to-be-invoked-programmatically-from-slash-commands

## Open items

- **Linux findings pending.** A question about how Linux hosts store and swap logins, read usage, and run a background agent under systemd was sent to Matthew's `srl-lin` session. Its reply has not arrived. The builder should check the Linux login path, file mode, swap behaviour and token rotation on a real Linux host before relying on the Windows findings.
- **Auto-reload research.** Desk research done; see "Research: automatic reload after a swap". Still open: canary-test whether a running session re-reads the credentials file, and whether `claude --resume` restarts a session safely. Until then the UI shows "needs reload".
- **Verify the three unverified calls above** (OAuth login from the web UI, token rotation on use, process scanning) with a short spike before committing to the design around them. The spike is planned first (Claude's call, not decided by Matthew); see "Builder-check resolutions".
