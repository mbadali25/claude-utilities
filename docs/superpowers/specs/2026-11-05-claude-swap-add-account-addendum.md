# claude-swap: "Add account" addendum (2026-11-05)

Status: draft for approval. Does not edit the approved design (2026-11-04). Extends Decision "import" with a guided sign-in.

## Decision (Matthew)

"Add account" in the web UI makes one agent host run Anthropic's own `claude auth login` in a throwaway `CLAUDE_CONFIG_DIR`. Matthew finishes the browser sign-in, pastes the one-time code back into the UI, and the resulting login enters the vault through the same rules as `/api/import` (claudeAiOauth block only, duplicate identity refused, importing host becomes owner). The live login on the host is never touched.

## Spike result (claude 2.1.318, Windows, stdin/stdout piped, no TTY)

Run: `claude auth login --claudeai`, `CLAUDE_CONFIG_DIR` = empty temp dir, 20 s, sign-in not completed.

- Options: `--claudeai` (default), `--console`, `--email <email>`, `--sso`.
- It tries to open a browser at once (a `BROWSER` stub script was invoked) and prints, on stdout only (stderr empty):
  - `Opening browser to sign in…`
  - `If the browser didn't open, visit: <URL>`, where the URL is wrapped in an OSC-8 hyperlink escape (`ESC ] 8 ; ; URL ... `), so the URL appears twice with control bytes around it.
  - `Paste code here if prompted > ` (no trailing newline).
- URL shape: `https://claude.com/cai/oauth/authorize?code=true&client_id=...&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback&scope=...&code_challenge=...&code_challenge_method=S256&state=...`. The redirect target is Anthropic's hosted page, which displays a code for the user to paste. So the flow does not depend on a localhost callback and works from a different machine than the browser.
- It ran without a TTY (it did not exit or error) and kept waiting until killed. It created `.claude.json` and `backups/` in the temp config dir.
- Not verified: that a code written to the piped stdin completes the login (needs a real sign-in); the file the CLI writes on success (`.credentials.json` on Windows/Linux is expected; macOS uses the Keychain and is out of scope); whether `BROWSER` unset opens a browser on each OS (on the agent host it should open one, which is acceptable only if the host has a user session; see Browser handling).
- The temp dir and process were removed after the spike.

Conclusion: headless relay is feasible. Fallback if the stdin paste proves not to work (verified only at T-12 step 1): the agent runs the child under a pseudo-terminal (ConPTY / pty), or the UI tells Matthew to run `claude auth login` on the host and then use the existing "Import" button.

## Flow

1. UI: Add account, pick host, enter label. `POST /api/accounts/add {host,label}` returns `202 {id}`.
2. Hub creates an `addJob` (id = 16 hex chars from crypto/rand), sends `login_start` to that host's agent.
3. Agent creates a fresh dir under its state dir (`<StateDir>/login-<id>`, mode 0700, `credfile.RestrictDir`), runs `claude auth login --claudeai` with `CLAUDE_CONFIG_DIR` set to it and stdin/stdout piped, reads stdout, strips ANSI/OSC sequences, extracts the first `https://` URL.
4. Agent validates the URL: scheme https, host exactly `claude.com` or `claude.ai`, path starts `/cai/oauth/authorize` or `/oauth/authorize`, length <= 4096. Anything else fails the job with `bad_url`.
5. Agent sends `login_url {url}`. Hub stores it on the job (state `awaiting_code`).
6. UI polls `GET /api/accounts/add/{id}`; when `awaiting_code`, it shows the URL as a link ("Open Anthropic sign-in") and a code field. Matthew signs in on any browser, copies the code from Anthropic's page, pastes it.
7. `POST /api/accounts/add/{id}/code {code}` -> hub sends `login_code {code}` -> agent writes `code + "\n"` to the child's stdin. Code is held in memory only, zeroed after the write.
8. CLI exits 0. Agent reads the block with `credfile.ReadBlock(<dir>/.credentials.json)` and the identity with `readIdentity(<dir>/.claude.json)`, sends `login_done {block, identity}` (or `login_done {err}`).
9. Hub validates with `oauthBlock`, refuses a stored identity (`ErrAlreadyStored`), stores `vault.Account` via `vault.Put` and does not call `reg.SwapIn`: ownership is not claimed, because the host's live login did not change. The account is stored unowned (free). State becomes `done` with the public account view.
10. Agent deletes the temp dir in every outcome (done, error, timeout, cancel, agent shutdown) and best-effort on startup (any `login-*` dir left by a crash).

## API

| Method and path | Auth | Request | Response |
|---|---|---|---|
| `POST /api/accounts/add` | session + CSRF | `{host,label}` | `202 {id}`; 400 bad label; 404 unknown host; 409 duplicate label, agent offline, or an add already running on that host |
| `GET /api/accounts/add/{id}` | session | none | `200 {state, url?, account?, error?}`; 404 unknown id |
| `POST /api/accounts/add/{id}/code` | session + CSRF | `{code}` | `200 {ok:true}`; 404 unknown id; 409 not awaiting a code; 400 empty or > 2048 chars |
| `POST /api/accounts/add/{id}/cancel` | session + CSRF | none | `200 {ok:true}` |

States: `starting`, `awaiting_code`, `finishing`, `done`, `failed`, `cancelled`. `url` is returned only in `awaiting_code`. The `account` view never carries the block. Routes sit behind the existing `apiGate` (401 without session) and `authPost` (403 without `X-CSRF-Token`); the GET needs only the session. `readJSON` (unknown fields refused, body capped) is reused.

## New agent messages (proto, Version stays 1)

Additive types; an old agent ignores unknown types (it logs at debug), and the hub treats a missing reply as a timeout, so no version bump.

| Type | Direction | Body | Secret fields |
|---|---|---|---|
| `login_start` | hub -> agent | `{label?}` (id in envelope) | none |
| `login_url` | agent -> hub | `{url}` | url is sensitive (carries `state`); mask in logs |
| `login_code` | hub -> agent | `{code}` | code |
| `login_done` | agent -> hub | `{block?, identity?, err?}` | block |
| `login_cancel` | hub -> agent | none | none |

All have non-empty envelope ID (the job id); `Decode` callers reject empty IDs, as for export/swap. `LoginURL`, `LoginCode`, `LoginDone` get `String`/`GoString`/`LogValue` that mask `url`, `code`, `block`, `identity`, `err` (redacted).

Because `hub.dispatch` today treats any unknown agent frame as a protocol violation, `login_url` and `login_done` must be added to its switch and routed to the job, not to `conn.deliver` waiters (these are unsolicited and outlive the 30 s `requestTimout`).

## Timeouts

- Agent: URL must appear within 15 s of start, else `no_url` (kills child).
- Whole job: 10 minutes from start (hub timer and agent timer); on expiry the child is killed, dir removed, state `failed: timed out`.
- After `login_code`, agent waits 60 s for the child to exit; non-zero or timeout is `login_failed`.
- Hub sweeps finished jobs 15 minutes after their end; the job map is bounded (max 8 live jobs).

## Concurrency

- One add per host at a time (409 otherwise); one add globally is simpler and sufficient for a single-owner tool, so the hub allows at most 1 live job in total.
- The job takes `host.swapMu` only for the final vault write, not for the sign-in wait, so swaps are not blocked for 10 minutes. The temp login never touches the live credentials path, so there is no race with a swap or import. Reuse of the duplicate check in `Import` is factored into one helper (SSOT).
- If the agent disconnects mid-job, the job fails with `agent offline`; the agent kills its child and removes the dir when its session ends.

## Admin session, CSRF

All four routes are inside the existing admin session. POST routes use `authPost`. The code and URL are never accepted or returned without a valid session. Responses carry the existing `Cache-Control: no-store` headers. The UI page does not put the URL or code in the query string, localStorage, or the document title.

## Logging allowlist

Allowed keys (existing): `action`, `result`, `reason`, `host`/`hostid`, `account` (opaque id), `durationms`, `err` (redacted), `component`. Fields: `action` is one of `login_start`, `login_url`, `login_code`, `login_done`, `login_cancel`, `login_cleanup`.

Never logged: the URL (contains `state`), the code, the block, tokens, the email/identity, the CLI's raw stdout/stderr (it may echo the URL or the code). Agent child output is parsed in memory and dropped; on failure the log carries only a fixed reason: `no_url`, `bad_url`, `child_exit`, `timeout`, `no_credentials`, `bad_block`. Do not add `url` or `code` to `logx.Allow` (the forbidden-key list also rejects `code`). Tests assert a captured log never contains a planted URL, code or block.

## Browser handling

The CLI opens a browser itself. On a headless or service-session host nothing opens, and the printed URL is the path (the CLI says so). On an interactive host a browser tab may open for the agent's user; this is harmless but may confuse. The agent sets `BROWSER` to an inert command for the child where possible so that only the UI shows the link. Not verified per OS.

## Error cases

| Case | Result |
|---|---|
| Unknown or revoked host | 404 `ErrUnknownHost` |
| Agent offline | 409 `ErrAgentOffline` |
| `claude` not on the agent's PATH | job `failed: claude CLI not found on host` |
| No URL within 15 s, or URL fails validation | `failed`, child killed |
| Wrong or expired code | CLI exits non-zero: `failed: sign-in rejected`; user starts again |
| Identity already stored | `failed` with `ErrAlreadyStored` text; nothing stored |
| Credentials file missing or has no `claudeAiOauth` after exit 0 | `failed: no_credentials` |
| Block carries `mcpOAuth` without `claudeAiOauth` | refused by `oauthBlock` |
| Server restart mid-job | job lost; agent times out its child in 10 min and removes the dir; startup sweep removes strays |
| Label empty, > 64 chars, or duplicate | 400 or 409 before anything starts |
| Second add while one is live | 409 |

## Risk

Anthropic's usage policy states that "sign-in to a Claude account must complete through Anthropic's own flow". This design keeps to that: the only sign-in is Anthropic's own `claude auth login` on a host, completed by the account owner in Anthropic's own browser page; claude-swap never sees a password, never implements OAuth, and only relays the CLI's printed URL and the one-time code the owner copies from Anthropic's page. Residual risks:

1. Relaying the URL and code through a third-party UI is a form of proxying; if Anthropic objects, fall back to "run `claude auth login` on the host, then Import".
2. The state/PKCE values in the URL and the code are short-lived secrets passing through the hub and the browser; mitigated by TLS, admin session, memory-only handling, and no logging.
3. Behaviour depends on the CLI's output format (OSC-8 wrapping, prompt text), which may change; URL extraction must be tolerant and fail closed.
4. Stdin paste in a non-TTY child is unverified (see spike).
5. Stored accounts from this path are unowned until swapped onto a host; the first swap's write-back behaviour is the existing one.
