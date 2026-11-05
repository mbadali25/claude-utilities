# Can a running Claude Code session pick up a swapped login?

**Short answer: no, not on demand.** Nothing outside a running session can tell it to
re-read `.credentials.json`. A session *may* adopt a new login by itself, but only once
its own token has already stopped working. A swap leaves the old token valid, so the
session keeps using it. The "Needs reload" badge stays, and v1 ships a restart list.

Spike date 2026-11-05. Evidence from Claude Code **2.1.318** (`claude --version`),
binary `C:\Users\d3ade\.local\bin\claude.exe`, build sha `ca1fa9de`, plus the public docs.
The binary evidence is minified internal code, **not a documented contract** — re-check it
after a Claude Code update.

## What exists: the "sibling login" watch

2.1.318 does detect a credentials file rewritten underneath it. In `JT` (the per-host
credential cache):

- `lC()` stats `<config-dir>/.credentials.json`. If `mtimeMs` differs from the cached
  `lastCredentialsMtimeMs`, it clears the in-memory token and emits `credentialsChangedOnDisk`.
- A session subscribes to that event in `_startSiblingLoginWatch()` and calls
  `_adoptSiblingLogin()`, which re-reads the file and re-runs managed-settings load.
  Telemetry key: `auth_sibling_login_adopt`. Feature gate: `tengu_streamed_thimble`
  (default on).
- On a 401, `rC()`/`kta()` re-read the store and poll for a changed token for up to
  `CLAUDE_CODE_OAUTH_401_WAIT_MS`.

## Why it does not help a swap

`_adoptSiblingLogin()` is gated on `recheckAfterCredentialsChange()`, whose first line is:

```js
recheckAfterCredentialsChange = async (h) => {
  if (!this.showsLoginNotice()) return !1;   // <-- bails out here
  ...
}
showsLoginNotice() { return this.#e === "missing" || this.#e === "invalid"; }
```

So adoption runs **only when the session's own auth is already missing or invalid**. The
timer that drives the mtime check (`_scheduleSiblingLoginCheck` -> `Qmt` -> `lC`) carries the
same gate. A healthy session holding a still-valid token never re-reads the file.

A claude-swap swap replaces the `claudeAiOauth` block but does not revoke the old token, so
the session stays "valid" and keeps the old login until it restarts.

**Rejected option:** we could force adoption by invalidating the old token to provoke a 401.
claude-swap must not. The old token's lineage is shared with the host that now owns that
account, so breaking it breaks the other host.

## No external trigger of any kind

| Candidate | Result |
|---|---|
| Signal | `SIGHUP`/`SIGINT`/`SIGTERM` are all mapped to exit. No `SIGUSR1`/`SIGUSR2` handler (0 hits). |
| Control protocol | Subtypes include `reload_plugins`, `reload_skills`, `reload_output_styles`, `read_file`. **No credential or auth subtype.** It also rides the SDK's own stdio stream, so it reaches only sessions the SDK parented. |
| Agent SDK | `query.reloadPlugins()` / `reloadSkills()` act on the SDK-owned child only; no auth method in the TypeScript reference. |
| `messagingSocketPath` (in `~/.claude/sessions/<pid>.json`) | Carries peer/user messages into the conversation, not control commands. `/login` is interactive. |
| Hook / sentinel file / CLI subcommand / env var | None documented, none found. |
| `/login` with `CLAUDE_CODE_OAUTH_TOKEN` | Switches the running session, but must be typed by the user, and the env var outranks the stored login. |

## Consequence for claude-swap

Keep the "Needs reload" badge and ship a restart list: per needs-reload session, a copyable
`claude --resume <session-id>` (`--resume <session-id>` confirmed in `claude --help` on
2.1.318; `sessionId` in `~/.claude/sessions/<pid>.json` is the 36-char UUID that flag takes).
The session's `cwd` is already shown next to it, so the command carries no shell quoting.

The plan's Step 7 rule — "if S4 shows a re-read, the badge text becomes 'may need reload'" —
does **not** fire. The re-read is real but gated on an already-broken token, so for a swap the
session definitely needs a reload. Badge text stays "Needs reload".

## Not verified

- No live canary: no running session was swapped and observed. Findings are from reading the
  binary and the docs, not from watching a session adopt or refuse a login.
- Behaviour when the host uses the macOS Keychain or the v5 "backend" credential store
  (`probeCredentials`/`version` path) was read but not exercised.
- Whether `tengu_streamed_thimble` is on for every account.

## Sources

- Claude Code 2.1.318 binary strings: `JT`, `lC`, `Mm`, `_startSiblingLoginWatch`,
  `_adoptSiblingLogin`, `recheckAfterCredentialsChange`, `showsLoginNotice`.
- https://code.claude.com/docs/en/authentication (credential locations, `/login`, precedence,
  multi-account via `CLAUDE_CONFIG_DIR`)
- https://code.claude.com/docs/en/agent-sdk/typescript (no auth control request)
- https://code.claude.com/docs/en/changelog (no credential hot-reload entry, 2.1.304-2.1.318)
- Feature request: https://claudeissues.com/issue/32827 (programmatic `/reload-plugins`)
- Design doc: `docs/superpowers/specs/2026-11-04-claude-swap-design.md`, Decision 9 and
  "Research: automatic reload after a swap"
