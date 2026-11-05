# Session control: asking a running session to do something

Backend reference for the session-control plumbing: what an operator can ask for, which mechanism
each command ends up using, what is honestly unsupported, how it fits the swap flow, and how to
install and remove the host-side hook.

**Read [session-reload.md](session-reload.md) first.** It establishes the constraint this whole
feature lives inside: nothing outside a running Claude Code session can make it re-read its
credentials. Session control does not change that. It gives the operator a way to *ask* for the
three things that help after a swap, and an honest answer when asking is not possible.

Spike evidence: Claude Code **2.1.318**, build sha `ca1fa9de`, read on 2026-11-05. The findings
come from reading the binary and the docs, not from a live two-account test. Re-check after a
Claude Code update.

## The three commands, the composite, and the scope

| Command | What it asks for |
|---|---|
| `reload_plugins` | Activate pending plugin changes in the session (`/reload-plugins`). |
| `remote_control_enable` | Bind a Remote Control bridge for the session. |
| `rename_remote` | Make the session carry a given remote-visible title. |
| `repair` | The composite: all three, in that order, per session. It takes no name; each session is named after its own name. |

Scope is a separate axis, so every command works at every scope:

| Scope | Targets |
|---|---|
| `session` | One session on one host. Needs `host` and `session`. |
| `host` | Every reported session on one host. Needs `host` and `confirm: true`. |
| `all` | Every reported session on every connected host. Needs `confirm: true`. |

`onlyNeedsReload: true` narrows any scope to the sessions a swap has left holding an old login.
**"Apply to all needs-reload sessions"** is therefore `{"command":"repair","scope":"all",
"onlyNeedsReload":true,"confirm":true}`.

`rename_remote` works at `session` scope only, where `name` is required. At `host` or `all` scope it
is refused outright (`ErrNameNotAllowed`, 400): one name would give every session the same title,
and no name would fail every target. Use `repair`, which derives each name from the session's own.

## Statuses

| Status | Means |
|---|---|
| `queued` | The hub has a target, or the agent has written the instruction, but nothing has reached the session yet. |
| `delivered` | The instruction reached the session. **It does not mean it ran.** |
| `done` | The command demonstrably ran. **No mechanism can claim this today.** Nothing in this build ever returns it. |
| `failed` | The attempt failed; the reason code says why. |
| `unsupported` | No proven mechanism can do this; the reason code says why, and the hint often carries the command an operator can run instead. |

Reason codes are short and machine-readable: `unsupported-requires-restart`,
`unsupported-inbox-unproven`, `no-mechanism`, `unknown-command`, `bad-session-id`, `no-name`,
`queue-full`, `queue-write-failed`, `agent-offline`, `timeout`, `bad-reply`.

## Mechanisms, and what each command actually uses

The agent holds a registry of mechanisms per command and tries them in order; the first result that
is not `unsupported` wins. A mechanism the spike has not proven reports `unsupported` rather than
claiming a success nobody can see.

| Command | Mechanism used | Best status it can reach |
|---|---|---|
| `reload_plugins` | `hook-queue` | `delivered` |
| `remote_control_enable` | `relaunch` | `unsupported` |
| `rename_remote` | `relaunch` | `unsupported` |
| any of the three, with the experimental flag on | `inbox` is tried first, declines, and the above still answers | unchanged |

### relaunch — reports the command, changes nothing

Remote Control cannot be enabled on a running session from outside by any public channel, and the
remote-visible title is **latched once when the bridge binds**: `/rename` does not re-latch it
(spike E). A relaunch is the only thing that sets both, so this mechanism returns
`unsupported` / `unsupported-requires-restart` plus the exact command for an operator to run:

```
claude --resume <sessionId> --remote-control <name>
```

`--resume <id>` and `--remote-control <name>` do combine: the spike's probe failed at session
lookup, not at argument parsing (spike A3). For the session to come back with Remote Control
already on by default, `remoteControlAtStartup: true` must be set at **user scope** — repo-scoped
settings cannot enable Remote Control (spike F).

The mechanism **never starts or stops a process.** Killing a session to relaunch it would throw
away whatever the operator was doing in it. It only reports the string.

Two safety details in that string:

- A session id that is not a 36-character UUID is never pasted into a command; the hint says to
  restart by hand instead.
- A name that would need shell quoting (a quote, a backslash, a shell metacharacter) is left out
  and the hint says to set the name in the session. Nothing in this program executes the string.

### hook-queue — writes an instruction, reaches `delivered`

The agent writes one instruction file per session under `<state dir>/commands/<sessionId>.json`,
owner-only (0600 in a 0700 directory, atomic replace), bounded (one pending instruction per command
per session, 16 entries per session, 64 sessions) and expiring after 24 hours. The installed hook
reads the file for its own session id, returns the instruction as `additionalContext`, and marks the
entry delivered. The agent reports that delivery in its next heartbeat report, and only drops the
notice once the report is on the wire, so a failed send repeats it rather than losing it.

**The ceiling is `delivered`, by design.** A hook's JSON output has no field that runs a command or
injects a user turn; `hookSpecificOutput.additionalContext` only puts text in front of the model
(spike G). So the hook *asks* the model to run `/reload-plugins`. It cannot make it happen, the
model may not comply, and nothing on the host can observe whether it did. Any claim of `done` here
would be a lie, which is why no code path produces one.

**Timing asymmetry worth knowing.** The hook is installed for two events:

- `UserPromptSubmit` fires in a session that is already running — which is exactly the session
  holding a stale login. This is the event that does the work, and it fires **when the human next
  types in that session.** An instruction can therefore sit unread for hours.
- `SessionStart` fires in a session that has just started, which is the session that needs the
  instruction least (a fresh session already picked up the new credentials). It is installed anyway
  so a resumed session picks up anything still queued.

### inbox — experimental, off by default, and unsupported even when on

The per-session message inbox is the one true outside channel the spike found: on Windows a named
pipe at `\\.\pipe\LOCAL\cc-msg-<32hex>`, named by `messagingSocketPath` in
`~/.claude/sessions/<pid>.json`, with the peer auth key published beside it as
`<pid>.<64hex>.key`. The module registers exactly the handlers this feature would want —
`onEnqueue`, `onRename`, `onEnableRemoteControl` — and the telemetry event
`uds_enable_remote_control` proves that enabling Remote Control over it is a real, instrumented
path (spike C).

It is still **unsupported**, and set `CLAUDESWAP_EXPERIMENTAL_INBOX=1` on the agent only changes
which mechanism is *tried first*; it still declines and the honest answer still comes back.

What is known: messages are JSON objects `{type, session_id?, ...}` with `type` one of `control`,
`user`, `notification`, `in_process_teammate`; a `session_id` mismatch is dropped with
`[uds-messaging] Dropping <type> message: session_id mismatch`. What is **not** known, and is the
TODO in `internal/agent/control.go`: the framing (length-prefixed or newline-delimited), which field
selects `onEnqueue` versus `onRename` versus `onEnableRemoteControl`, how the published key becomes
an authentication value, and whether the GrowthBook gate that silences the inbox
(`cross-session messaging gate off`) is even on for this account. The spike could not start a
sandbox session to send into, so the wire frame was never exercised.

Prove all of that against a session you own, with the key read from that session's own key file,
before this returns anything but `unsupported`. **Never guess a frame at a session holding somebody
else's work.**

## The API

### POST /api/sessions/command

Needs a signed-in admin session cookie and the session's CSRF token in `X-CSRF-Token`, like every
other POST. Rate limited to 30 requests per minute per source address. Unknown body fields are
rejected.

```json
{
  "command": "repair",
  "scope": "all",
  "host": "",
  "session": "",
  "name": "",
  "onlyNeedsReload": true,
  "confirm": true,
  "requestId": "idem-7"
}
```

`requestId` is an optional idempotency key (at most 64 characters): repeating a request with the
same key returns the first request's view instead of dispatching again. **It is not permanent.** A
key is forgotten with its request, 15 minutes after the request finished, so a retry after that
dispatches a fresh one. Mint a new key per operator action rather than reusing one.

`202 Accepted` with every target queued — the verdicts arrive asynchronously:

```json
{
  "id": "a1b2c3d4e5f60718",
  "command": "repair",
  "scope": "all",
  "createdAt": "2026-11-05T12:00:00Z",
  "counts": {"total": 3, "queued": 3, "delivered": 0, "done": 0, "failed": 0, "unsupported": 0},
  "targets": [
    {
      "id": "a1b2c3d4e5f60718-0-0",
      "hostId": "h-1",
      "sessionId": "1111...5555",
      "pid": 4321,
      "command": "reload_plugins",
      "status": "queued",
      "code": "",
      "mechanism": "",
      "hint": "",
      "createdAt": "2026-11-05T12:00:00Z",
      "updatedAt": "2026-11-05T12:00:00Z"
    }
  ]
}
```

Error statuses: `400` for an unknown command, a bad scope, a rename with no name or a rename with
one name for many sessions; `409` for a missing `confirm`, no matching session, too many matching
sessions, or an offline agent; `404` for an unknown host or session; `429` over the rate limit.

### Status: the existing poll

There is **no separate status endpoint.** Each session in `GET /api/hosts` carries the commands
recently aimed at it, oldest first, at most eight, under `commands` — the same object shape as a
target above minus `hostId`/`sessionId`/`pid`. The key is omitted when a session has none, so an
older reader sees the shape it expects.

A request's own record stays readable for 15 minutes; the hub keeps at most 64 requests and 256
targets per request, and a target with no verdict after 60 seconds becomes
`failed` / `timeout`.

## How this fits the swap flow

1. A swap replaces the `claudeAiOauth` block. Every session running at that moment is flagged
   **Needs reload** — it still holds the old login, and will until it restarts
   ([session-reload.md](session-reload.md)).
2. The operator asks for `repair` with `onlyNeedsReload: true`. Per stale session that queues one
   `reload_plugins` instruction and returns two honest `unsupported-requires-restart` answers with
   the relaunch command.
3. The relaunch command is the one that actually fixes the session: it comes back with the new
   login, with Remote Control bound and with its name latched. The queued `reload_plugins` is a
   convenience for a session the operator is not restarting yet.
4. The hub forgets a session's needs-reload flag when the session ends, so a relaunched session
   stops being listed.

A `rename_remote` on its own is worth asking for only to record the intent: it always comes back
`unsupported`, because the bridge title cannot be changed after bind.

## Installing and removing the hook

Installation is **explicit opt-in**: nothing installs it for you, and nothing else in this program
edits a user's `settings.json`.

```
agent hooks install      # adds one entry per event, prints the file it edited
agent hooks uninstall    # removes only this program's entries, prints how many went
```

What it touches, and what it does not:

- The file is `$CLAUDE_CONFIG_DIR/settings.json`, or `~/.claude/settings.json` when that is unset.
  Remote Control's own `remoteControlAtStartup` must be at user scope too, so this is the right
  file for both.
- It adds one entry under `SessionStart` and one under `UserPromptSubmit`, each running
  `"<agent path>" hook --tag claude-swap-session-control`. That tag inside the command string is
  the only marker; `uninstall` removes exactly the entries carrying it.
- Everything else in the file — other hooks, other events, `model`, `permissions`, keys this
  program has never heard of — is decoded, re-encoded and left alone.
- It is idempotent: running `install` three times leaves one entry per event.
- The previous file is kept as `settings.json.claudeswap-backup` before each edit.
- The rewrite also makes `settings.json` **owner-only** (0600, or an owner-only ACL on Windows),
  because it goes through the same private-write path as the agent's own state. That is a
  tightening, not a loosening, but it is a change: a tool that expected the file to be
  group-readable would stop reading it. The backup carries the old content, not the old mode.
- `uninstall` prunes an event list it empties and the `hooks` object if that empties, and a file
  with none of this program's entries is not rewritten at all.
- A `settings.json` that cannot be parsed is **refused**, not rewritten: a rewrite would lose
  settings.

`agent hook` is the hook itself. It reads the hook payload on stdin, always writes valid JSON and
always exits 0 — a hook that fails interrupts the user's session, and nothing it carries is worth
that.

Do not run `agent hooks install` against a real `~/.claude` while testing. The tests point
`CLAUDE_CONFIG_DIR` at a temporary directory for exactly that reason.

## Security notes

- **Authorisation.** `Hub.Command` authenticates nobody. The HTTP route is where the admin session
  and the CSRF token are checked, the same as every other control method on the hub.
- **Confirmation.** A command that reaches every session on a host, or every host, needs
  `confirm: true` in the body. The hub refuses it otherwise; this is not a UI-only guard.
- **What is never logged.** A session's name, its remote name, its cwd, and the operator-facing
  hint (which can carry both a session id and a name). The audit lines carry the command, the
  scope, the mechanism, the result, the reason code, counts, the opaque host id and the opaque
  session id — and nothing else. Every new field needed a key added to the `logx` allowlist; a key
  that is not on the list logs as `[dropped]`, and `logx.Allow` panics on a key that merely looks
  secret-bearing.
- **Agent text is not trusted.** A reply's code, mechanism and hint reach a browser, so the hub
  strips control characters, runs them through the redactor and caps them (64 bytes for a code, 400
  for a hint) before storing them. The UI must still write them with `textContent`.
- **Path safety.** A session id becomes a file name in the instruction queue, so it is matched
  against the UUID shape first; anything else is refused with `bad-session-id` and nothing is
  written. The queue refuses to write at all without a state dir, rather than landing a relative
  path in whatever directory the agent happens to be running in.
- **Bounds everywhere.** The queue bounds entries per session, sessions per host and entry age; a
  report carries at most 32 command statuses; the hub bounds targets per request, requests in
  history and targets remembered per session.
- **Wire compatibility.** `command_req` / `command_res` are additive and strictly
  request/response. An older agent ignores `command_req` and the target times out. A newer agent
  never sends `command_res` unsolicited, which matters because an older hub's dispatcher closes the
  connection on an unexpected frame; a delivery observed long after the reply rides in
  `Report.commands`, an additive field an older hub ignores.
- **Credentials.** Nothing in this path reads, writes or carries a credential block. A command
  never touches `.credentials.json`.

## Not verified

- No live canary. No running, logged-in session was asked to do any of this and watched. The
  statuses reflect what the mechanisms can honestly claim, not an observed outcome.
- Whether a hook's `additionalContext` reliably gets a model to run `/reload-plugins`. The
  instruction is delivered; compliance is the model's.
- Whether the installed hook entries fire exactly as expected in a real session. The entry shape,
  the marker, the backup and the idempotence are covered by tests; the firing is not.
- The inbox wire frame, end to end — see the mechanism section above.
- Whether rewriting `claudeAiOauth` under a session with an already-connected bridge tears the
  bridge down, keeps the old account's connection, or reconnects as the new account. Needs a
  logged-in two-account test.
