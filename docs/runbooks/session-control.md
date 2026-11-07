# Session control: asking a running session to do something

Backend reference for the session-control plumbing: what an operator can ask for, which mechanism
each command ends up using, what is honestly unsupported, how it fits the swap flow, and how to
install and remove the host-side hook.

**Read [session-reload.md](session-reload.md) first.** It establishes the constraint this whole
feature lives inside: nothing outside a running Claude Code session can make it re-read its
credentials. Session control does not change that. It gives the operator a way to *ask* for the
three things that help after a swap, and an honest answer when asking is not possible.

Spike evidence: Claude Code **2.1.318**, build sha `ca1fa9de`, read on 2026-11-05. Spike 1 read the
binary and the docs. Spike 2 read the bundle again **and drove frames into a throwaway session it
started itself**, which corrected three things spike 1 had inferred — see
[What spike 2 corrected](#what-spike-2-corrected). Nothing was ever sent into a session holding
somebody's work. Re-check after a Claude Code update: every offset and every claim below is
specific to this build.

## The three commands, the composite, and the scope

| Command | What it asks for |
|---|---|
| `reload_plugins` | Activate pending plugin changes in the session (`/reload-plugins`). |
| `remote_control_enable` | Bind a Remote Control bridge for the session. |
| `rename_remote` | Make the session carry a given remote-visible title. |
| `restart_sessions` | Ask for the restart that actually fixes a stale session. **Copy-only: it stops nothing.** See [The restart action](#the-restart-action-copy-only-by-decision). |
| `relaunch_remote` | **Kills one idle session's process and starts `claude --resume <id> --remote-control` in its cwd.** The only command that stops anything. See [relaunch_remote](#relaunch_remote-the-one-command-that-stops-a-process). |
| `repair` | The composite: `reload_plugins`, `remote_control_enable`, `rename_remote`, in that order, per session. It takes no name; each session is named after its own name. It never expands to `restart_sessions`. |

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

`restart_sessions` needs `confirm: true` at **every** scope, `session` included — the one command
where the scope rule above is not enough, because the confirm is what proves the operator was shown
which sessions are named. `proto.IsRestartCommand` is the predicate the hub tests, so a second
restart-type command cannot be added without every confirm gate picking it up.

## What the nudge is, and what it is not

`reload_plugins` is shown in the UI as **"Nudge: ask session to reload plugins"** per session and
**"Nudge all sessions on this host to reload plugins"** per host (the protocol value is still `reload_plugins`). It writes an instruction the hook later
puts in front of the model, so the best it can reach is `delivered`, shown as **"Delivered (asked,
unverified)"**. The UI also shows the line that does it for certain: type `/reload-plugins` in
that session.

The host card carries a **hook installed?** indicator (`Hook installed` / `Hook not installed` /
`Hook state unknown`). The agent reports one boolean in `Report.hookInstalled`: true only when this
program's entries (the `claude-swap-session-control` tag) exist under **both** `SessionStart` and
`UserPromptSubmit` in the host's `settings.json`. It is a pointer on the wire: an older agent, or a
settings file that cannot be read or parsed, is omitted and reads as *unknown*, never as *not
installed*. No path or setting value rides in the report. With the hook not installed, a nudge is
queued and nothing reads it.

## Statuses

| Status | Means |
|---|---|
| `queued` | The hub has a target, or the agent has written the instruction, but nothing has reached the session yet. |
| `delivered` | The instruction reached the session. **It does not mean it ran.** |
| `done` | The command demonstrably ran. **No mechanism can claim this today.** Nothing in this build ever returns it. |
| `failed` | The attempt failed; the reason code says why. |
| `unsupported` | No proven mechanism can do this; the reason code says why, and the hint often carries the command an operator can run instead. |

Reason codes are short and machine-readable: `unsupported-requires-restart`,
`unsupported-no-bridge`, `unsupported-no-inbox`, `unsupported-inbox-no-change`,
`inbox-send-failed`, `no-mechanism`, `unknown-command`, `bad-session-id`, `no-name`, `queue-full`,
`queue-write-failed`, `agent-offline`, `timeout`, `bad-reply`; and for `relaunch_remote`:
`relaunched` (the only success code), `not-idle`, `session-gone`, `bad-cwd`, `no-claude`,
`kill-failed`, `start-failed`.

`unsupported-inbox-unproven` is **gone.** The frame is no longer unproven, so a code that said so
would be a lie in the other direction; what used to answer with it now answers `no-mechanism`
(`remote_control_enable`) or one of the three specific inbox codes (`rename_remote`).

## Mechanisms, and what each command actually uses

The agent holds a registry of mechanisms per command and tries them in order; the first result that
is not `unsupported` wins. A mechanism the spike has not proven reports `unsupported` rather than
claiming a success nobody can see.

| Command | Mechanism used | Best status it can reach |
|---|---|---|
| `reload_plugins` | `hook-queue`, and **nothing else is registered for it** | `delivered` |
| `remote_control_enable` | `relaunch` (`inbox` first when the flag is on, declining `no-mechanism`) | `unsupported` |
| `rename_remote`, flag **off** | `relaunch` | `unsupported` |
| `rename_remote`, flag **on** | `inbox`, with `relaunch` behind it as the fallback | `delivered` |
| `restart_sessions` | `relaunch`, and **nothing else is registered for it** | `unsupported` |

Two registrations are deliberate absences, and both are load-bearing:

- The inbox is **not** registered for `reload_plugins`, flag or no flag. Its user-message path
  sets `skipSlashCommands`, so `/reload-plugins` arrives as literal text: it adds a visible user
  turn to somebody's conversation and costs an API call without running the command. That is
  strictly worse than `hook-queue`, which at least asks for the right thing at no cost. Proven
  live: injecting `{"type":"user","message":{"content":"/reload-plugins"}}` logged
  `Routed user message to queue (priority=now): /reload-plugins` and then attempted an API
  request, with no `local_command_run` and no command executed.
- The inbox is **not** registered for `restart_sessions`. Its whole accepted surface is a rename
  plus six notification actions, none of which stops a session, and offering it would imply a kill
  path that does not and must not exist.

### relaunch — reports the command, changes nothing

Remote Control cannot be enabled on a running session from outside by any public channel, and a
session with **no bridge bound** has nothing a rename could push a title to. A relaunch is the only
thing that fixes either, so this mechanism returns
`unsupported` / `unsupported-requires-restart` plus the exact command for an operator to run:

```
claude --resume <sessionId> --remote-control <name>
```

`--resume <id>` and `--remote-control <name>` do combine (spike A3). Spike 2 ran the resume half
offline against its own throwaway and confirmed two things: the **session id is preserved
identically** across `--resume`, and `/rename` on a resumed session costs **no API call**
(`num_turns: 0`, `duration_api_ms: 0`, 58 ms). For the session to come back with Remote Control
already on by default, `remoteControlAtStartup: true` must be set at **user scope** — repo-scoped
settings cannot enable Remote Control (spike F).

**For `rename_remote` this is the FALLBACK, not the mechanism.** It answers when no bridge is
bound, and when the inbox flag is off. See [inbox](#inbox--the-rename-mechanism-off-by-default).

The mechanism **never starts or stops a process.** Killing a session to relaunch it would throw
away whatever the operator was doing in it. It only reports the string.

What a relaunch costs the person in that terminal is not the transcript — `--resume` reloads it —
but the **live** process state: scrollback, anything queued or mid-turn, in-session `/add-dir` and
permission-mode changes, and running subagents. That is why it is the last resort for a rename and
not the first.

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

### inbox — the rename mechanism, off by default

The per-session message inbox is the one channel from outside that reaches a **running** session:
on Windows a named pipe at `\\.\pipe\LOCAL\cc-msg-<32hex>`, off Windows a unix socket, in both
cases named by `messagingSocketPath` in `~/.claude/sessions/<pid>.json`, with the peer auth key
published beside it as `<pid>.<64hex>.key`.

It is **off unless `CLAUDESWAP_EXPERIMENTAL_INBOX=1` is set on the agent**, and it is off on every
host today — Matthew has not enabled it. With the flag off, nothing in this program connects to a
session's socket at all. With the flag on it is **real, not a stub**, and it does exactly one
thing: rename.

#### The wire protocol

```
connect  \\.\pipe\LOCAL\cc-msg-<32hex>
send     {"type":"auth","token":"<peerToken>"}\n
send     {"type":"control","session_id":"<that session's OWN id>","action":"rename","name":"<name>"}\n
close
```

Every part of that is load-bearing:

- **NDJSON.** One JSON object per line, `\n`-terminated, no length prefix. A line over the
  server's limit drops the connection.
- **The auth line is first, and is mandatory on Windows** (the server takes `requireAuth` from the
  platform: `authRequired = requireAuth ?? platform==windows`). On Linux, send the auth frame
  whenever a key file exists; nothing is verified on Linux, and only `entrypoint=cli` sessions
  register the rename handler (`sdk-cli` does not), so attempt and report rather than refusing. A control line on an unauthenticated connection is dropped and the connection closed:
  `Dropped a 'control' line from a connection that did not authenticate; closing it`. A wrong
  token gets `Dropped a bad auth frame…`, so the token is genuinely checked.
- **The token is the `peerToken`** in that session's **own** `<pid>.<64hex>.key` file, a 32
  lowercase-hex value. `childToken` is never written to disk. The key file is 0400 and bounded at
  4096 bytes.
- **A connection that sends no complete line within 30 s is closed** (`firstLineDeadlineMs`), so
  both lines go out in one write and the connection is closed immediately after.
- **`session_id` is ALWAYS set.** The server drops a frame whose `session_id` is not its own
  (`Dropping control message: session_id mismatch (got …, expected …)`). That drop is the
  interlock this whole feature leans on: a misdirected frame is a logged no-op in somebody else's
  session rather than a rename of it. This agent additionally refuses to send at all unless the
  session file's own `sessionId` is the one the hub asked about — the interlock is the net, not the
  plan.

Claude Code documents the shape itself. A session's own debug log prints, at inbox start:
`[uds-messaging] Inject messages (auth line REQUIRED here; a pipe is not reachable via
socat/AF_UNIX): node -e "…{type:'auth',token:…}+'\n'+…"`. The recipe above is the vendor's, not
an inference.

#### Why a rename reaches claude.ai at all

Every non-`auto` rename runs `Jvn`, and `Jvn` ends in `gJo`, which ends in
`bridge.titleWriter.update(bridgeSessionId, name, …)` — a host-to-bridge title push, with no
restart and no re-bind. The inbox's `onRename` handler calls
`Jvn(name, "peer", storage, /*userInitiated*/ false, false, credentials)`, so a rename frame lands
in exactly that path.

The only thing that stops the push is the `Tk` gate, and every disjunct of `Tk` is a
**transcript/history-suppression** condition: a conversation foreign to the bound bridge session, a
`noHistoryBackfill` session, a precautionary-suppression sid, a known-tainted sid. **None of them
is "a bridge is bound."** The one to watch is `noHistoryBackfill`, which is set for
remote-created sessions: a session **created from claude.ai** may be suppressed where one started
in a terminal and later bridged is not. That is in [Not verified](#not-verified).

**Verified live on 2.1.318 by the owner:** a bridge-bound session bound as one title was read back
on claude.ai/code under the new title after one inbox rename frame. The host cannot observe the
effect (fire-and-forget push), so the code ceiling stays `delivered`.

**Test-harness tip.** An interactive `claude --remote-control` in a fresh directory stops on the
workspace-trust dialog (skipped only in non-interactive mode). `claude --bg --remote-control <name>`
avoids it and still registers `entrypoint=cli`, the app class that registers the rename handler. It
is the reproducible way to stand up a test session.

#### The ceiling is `delivered`, and that is not going to change

The push is `…titleWriter.update(…).catch(()=>{})`. **The result is discarded.** Nothing on the
host can see whether the title on claude.ai changed, and the authoritative remote title can only
be read with the account's own token against a claude.ai endpoint, which is out of scope. So:

> **No code path returns `done` for `rename_remote`.** `internal/agent/inbox.go` says so in a
> comment and `TestInboxRenameNeverClaimsDone` holds it. The mechanism changed; the ceiling
> did not.

#### Verification: read `name`, and only `name`

After the frame goes out, the agent re-reads the session file's **`name`** for a bounded 500 ms. A
changed `name` proves the handler ran — the local half. The remote half is unobservable, so the UI
says the ask reached the session and never that the remote name is fixed.

> **The pass condition is `name`; `nameSource` is never required.** A live 2.1.318 session read
> back `name="..." nameSource="peer"` after an inbox rename (spike evidence 7.3), so `"peer"` may be
> asserted as a secondary signal. Its absence is not a failure, and a `"collision"` can rewrite it.
> `TestInboxRenameVerifiesTheNameAndNeverWaitsForPeerNameSource` holds this for `peer`, `user`,
> `collision` and empty. A collision takes a uniquifying suffix, so a name that *starts with* the
> one asked for counts as taken.

**The name must have *changed*, not merely match.** The prefix tolerance above is for a collision
suffix taken *during* the send. A session already sitting at `alpha-2`, asked for `alpha`, would
otherwise read as an instant success for a rename that never happened — a false `delivered`, which
is the one failure this mechanism is not allowed to have. So the read-back compares against the
name the session had *before* the frame went out, and the pre-send comparison is exact:
`alphabet` is not `alpha`. `TestInboxRenameNeverReadsAPreExistingNameAsSuccess` and
`TestTookTheNameRequiresAChange` hold it.

#### A name the session already has is the one case the inbox cannot help with

If the session's local name is already the name asked for, the inbox **declines to the relaunch**
rather than reporting `delivered`. This is a deliberate decision, not a shortcut.

Claude Code's rename handler is `if (!N || N === jle()) return;` — it returns on a name it already
has **before** reaching `Jvn`, so **no bridge push happens at all**. And that is precisely the state
in which a stale title on claude.ai can only be refreshed by a relaunch: the operator pressed "Fix
name" *because* the remote title is wrong, and the local name already matching is exactly why the
cheap fix cannot reach it. Reporting `delivered` there would show a success chip and send the
operator away from the only mechanism that would work. The decline carries the relaunch command.

If `name` did not change, the agent declines (`unsupported-inbox-no-change`) and the relaunch
fallback answers. It does not retry, and it does not claim anything.

**Why the window is 400 ms and not longer.** The agent handles hub frames **serially** on one
connection, so a slow mechanism does not merely delay its own reply — it holds up every later
target and the heartbeat behind it. One request fans out to at most 256 targets and the whole burst
has 60 s, so a `repair` caps at about 85 renames; at 400 ms each that is a ~34 s tail, inside the
deadline with room for the other 170 targets. The full window is only paid when the rename
**failed**: the loop reads before it sleeps, polls every 25 ms, and a rename frame is processed
immediately rather than behind the session's queued messages, so a rename that works normally costs
one read and no wait. `TestInboxVerifyBudgetIsBoundedAndCostsNothingOnSuccess` holds both halves. If
the fan-out bound ever grows, this arithmetic is what has to be redone.

#### A key file does not prove a live session

A **cleanly exited** session unlinks its own socket and key file. A session **killed** with
`taskkill /F` leaves its `<pid>.<64hex>.key` behind, orphaned, for a pid that no longer exists —
and pids get reused. Dialling on the strength of the file existing would eventually mean dialling a
pipe whose name has been handed to a different session.

Claude Code models this itself: its own lookup takes `requireLiveOwner` and answers `dead-owner`
when the owning pid is gone or its `procStart` no longer matches, and it sweeps stale key files.
The agent does the same check **before it connects to anything**:

- the pid must be a live session process whose recorded start time matches, via the same
  `sessions.Alive` gate the host report already keeps a session on;
- the key's own `procStartFt` (and `procStart`, when present) must match that live pid too — this
  is the check that catches the orphan;
- the key's `pidDomain` must agree with the session file's when both carry one, since the same
  process wrote both.

This host's own pid domain is **not** reconstructed: its format (`win32:<hostname>`) would be a
guess, and a guessed check is worse than a stated gap. `TestInboxRenameRefusesADeadOwnerWithoutDialling`
asserts every one of these refuses *without dialling*.

#### What the inbox cannot do — proven absent, not merely unproven

- **It cannot enable Remote Control.** `onEnableRemoteControl` is **dead code**: its setter has
  exactly one occurrence in the whole binary — its own definition — and the dispatcher never reads
  the field. Live, `action:"enable_remote_control"` logs
  `[uds-messaging] Unhandled control action: enable_remote_control`. The
  `uds_enable_remote_control` telemetry string exists in the binary **with no reachable call
  site**, so spike 1's inference from it ("enabling RC over this socket is a real, instrumented
  path") does not hold for 2.1.318 and has been removed from this runbook. The inbox answers
  `no-mechanism`, and `relaunch` behind it still gives the operator the command that works.
- **It cannot run a slash command.** See the deliberate absence under
  [Mechanisms](#mechanisms-and-what-each-command-actually-uses).
- **It cannot stop a session.** Nothing can; see
  [The restart action](#the-restart-action-copy-only-by-decision).

#### Transport: no dependency was added

A Windows named pipe is not reachable through `net.Dial`, and this program takes **no dependency**
to reach one — `go-winio` was considered and not added. It is not needed: a pipe client is opened
with `CreateFile` exactly as a file is, and `os.OpenFile` *is* `CreateFile`. Verified by hand on
2026-11-05 on go1.27.3 windows/amd64 against a real named-pipe server: open, both NDJSON lines in
one write, close, and the server read both lines intact.

There is **no unit test for `dialInbox` on Windows**, because what the standard library lacks is
the ability to *serve* a named pipe, not to dial one. What is tested instead:

- the path shape, exhaustively — `dialInbox` matches the whole path against
  `^\\\\\.\\pipe\\LOCAL\\cc-msg-[0-9a-f]{32}$` and refuses anything else before touching the
  filesystem, because the path arrives out of a file on disk
  (`TestWindowsDialRefusesAnythingThatIsNotASessionPipe`);
- the frames, over a **real socket** with a **fake** inbox server that reimplements the three
  dispatcher rules (auth first, token checked, `session_id` interlock) — `inbox_socket_test.go`.
  It uses a unix socket because the standard library can listen on one on every platform this
  program builds for, Windows included.

Off Windows the path is a unix socket and the dial is `net.DialTimeout("unix", …)`. **The Linux
socket path shape is unverified** — the spike only ever saw Windows sessions publish one — so the
only checks made there are the ones that hold for any unix socket: an absolute path, and a base
name beginning `cc-msg-`.

Nothing in this path logs the name, the identity or the token. The token never leaves the frame
buffer: it is not logged, not put in a hint, not wrapped into an error and not returned to the hub
(`TestInboxNeverLeaksThePeerToken`).

### The order "Fix name" tries, and why

Non-destructive first. The relaunch is last, and it is the only step that costs the person in that
terminal anything.

**Step 0 — precondition, free.** Read the target's `sessions/<pid>.json`. No `bridgeSessionId`
means no bridge to retitle, so skip to step 3 and say so (`unsupported-no-bridge`). Prove the key's
owner is the live pid in the same pass; nothing is dialled before that holds.

**Step 1 — the inbox rename.** Auth line from that session's own key file, then the rename frame
with that session's own `session_id`. Reachable status: **`delivered`**. Cost if it silently fails:
nothing. No process is touched, no user turn is added, no API call is made.

**Step 2 — re-read and report; do not re-send.** Check `name`, only `name`, briefly. Changed means
the handler ran. Unchanged is reported plainly (`unsupported-inbox-no-change`) rather than retried.

**Step 3 — relaunch, behind the confirm that names the sessions.** The only thing that both
re-binds the bridge and sets the title, and the only option with no bridge bound.

**Deliberately not in the order:** enqueueing slash-command text (it does not run the command, and
it injects a visible user turn and an API call into somebody's conversation — strictly worse than
`hook-queue`); an inbox "enable remote control" (no such action exists); and toggling
`/remote-control` off and on to "re-latch" (it mints a new `bridgeSessionId`, so it would appear
remotely as a new session, and it is untested).

## The restart action: copy-only by decision

A relaunch is the only thing that actually fixes a session a swap left behind. `restart_sessions`
exists so that answer is a first-class command with a confirm step of its own, instead of a hint
hanging off a rename. **It restarts nothing.**

### The decision, and why

Asked to add an optional "Restart sessions" that terminates the session process after the hub
passes a confirm token, the answer was **no: no kill path at all.** What shipped instead is the
confirm dialog that names the sessions and hands over the exact relaunch commands to copy, plus a
"Mark as restarted" that is a note in one browser.

The reasons, in the order they settle it:

1. **A terminate cannot be relaunched back.** A Claude Code session is attached to a terminal the
   server has never seen. The agent could kill the process; nothing could put the session back in
   front of the person who was working in it. "Terminate cleanly" is still throwing away their
   work, and the relaunch has to happen in that terminal either way — so the kill buys nothing the
   copied command does not already give.
2. **It could not be tested.** This feature is built and gated entirely offline, with the rule that
   no command is ever run against a real session. A kill path would ship unexercised, which is the
   one thing a kill path must never be.
3. **It contradicts a promise already in the product.** "No session is stopped, killed or
   restarted" is written in the confirm dialogs and in this runbook. Adding a kill would retract it.

So there is **no confirm token**, and nothing for one to unlock: `relaunch` is the only mechanism
registered for the command, and `relaunch` starts and stops nothing. The safety argument is the
absence of the code, not a gate in front of it. If a safe relaunch is ever wanted, it needs the
terminal's cooperation (a wrapper the person started themselves that can re-exec), and that is a
different feature with its own spike — not a flag on this one.

### What the operator sees

`restart_sessions` answers `unsupported` / `unsupported-requires-restart` per session, with the
relaunch command in the hint. The UI reads that as **Restart required**, which is accurate: the
restart is required and it is the operator's to run.

The confirm dialog (`#ctl-restart`) must name its targets. It lists every session the ask would
reach — the session's own name, its host and pid, whether it is on the old login, and the exact
command with a Copy button — and says in its body that claude-swap stops nothing. Two tests hold
that: `TestRestartConfirmDialogListsTheSessionsItWouldRestart` asserts the list element and the
no-kill sentence are served, and `TestRestartCommandNeedsConfirmAtEveryScope` asserts the hub
refuses a restart with no confirm at session, host and all scope (`ErrConfirmRequired`, a 409).

A session on an **offline** host is listed too, with "host offline, so the ask will not reach it"
on its row. Leaving it out would make the dialog's count disagree with the needs-reload callout
above it, which counts stale sessions whether or not their host is connected; two numbers on one
screen that disagree cost more trust than a row that states its own limit. The ask comes back
`failed` / `agent-offline` for those targets.

**Mark as restarted is a no-op.** It writes a key in page memory, drops those sessions from the
needs-reload callout's count for this browser, and prints "Marked as restarted in this browser
only; it stays listed until the session ends" on the row. It sends no request and changes no server
state. The hub's own needs-reload flag is cleared by one thing only: the session ending. A control
that cleared it for the hub would let the UI assert something nobody observed, which is the failure
this whole feature is built to avoid.

### Two facts the restart answer rests on

Both are recorded elsewhere in this runbook and repeated here because the restart action is where
they bite:

- **A rename of a running session needs a bridge bound to it.** The title push returns early
  without a `bridgeSessionId`, so a session with no bridge cannot be given a remote title by any
  channel — a relaunch is the only answer, and that is why the relaunch command carries the name.
  (A bridge-bound session is a different case: see
  [inbox](#inbox--the-rename-mechanism-off-by-default).) The title is **not** latched at bind; see
  [What spike 2 corrected](#what-spike-2-corrected).
- **What a credential swap does to an already-connected bridge is UNPROVEN.** Whether rewriting
  `claudeAiOauth` under a session with a live bridge tears the bridge down, keeps the old account's
  connection, or reconnects as the new account has never been tested; it needs a logged-in
  two-account run. Nothing in the UI or the docs may imply the bridge survives a swap. See
  [Not verified](#not-verified).

## relaunch_remote: the one command that stops a process

`restart_sessions` above stays copy-only. `relaunch_remote` is the separate, deliberate exception,
added because a relaunch is the only thing that binds Remote Control to a running session. It does
**not** reverse the decision above: it is a different command, per session, behind its own gates.

**What it does** (`internal/agent/relaunch.go`, mechanism `relaunch-process`): re-checks everything,
kills the session's pid, waits for it to exit, then starts `claude --resume <sessionId>
--remote-control` in the session's cwd with the agent's `CLAUDE_CONFIG_DIR`, detached (setsid on
Linux, a new console and process group on Windows). Arguments are an exec vector; there is no shell
and nothing from a file is interpolated into a command line.

**The cost, which the confirm names:** the process is killed, the running turn and its tools are
lost, and the new process needs a terminal (a new console window on Windows; on Linux it is
detached with no tty).

**Gates**, hub first and then the agent again from the session's own file:

| Gate | Refusal |
|---|---|
| Session scope only | `ErrRelaunchScope`, 400 |
| `confirm: true` | `ErrConfirmRequired`, 409 (it is a restart-type command, `proto.IsRestartCommand`) |
| Session reported `idle` | `ErrSessionNotIdle`, 409; the agent re-reads `status` and answers `failed` / `not-idle` |
| Session id is a UUID | `failed` / `bad-session-id` |
| The pid's file carries that id and the pid is alive with its recorded start time | `failed` / `session-gone` |
| cwd is an absolute existing directory, no control characters | `failed` / `bad-cwd` |
| `claude` is on PATH, checked **before** the kill | `failed` / `no-claude` |

Never part of `repair`, never registered for the inbox, never reachable at host or all scope. The UI
offers the button only for an idle session, behind the shared confirm dialog.

**Outcome.** The result stays `unsupported` / `unsupported-requires-restart` (with the manual
command in the hint) until a read-back sees the resumed session, the same session id on a different
live pid, publish a `bridgeSessionId` that is set and different from the old one. Only then is it
`done` / `relaunched`. A successful start proves nothing about the bridge. Failures after the kill:
`kill-failed` (the pid did not die, nothing was started) and `start-failed` (the old one is gone,
the new one did not start; the hint carries the manual command). The read-back waits up to about
10 s and the agent handles frames serially, so a relaunch holds that host's connection that long.

**Unproven:** whether `--resume` re-enables the bridge for a session that had none, and so whether
relaunching can *disable* it. A resume may bring the bridge straight back, so do not use this to turn
Remote Control off. Also unverified: Linux detached-start behaviour with no tty, and any live run.
The tests inject the kill and start functions; none starts a real `claude` or stops a real process.

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

## The operator's view

Everything above is driven from the **Hosts** tab of the admin UI
(`internal/web/static/index.html`), and nowhere else:

- **Per session**, inside the host card's session list: *Nudge: ask session to reload plugins*,
  *Enable remote*, *Fix name* and, for an idle session only, *Relaunch with remote control* (behind a
  confirm that names the cost). *Fix name* opens a small dialog with a labelled field prefilled from the session's
  current remote name, capped at 256 characters. There is deliberately **no per-session Restart
  button**: a stale session's row already carries its own relaunch command with a Copy button, which
  is the whole of what a restart can give one session. `restart_sessions` is still reachable at
  `session` scope through the API, with `confirm: true` like every other scope.
- **Per host**, on their own rule above the swap row: *Nudge all sessions on this host to reload plugins*, *Enable remote on all* and
  *Restart sessions*. The first two go through a confirm dialog that states how many sessions are
  affected and that no session is stopped, killed or restarted — the UI side of the `confirm: true`
  the hub insists on. *Restart sessions* goes to its own dialog, because a count cannot name the
  sessions and a restart has to.
- **Estate-wide**: a callout above the host list appears whenever a swap has left sessions on an
  old login, offering *Apply to all needs-reload sessions*
  (`repair` + `onlyNeedsReload` + `confirm`) behind the same confirm step, and *Restart sessions*
  through the naming dialog.

Each session's verdicts render as chips whose **word** carries the state, so colour only repeats
it: Queued, Delivered, Done, Failed, **Restart required**, **Unsupported**. The last two are both
the `unsupported` status, split on the reason code, because an operator acts on them differently:

| Chip | When | The sentence beside it |
|---|---|---|
| Delivered (asked, unverified) | status `delivered` | "Delivered: the ask reached the session. It does not mean the session acted on it." |
| Restart required | `unsupported-requires-restart`, or `unsupported-no-bridge` | "Restart required: cannot be done on a running session. Nothing was stopped." (the no-bridge variant names the missing bridge) |
| Unsupported | `unsupported` + any other code | "Unsupported: no proven mechanism can do this on a running session", or the specific sentence for `unsupported-no-inbox` / `unsupported-inbox-no-change` |
| Failed | status `failed` | "Failed: nothing was asked of the session", or for `inbox-send-failed`, "the session would not take the ask. Nothing reached it." |

The **Delivered** sentence is deliberately general. It has to be true of a hook putting an
instruction in front of the model at the next prompt *and* of a rename that reaches the session at
once but whose effect on claude.ai cannot be seen from the host. "The session runs it at its next
prompt" was true of only the first, and the UI must not imply the second was observed.

**The "Fix name" dialog's hint must not promise a mechanism.** It says a session with remote control
bound can take a new name where it stands, a session without gets the restart command, and either
way the answer means the ask reached the session — not that the name on claude.ai changed.

Before this split every `unsupported` read as "Needs restart", which was false for an unproven
inbox or a missing mechanism — neither of those is fixed by restarting. A relaunch hint gets a Copy
button. A counts line under the callout is recomputed
from the poll's own `commands[]` rather than from the 202's snapshot, so it can never contradict
the chips beside it. Buttons go disabled for the round trip and come back on either answer,
because a 202 means queued and not done; a refusal lands in an inline `role="alert"` beside the
control that raised it. After an ask the poll speeds up to 3 seconds for a minute.

## How this fits the swap flow

1. A swap replaces the `claudeAiOauth` block. Every session running at that moment is flagged
   **Needs reload** — it still holds the old login, and will until it restarts
   ([session-reload.md](session-reload.md)).
2. The operator asks for `repair` with `onlyNeedsReload: true`. Per stale session that queues one
   `reload_plugins` instruction and returns two honest `unsupported-requires-restart` answers with
   the relaunch command.
3. The relaunch command is the one that actually fixes the session: it comes back with the new
   login, with Remote Control bound and with its name given at bind. The queued `reload_plugins`
   is a convenience for a session the operator is not restarting yet.
4. The hub forgets a session's needs-reload flag when the session ends, so a relaunched session
   stops being listed.

A `rename_remote` on its own is worth asking for. With the inbox flag off it comes back
`unsupported` with the relaunch command, which records the intent and hands over the fix. With the
flag on, a bridge-bound session can be renamed where it stands, reaching `delivered` with no
restart and no API turn — which is the cheap half of what a relaunch would have given.

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

## What spike 2 corrected

Three claims in earlier versions of this runbook were wrong for 2.1.318. They are recorded here
rather than quietly deleted, because the next person to read the bundle will meet the same code and
needs to know which reading won.

**1. "The remote-visible title is latched once when the bridge binds; `/rename` does not re-latch
it."** Stated in three places. **Wrong.** Every non-`auto` rename runs `Jvn` → `gJo` →
`bridge.titleWriter.update(bridgeSessionId, name)`. The `Tk` gate that can stop it keys on
**transcript/history suppression**, not on bridge presence, so an ordinary host-started session
with a bridge bound pushes the new title. All three statements are rewritten.

Spike 1's **finding E** is not deleted, because it is a real finding read in the **opposite
direction**. `Cdn()` builds a `{subtype:"rename_session", title}` *control_request* and `_dn` logs
`tengu_device_bind_title_latched` / `[deviceBind] rename_session after bound create failed`. That
is the **bridge naming the host at bound-create** — remote to host, once, at bind. It is not a
latch that blocks later **host to bridge** pushes. The telemetry string carrying the word "latched"
is what made the direction easy to invert.

**2. "The telemetry event `uds_enable_remote_control` proves that enabling Remote Control over the
inbox is a real, instrumented path."** **Wrong.** The string exists in the binary; the call site
does not. `onEnableRemoteControl`'s setter has one whole-binary occurrence — its own definition —
and the dispatcher never reads the field. A session asked for the action logs
`Unhandled control action: enable_remote_control`. A telemetry string is evidence that somebody
once planned a path, not that one exists. The claim is removed, and the UI no longer implies a
mechanism.

**3. The inbox's open TODO list** — "the framing (length-prefixed or newline-delimited), which
field selects `onEnqueue` versus `onRename` versus `onEnableRemoteControl`, how the published key
becomes an authentication value, whether the GrowthBook gate is even on for this account" — is
**answered**, with one correction: there is no field that selects `onEnableRemoteControl`, because
nothing can select it. The gate is **on** on this machine; the throwaway's inbox bound without
coaxing.

One thing spike 1 got right and spike 2 narrowed: the accepted surface. It is `type:"user"` plus
`type:"control"` with one of seven `action` values. `notification` and `in_process_teammate`, named
in spike 1, are **not** handled — they fall through to
`Received unhandled message type: notification`.

## Not verified

- **The remote title change is verified once, by hand, not by the host.** The owner read the new
  title back on claude.ai/code on 2.1.318 for one bridge-bound session. The host still cannot
  observe it, so nothing in the UI may say the remote title changed; the ceiling stays `delivered`
  (`.catch(()=>{})` discards the push result). Not covered: other versions, other platforms.
- Whether `Tk`'s `noHistoryBackfill` disjunct suppresses the push for sessions **created from
  claude.ai**, as opposed to started in a terminal and then bridged. The bridge is constructed with
  `noHistoryBackfill: j && Oe?.uncertaintyOnly !== true`, which is set for remote-created sessions,
  so this is a real possibility and not a theoretical one.
- **A possible revert race.** `fqe` registers a `[jobStateNameSync]` watcher alongside the rename
  handler. It watches the job's `state.json` and re-applies the name it finds there. If job state
  still holds the old name, that watcher may re-apply it *after* a peer rename lands. One extra
  observation in the same logged-in run, not a separate test.
- `dialInbox` on Windows has no unit test; the standard library cannot serve a named pipe. The
  shape check and the frames are tested, and the open was proven by hand — see
  [Transport](#transport-no-dependency-was-added).
- The **Linux** inbox socket path shape, and the Linux transport end to end. No Linux session was
  observed publishing one.
- Which `entrypoint` values construct the interactive class that registers `onRename`. `cli` does
  and `sdk-cli` does not (a print-mode session left the handler null, which is why the throwaway's
  own name never changed). Anything else is **unknown**; treat `entrypoint` as three-valued, attempt
  the rename and report what the session file shows, rather than refusing up front.
- The `/remote-control` toggle, entirely. Driving it needs an interactive signed-in session. Note
  that a disconnect/reconnect mints a **new** `bridgeSessionId`, so it is a re-bind, not a
  re-latch: anything watching the old bridge session would see a new entry rather than a renamed
  one.
- No live canary against a session holding real work. No running, logged-in session of Matthew's
  was asked to do any of this and watched. The statuses reflect what the mechanisms can honestly
  claim, not an observed outcome on his sessions.
- Whether a hook's `additionalContext` reliably gets a model to run `/reload-plugins`. The
  instruction is delivered; compliance is the model's.
- Whether the installed hook entries fire exactly as expected in a real session. The entry shape,
  the marker, the backup and the idempotence are covered by tests; the firing is not.
- Whether rewriting `claudeAiOauth` under a session with an already-connected bridge tears the
  bridge down, keeps the old account's connection, or reconnects as the new account. Needs a
  logged-in two-account test. **Treat the effect of a swap on a live bridge as unknown**; the
  restart answer does not depend on it either way, since a relaunch rebinds the bridge regardless.
- Whether a pasted relaunch command brings a session back as expected. The command string is built
  and shown; nobody has run one here. `restart_sessions` deliberately runs nothing, so there is no
  kill or relaunch path to verify — only the string and the confirm that names the sessions, both
  of which are covered by tests.
