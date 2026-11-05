# claude-swap: app-managed tunnels addendum (2026-11-05)

Status: draft for approval. Does **not** edit the approved design (`2026-11-04-claude-swap-design.md`).
It extends that design with a **Tunnels** section in the admin UI and moves the reverse-SSH
supervision out of `scripts/claude-swap-tunnels.ps1` and the `claude-swap-tunnels` scheduled task
into the server binary.

Design only. No application code is written by this addendum.

## Decision (Matthew)

The app manages the tunnel key and the tunnels itself. The admin UI gets a Tunnels section. The
interim scheduled task becomes a fallback, then goes away.

## 0. Measured baseline: what the interim task actually does

Run on the live hosts on 2026-11-05 before any design was written. One host (label `SRL-LIN`) had
its tunnel `ssh.exe` killed; nothing else was touched. Addresses and usernames were never printed.
Observation was server-side only: the per-process `ESTABLISHED` connection to `127.0.0.1:8443`
is the agent's WebSocket arriving through that host's tunnel, so a tunnel can be seen as *up*
separately from the *agent* being connected through it. (`<datadir>/hosts.json` holds enrolment
records only — liveness is `hub.host.lastSeen`, in memory — so it is useless for timing.)

### Run 1 and run 2 — single kill, counter already reset

| Event | Run 1 | Run 2 | Source |
|---|---|---|---|
| kill of the host's tunnel `ssh.exe` | t = 0 (08:07:38.5 local) | t = 0 (08:08:42.0) | measured |
| supervisor logs `tunnel exit … code=-1 reason=''` | +2 s | +2 s | `tunnels.log` |
| replacement `ssh.exe` running | **+18.2 s** | **+17.4 s** | measured, and `tunnels.log` `tunnel start` at +18 s |
| agent's connection re-established through it | **+26.9 s** | **+27.6 s** | measured |

The ~18 s is `RestartDelaySeconds = 15` plus the 2 s supervisor poll plus detection granularity.
The remaining ~9 s is the agent's own redial: `internal/agent/backoff.go` is 1 s doubling to a
60 s cap with a 0.8–1.0 jitter factor, and `stableAfter = 30 s` resets the attempt counter. Both
runs started from a connection that had been up 11 min and 46 s, so the counter was 0 and the
agent was climbing 1, 2, 4, 8, 16 s — it was sitting on the 16 s tier when the tunnel returned.

**~27 s is the best case, not the bound.**

### Incidental run 3 — counter saturated (the case that matters)

Mid-test another session restarted the supervisor (`tunnels.log`: `supervisor start … pid=86532`
at 14:13:55Z), whose predecessor's `finally` block killed both tunnels. That produced the
saturated path for the other host (label `TSS`) for free:

- 14:13:17Z — its 18-minute-old tunnel died. Counter reset; agent reconnected inside ~15 s.
- 14:13:55Z — that 22 s connection was killed. 22 s < `stableAfter`, so the counter did **not**
  reset; the agent was on the 16–32 s tier.
- 14:13:56Z — the tunnel was back after **1 second**.
- The agent was still not connected when sampled roughly 10–40 s later, and was connected at
  +64.5 s after the tunnel process started.

So with the tunnel restored in one second, the agent took somewhere between ~15 s and ~64 s to
notice. Computed worst case from `backoff.go`, not measured: 60 s cap + ~18 s supervisor delay =
**~78 s kill-to-connected**. The runbook's "~60 s of lag" refers to the agent half only.

### Does the agent need a redial fix?

It redials unaided — no correctness fix is required. But there is a ratchet worth closing:
`stableAfter = 30 s` means any connection that dies inside 30 s leaves the counter where it was,
while the supervisor restarts unconditionally every 15 s. A genuinely unreachable host therefore
produces exactly the flap pattern that pins the agent at the 60 s cap, and it stays pinned for the
first redial after the link comes back for good.

**Recommendation — lower the cap, do not add tunnel detection.** The agent dials
`127.0.0.1:8443`; while the tunnel is down that fails instantly and locally, so no remote server
is being spared by a 60 s cap. Use a separate cap of 10–15 s when the configured server URL's host
is loopback, keeping 60 s for any non-loopback deployment. No new mechanism, and it turns ~78 s
into ~30 s. A "fast retry when the tunnel is back" signal is explicitly **not** recommended: the
agent has no way to learn that except by dialling, which is what it already does.

The bigger win is on the server side, and it comes free with this addendum: an app-owned supervisor
can use a 1 s-first backoff instead of a flat 15 s wait, cutting the supervisor half from ~18 s to
~3 s. Best case kill-to-connected then lands near 5 s.

### Two defects the test surfaced in the interim task

1. `tunnels.log` at 13:55:07Z: `tunnel start-failed name=TSS reason='The property 'ArgumentList'
   cannot be found on this object.'` The current script builds the command line by hand precisely
   to avoid that, so the *installed copy* was stale against the repo — the footgun the runbook
   already warns about ("Re-run the installer after you edit the script") firing for real. One
   binary has no second copy to go stale.
2. Every `tunnel exit` line reads `code=-1 reason=''`. Exit code and empty stderr give nothing to
   diagnose, which is the observability gap section 5 fixes with mapped reason codes.

## 1. Where the tunnel and key logic lives

New package `internal/tunnel`. The server owns it; the agent is untouched by this addendum.

```
internal/tunnel/
  tunnel.go        Supervisor, Spec, State, HostTunnel, public API used by hub/web
  backoff.go       NextDelay: 1s doubling, 30s cap, 0.8 jitter floor  (mirrors internal/agent)
  classify.go      ssh stderr -> reason code; scrubs address/user before anything is kept
  keyring.go       ed25519 generate / fingerprint / rotate / revoke, vault-backed
  authkeys.go      the authorized_keys line, and the install/remove commands (strings only)
  knownhosts.go    the app-owned known_hosts file
  spawn.go         Runner interface + argv construction (platform independent)
  spawn_windows.go ssh.exe, ephemeral key file with a restricted ACL
  spawn_unix.go    ssh, 0600 key file in a 0700 dir
  reap.go          kills tunnel children left by a previous, hard-killed server process
```

Interfaces, so tests need no network and no real `ssh`:

```go
type Runner interface { Start(ctx context.Context, s Spec, keyPath string) (Proc, error) }
type Proc   interface { Pid() int; Wait() error; Kill() error; Stderr() string }
type Keys   interface { Private(hostID string) (ed25519.PrivateKey, error); Public(hostID string) ssh.PublicKey }
```

`Runner` is the single platform seam. A Linux-hosted server later swaps `spawn_windows.go` for
`spawn_unix.go` and nothing above changes. (Costed in open question 6: replacing the child process
with a pure-Go client over `golang.org/x/crypto/ssh` would remove the seam entirely.)

**One supervisor per server process; one goroutine ("tunnel runner") per host.** Hosts are
independent: one host failing never delays another, and `Supervisor` holds no lock while a child
runs.

### Per-host state machine

```
            start()                process alive > grace
  disabled ─────────> connecting ──────────────────────> up
     ^                   │  │                             │
     │                   │  └── exit, retryable ──> down ─┘ (after NextDelay)
     │                   └───── exit, terminal ───> failed
     └──────────── disable() from any state ──────────────┘
```

| State | Meaning |
|---|---|
| `disabled` | configured but switched off in the UI; no child process |
| `connecting` | child started, has not yet survived the 3 s grace window |
| `up` | child alive past grace; forward presumed established |
| `down` | child exited for a retryable reason; waiting out `NextDelay(attempt)` |
| `failed` | terminal reason (see section 5); retries stop, the UI shows the code and offers Restart |

`up` deliberately means *the process is alive past a grace window*, not *the forward is
established* — proving the latter means parsing `ssh -v` stderr, which carries addresses (open
question 8). The Hosts tab therefore shows the tunnel state and the agent state as **two separate
indicators** and never merges them; "tunnel up, agent offline" is the diagnostic case.

`attempt` resets to 0 once a child has been `up` for `stableAfter = 60 s`.

### Lifecycle

- **Server start**, after the vault is unlocked (the key material lives there): `reap.go` kills any
  `ssh.exe` recorded in `<datadir>/tunnels-journal.json` by a previous process that did not shut
  down cleanly, and deletes any orphaned ephemeral key file. Same journal-then-settle pattern as
  `internal/agent`'s swap journal. Then the supervisor starts one runner per enabled host.
- **Each spawn** writes the child's pid and start time into the journal and removes it on exit, so
  a hard kill of the server leaves a record rather than an orphan.
- **Server stop**: cancel the supervisor context; each runner signals its child, waits 5 s, then
  force-kills; the journal is emptied. One audit line per host. The PowerShell script does this in
  a `finally`, which does **not** run when the task is hard-killed — the journal plus reap is what
  makes the Go version survive that.
- The supervisor never blocks server start: a host that cannot be reached sits in `down`/`failed`
  and the UI says so.

## 2. Key generation, rotation, revoke, fingerprints

**Algorithm: ed25519.** Same as today; small, fast, no parameter choices.

**One app key or one key per host? Recommend per-host keys.**

| | One app key | Per-host keys (recommended) |
|---|---|---|
| Revoke one host | re-key every host | remove one line, one host |
| Blast radius of theft | forward into every host | forward into one host |
| Attribution | an `authorized_keys` line cannot say which host it is | the line names the host |
| Operator effort | one install command, ever | one install command per host |
| `permitlisten` | identical either way (per-line option) | identical |

The operator effort is the only argument for a shared key, and option C in section 3 makes it one
pasted line per host — the same line the operator already pastes to enrol an agent. Per-host keys
also make rotation incremental: one host at a time, with an overlap window, instead of a flag day.

**Fingerprint display.** The standard `SHA256:<base64>` form, exactly what `ssh-keygen -lf` prints,
so the operator can compare it on the host. Shown in full in the Tunnels section; the first 8
characters appear on the Hosts tab row, matching the enrolment-fingerprint convention the design
already uses (Decision 13).

**Rotation** (per host, never destructive first):
1. Generate a new key; state becomes `rotating`.
2. The UI shows the install command for the **new** public key. Both lines are valid.
3. The supervisor restarts the tunnel on the new key. It must reach `up` and stay there for a
   settling period.
4. Only then does the UI offer the remove command for the **old** line, and the old private key is
   deleted from the vault.

A rotation abandoned at step 2 leaves one extra authorized line and no loss of service; the UI
shows `rotating` until it is finished or cancelled, so it cannot be silently half-done.

**Revoke**: delete the private key from the vault and show the remove command. If the host is
unreachable the state is `revoke_pending` and the UI says plainly that the line probably still
exists on that host. A false green here would be worse than the honest warning.

**Passphrase handling.** There is none, and that is now defensible rather than a compromise. The
private keys sit inside the existing vault (argon2id + AES-256-GCM, key from `CLAUDESWAP_KEY` at
start), so at rest they are protected by the same passphrase as every account token. The runbook's
deliberately passphrase-less on-disk key goes away with the scheduled task. Key bytes are
decrypted into memory only, and reach `ssh` by the route in section 4.

## 3. Installing and removing the restricted `authorized_keys` line

The line, unchanged from the runbook except for a per-host comment:

```text
command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:8443" ssh-ed25519 AAAA… claude-swap-tunnel-<label>
```

Order is load-bearing: a later option beats an earlier one, so `restrict` (deny everything,
including capabilities OpenSSH has not invented yet) must come before `port-forwarding`
(re-enable forwarding only). Pending open question 1, `permitopen="127.0.0.1:1"` is added to close
the `-L` gap described in section 7.

Mechanics, wherever the append happens: `~/.ssh` mode 0700, `authorized_keys` mode 0600, existing
lines preserved, idempotent on the key body (skip if present), and written temp-then-rename rather
than edited in place — the same discipline `internal/credfile` uses on the credentials file. No
`sudo`, and nothing under `~/.claude*` is touched.

### How the server gets the one-time login: option P vs option C

**Option P — password prompted in the UI.** The admin types the host password once; the server
feeds it to `ssh` through an askpass helper (`SSH_ASKPASS` plus `SSH_ASKPASS_REQUIRE=force`),
appends the line, then zeroes it. Never stored, never logged.

- For: no step on the host at all. Works for a host the operator cannot easily sit at.
- Against: a host shell password transits, and briefly lives inside, the one process that already
  concentrates every Claude account token. Server compromise escalates from "a loopback forward on
  N hosts" to "an interactive shell on N hosts". The askpass path on Windows needs a helper
  executable or script and puts the secret in a child process's environment. A wrong password is
  indistinguishable from a locked account, so the error is poor. It also contradicts the posture
  the design already chose: agents dial out, the enrol code is environment-only and never a flag,
  and nothing asks the owner for a host credential.

**Option C — the host operator runs a generated one-line command (RECOMMENDED).** The UI shows a
line containing the public key only; the operator pastes it on the host.

```sh
umask 077; mkdir -p ~/.ssh; K='ssh-ed25519 AAAA…'; L='command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:8443" '"$K"' claude-swap-tunnel-<label>'; grep -qF "$K" ~/.ssh/authorized_keys 2>/dev/null || printf '%s\n' "$L" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

The trailing `ssh-keygen -lf` prints the **host's own** key fingerprint, which the operator pastes
back into the UI to seed `known_hosts` (section 7). Removal is the matching `grep -v` one-liner,
also generated.

- For: the server holds no host credential, so server compromise cannot become shell access that
  it did not already have. It matches Decision 13 and the enrol-code path the operator already
  uses. The failure mode is "the operator did not run it", which shows up as a tunnel in `failed`
  with code `auth_denied` — legible, not silent.
- Against (not free): the operator needs a shell on each host, for install **and** again for
  removal and rotation. A host nobody can log into cannot be onboarded at all. Pasting a long
  generated line invites truncation, so the UI must offer a copy button and the command must be
  idempotent — which it is.

**Decision requested: option C, with option P out of scope for v1** — not "later maybe". If a host
ever genuinely cannot be reached by hand, revisit it then with the escalation written down.

## 4. Private key storage and getting it to `ssh.exe`

**At rest: in the vault**, as a record per host beside the account blocks. No API response, log
line, template or error ever contains private key bytes; there is no endpoint that returns one.
The UI shows the fingerprint and the public key, which is all an operator needs.

`ssh` will not take a key on stdin. It needs a file (`-i`) or an agent socket, so one of:

**Option A — ephemeral file per spawn (default for v1).** Write the key into the data dir in a
directory already restricted by `credfile.RestrictDir`, mode 0600 on Unix and a DACL granting only
the server's own SID on Windows; pass `-i <path> -o IdentitiesOnly=yes`; delete it when the child
exits, and reap leftovers at server start (section 1). The exposure window is one child's lifetime
and the file is rewritten on every respawn — which, given the supervisor restarts on every exit,
happens often. The precise ACL Windows `ssh.exe` accepts is open question 3: it refuses keys it
judges too permissive, and the failure is an unhelpful one.

**Option B — in-process ssh-agent over a named pipe (follow-up).** Serve the agent protocol with
`golang.org/x/crypto/ssh/agent.ServeAgent` — already in the dependency set — and point the child's
`SSH_AUTH_SOCK` at it. The key never touches disk at all. Two unknowns: whether Windows `ssh.exe`
accepts a named pipe path in `SSH_AUTH_SOCK` (it speaks to `openssh-ssh-agent` over a pipe, so it
is plausible but unverified), and that Go's `net` cannot serve a Windows named pipe, so the pipe
itself needs `x/sys/windows` syscalls or a new dependency. Open question 2.

Ship A, spike B, move to B if it holds — it removes the only on-disk window. Do not assert B works
until it is tested.

## 5. Per-host tunnel state on the Hosts tab

Each host row gains a tunnel column, independent of the existing online/offline agent indicator:

| Field | Example |
|---|---|
| state | `up`, `connecting`, `down`, `failed`, `disabled`, `rotating`, `revoke_pending` |
| in state since | `up for 3 h 12 m` |
| restarts (1 h) | `0`, or `7` |
| last restart | `08:08:59` |
| last error | `auth_denied` + one short redacted sentence, or empty |
| key fingerprint | first 8 characters, full value in the Tunnels section |

Errors are **reason codes mapped from stderr, never stderr itself**:

| Code | ssh stderr it maps from | Retry? |
|---|---|---|
| `auth_denied` | `Permission denied (publickey)` | no — `failed` |
| `hostkey_mismatch` | `REMOTE HOST IDENTIFICATION HAS CHANGED` | no — `failed` |
| `hostkey_unknown` | `Host key verification failed` | no — `failed` |
| `forward_refused` | `remote port forwarding failed for listen port` / `administratively prohibited` | yes — a stale listener clears |
| `unreachable` | timeouts, no route, name resolution | yes |
| `exec_failed` | `ssh` not on PATH | no — `failed` |
| `killed` / `exit_<n>` | anything else | yes |

Two logging rules the package must honour, both learned from existing code:

- **`logx.Redact` masks secret-*looking* text; it knows nothing about host addresses.** So
  `classify.go` scrubs the configured address, the username and every non-loopback IP literal out
  of any free text *before* it is kept at all — the same `Protect-Text` approach the PowerShell
  supervisor already takes — and the default is to keep only the code and drop the text.
- **The allowlist is an allowlist.** New fields need registering: `logx.Allow("tunnel",
  "tunnelstate", "restarts")` at init, or they log as `[dropped]`. Note two traps: `logx.Allow`
  panics on any key containing `key`, so there is no `tunnelkeyid` field (use `fingerprint`); and
  `code` is already allowlisted, so the reason code uses the existing `code` key rather than a new
  one. `host` likewise already exists and means the label, never an address.

## 6. Admin session, CSRF, rate limits, audit

Endpoints follow the existing pattern exactly — `s.auth` for reads (401 unauthenticated) and
`s.authPost` for writes (401, then 403 on a wrong or missing `X-CSRF-Token`):

| Method and path | Purpose |
|---|---|
| `GET /api/tunnels` | list: label, state, since, restarts, last error code, fingerprint, public key |
| `POST /api/tunnels` | add a host: label, address, user, port |
| `POST /api/tunnels/{id}/enable`, `/disable` | switch a host's tunnel on or off |
| `POST /api/tunnels/{id}/restart` | restart now, skipping the remaining backoff |
| `POST /api/tunnels/{id}/key/rotate`, `/key/revoke` | section 2 |
| `GET /api/tunnels/{id}/install-command`, `/remove-command` | the generated one-liners (public key only) |
| `DELETE /api/tunnels/{id}` | forget the host; revoke first |

Rate limits, because an admin can otherwise out-hammer the backoff and because these spawn
processes: `restart` at most once per host per 10 s and 6 per host per hour; `key/rotate` once per
host per minute; `POST /api/tunnels` 10 per hour overall. Over the limit is `429` and nothing
happens.

Input validation, so nothing unvalidated reaches an `ssh` argument list: address ≤ 253 characters
and DNS-or-IP shaped; user `^[a-z_][a-z0-9_-]{0,31}$`; port 1–65535; label `^[A-Za-z0-9._-]{1,32}$`.
Any value containing whitespace, a quote, a newline or a leading `-` is refused. Arguments are
passed as an `exec.Command` argv slice, never a joined string — the manual quoting in
`ConvertTo-CommandLine` is a Windows PowerShell 5.1 constraint that does not apply to Go.

Audit lines, allowlisted keys only (`host`, `action`, `result`, `code`, `tunnelstate`, `attempt`,
`durationms`), one per event: `tunnel_added`, `tunnel_enabled`, `tunnel_disabled`,
`tunnel_restart_requested`, `tunnel_key_rotated`, `tunnel_key_revoked`, `tunnel_removed`,
`tunnel_state_change`, `tunnel_stopped`. Never the address, the username, the private key, or raw
stderr. The app's own tunnel event log gets an explicit retention, not never-expire (open
question 9).

## 7. Threat model

**Server compromise.** An attacker with the data dir *and* `CLAUDESWAP_KEY` gets every Claude
account token and every tunnel private key. With the keys they can open a reverse forward to each
host's loopback 8443. `command="/bin/false"` and `restrict` deny them a shell, a PTY, agent
forwarding, user rc and X11. But note what is *not* denied: `port-forwarding` re-enables **both**
`-R` and `-L`, and `permitlisten` constrains only the listen address of `-R`. So the key can be
used as an **outbound pivot** — `ssh -L 1234:<anything-the-host-can-reach>:<port>` — into each
host's network. That is the real gap in the current line, and the mitigation to verify is
`permitopen="127.0.0.1:1"`, a deliberately dead destination (open question 1). Context, not
excuse: an attacker who owns the server already owns the agent channel and every token, so the
pivot is the incremental damage, not the headline.

**Host compromise.** The host holds only a public key, so nothing is learned from it. A host-local
attacker can deny service, and can connect to the forwarded port — but still needs a valid agent
token, and the agent pins the server's TLS certificate by sha256, so a forged local listener
cannot impersonate the server. What a compromised host *can* read is that user's
`~/.claude/.credentials.json`: pre-existing exposure, unchanged by this addendum.

**Key theft.** At rest the keys are inside the vault, so stealing the data dir alone is not
enough; the environment key is also needed. The live exposure is the ephemeral `-i` file of
section 4 — bounded by a single child's lifetime, a restricted ACL, and reap-on-start. Option B
closes it entirely.

**MITM and host key pinning.** `StrictHostKeyChecking=yes` is already set, which means an unknown
host key *fails* rather than prompting — so the app must own `known_hosts` explicitly:
`-o UserKnownHostsFile=<datadir>/known_hosts -o GlobalKnownHostsFile=/dev/null`, seeded at
add-host time from the fingerprint the operator read off the host (the tail of option C's command).
Never `StrictHostKeyChecking=no`, and never `accept-new` for a key the operator has not confirmed.
A changed host key becomes `hostkey_mismatch`, state `failed`, no retries, and an explicit
re-confirmation in the UI. Independently of all this, **the agent's `--pin` still authenticates the
server**: a successful SSH MITM sees TLS ciphertext and can deny service, but cannot impersonate
the server to the agent.

**Port-forward abuse from the host side.** The `-R` listener binds `127.0.0.1` on the host, so only
host-local processes reach it; `permitlisten` is what keeps it from being bound on a routable
address. The hub's existing pending-connection caps and per-IP limits still gate what an
unauthenticated dialler can do once it arrives.

**What `permitlisten` does and does not cover.** It covers: the one listen address an `-R` request
may ask for. It does not cover: `-L` and `-D` destinations, how many forwards a session opens, or
traffic volume. `restrict` *is* forward-compatible — it denies capabilities added in a future
OpenSSH — so that particular worry is covered, as long as `port-forwarding` stays the only
re-enabling option on the line.

## 8. Tests plan (TDD, fake ssh)

The `Runner` seam makes most of this network-free. Two fakes: an in-Go `Runner` for state-machine
tests, and a **fake ssh binary** — a tiny program under `internal/tunnel/testdata/fakessh`, built
by the test into `t.TempDir()`, which echoes its argv to a file and then emits scripted stderr and
a scripted exit code from an environment variable. That one covers argv construction and stderr
classification end to end without a network or a real host.

Red-first list:

1. `NextDelay`: monotone doubling, 30 s cap, jitter inside [0.8, 1.0], `attempt < 0` safe.
2. Supervisor starts exactly one child per enabled host and none for a disabled one.
3. Child exits for a retryable reason → `down`, restarted after `NextDelay`, `attempt` increments.
4. A child `up` longer than `stableAfter` → `attempt` resets to 0.
5. `Permission denied (publickey)` → `auth_denied`, `failed`, **no** further restart.
6. `REMOTE HOST IDENTIFICATION HAS CHANGED` → `hostkey_mismatch`, `failed`, no restart.
7. `remote port forwarding failed for listen port` → `forward_refused`, retried with backoff.
8. argv contains `-N`, `-o StrictHostKeyChecking=yes`, `-o UserKnownHostsFile=<datadir>/known_hosts`,
   `-o GlobalKnownHostsFile=/dev/null`, `-o ExitOnForwardFailure=yes`, `-o IdentitiesOnly=yes`,
   `-o BatchMode=yes`, `ServerAlive{Interval=30,CountMax=3}`, and exactly one
   `-R 127.0.0.1:P:127.0.0.1:P`.
9. A label, user or address containing a space, quote, newline or leading `-` is refused by the API
   and no child is spawned.
10. Ephemeral key file: created with the restricted mode/ACL, deleted after the child exits, and
    reaped at supervisor start when a journal entry survives a hard kill.
11. **Leak test**: run a whole lifecycle (start, auth failure, restart, stop) against a captured
    log buffer and assert the output contains neither the configured address, nor the username, nor
    any private key byte sequence. Table-driven, one row per event.
12. `Stop` kills every child, empties the journal, logs `tunnel_stopped` per host; a second `Stop`
    is a no-op.
13. Rotation: both lines valid during overlap; the old key is deleted only after the new tunnel
    settles; revoke with the host unreachable → `revoke_pending` and the key gone from the vault.
14. Web: every `/api/tunnels*` route is 401 without a session, 403 with a session and no CSRF
    header, and 429 past the restart rate limit.
15. Generated install/remove commands contain the public key, never a private key, carry the
    `grep -qF` idempotence guard, and the remove command leaves other `authorized_keys` lines
    alone (asserted against a fixture file).
16. Windows: argv survives as a slice — asserted by the fake ssh writing its own `os.Args` back.

Plus a `_verify/cases/` case that drives the fake-ssh lifecycle and greps the log for addresses, so
the leak check runs outside `go test` too.

## 9. Rollback, and coexisting with the interim scheduled task

**They must not overlap.** Two supervisors means two `ssh -R` to the same host; the second gets
`remote port forwarding failed` because the host's 8443 is already bound and, with
`ExitOnForwardFailure=yes`, exits at once — an endless restart loop and a flapping Hosts tab. Run 3
of the measurement is a mild version of exactly this.

Migration, one host at a time:

1. Ship the Tunnels section behind a flag, **off by default** (`--tunnels`). No behaviour change.
2. Import hosts: a one-shot "import from `tunnels.json`" button reads
   `%USERPROFILE%\.claude-swap\tunnels.json` into the vault and **leaves the file in place** for
   rollback. (Manual retyping also works; the button avoids a transcription error in an address.)
3. Per host: generate the per-host key, show the install command, operator pastes it, operator
   pastes the host fingerprint back. The old shared key's line stays — both keys work.
4. Stop the interim task: `Stop-ScheduledTask -TaskName claude-swap-tunnels`, then
   `install-tunnels-task.ps1 -Uninstall`. Then **check for orphans**: the script's `finally` kills
   its children on a clean stop but not on a hard kill, so confirm no `ssh.exe` with
   `-R 127.0.0.1:8443` remains, and kill any that do.
5. Enable `--tunnels`. Watch the Hosts tab: tunnel `up`, then agent online. Expect the two to be
   seconds apart, not simultaneous.
6. After a settling period, and only then, remove the old shared key's `authorized_keys` line with
   the generated remove command and delete `~\.ssh\id_ed25519_claudeswap`.

**Rollback** at any point before step 6: disable `--tunnels` (the supervisor stops and kills its
children), re-run `install-tunnels-task.ps1`, `Start-ScheduledTask`. The shared key's line and
`tunnels.json` are both still there, which is why step 6 is last and deliberate.

## 10. Open questions

1. Does `permitopen="127.0.0.1:1"` neuter `-L` while leaving the `-R` forward working? Spike on one
   host. If yes it belongs in the recommended line, and the delta is a step in section 9.
2. Does Windows `ssh.exe` accept `SSH_AUTH_SOCK` pointing at a named pipe we serve in-process? If
   yes, which pipe implementation — `x/sys/windows` syscalls, or a new dependency?
3. What exactly does Windows `ssh.exe` require of the `-i` file's ACL? It refuses keys it judges
   too open, and the error is unhelpful.
4. Per-host keys over one app key is recommended (section 2) — confirm Matthew accepts one install
   step per host.
5. Keep 8443 as the forwarded port on every host, or give each host a distinct remote port? Distinct
   ports would let two servers coexist and narrow `permitlisten`, but would change every agent's
   configured URL. Probably no.
6. Linux-hosted server: the same `Runner` with a 0600 file in a 0700 dir, and no ACL story.
   Separately, cost replacing the child process with a pure-Go client over
   `golang.org/x/crypto/ssh` — it removes the fake-ssh seam, the ephemeral key file and the
   platform split in one go, at the price of owning a reverse-forward implementation.
7. Lower the agent's backoff cap for a loopback server URL (section 0) — same ticket, or its own?
8. Should `up` mean "forward actually established" rather than "process alive past grace"? It needs
   a `-o LogLevel=VERBOSE` stderr parse, whose text carries addresses.
9. Retention for the app's tunnel event log — propose 7 days or 1 MB, whichever comes first.
   Explicit, never unbounded.
10. Should the Tunnels section be able to add a host that has no agent enrolled yet (tunnel first,
    agent second), or only annotate existing hosts? Tunnel-first is the real onboarding order.
