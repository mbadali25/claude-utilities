# Install the claude-swap agent on a Linux host

## Quick start

1. On a build machine run `GOOS=linux go build -o agent-linux ./cmd/agent` and copy `agent-linux` to the host.
2. Set these environment variables (secrets never travel as flags):

```bash
export CLAUDESWAP_SERVER=https://swap.example:8443     # the server URL
export CLAUDESWAP_PIN=<64-hex-cert-sha256>             # printed at server start
export CLAUDESWAP_AGENT_BIN=/path/to/agent-linux       # the binary you copied
read -rs CLAUDESWAP_ENROL_CODE && export CLAUDESWAP_ENROL_CODE   # optional, no echo

# optional: which local user the agent runs as. Default is the invoking user.
export CLAUDESWAP_RUN_AS=dadeush        # any local user, 'root' included
```

3. Look before you leap, then install:

```bash
CLAUDESWAP_DRY_RUN=1 bash scripts/install-agent.sh   # prints user, home, state dir, unit path
sudo -E bash scripts/install-agent.sh                # system unit, runs as CLAUDESWAP_RUN_AS
#   or, for a per-user unit installed as yourself:
bash scripts/install-agent.sh
unset CLAUDESWAP_ENROL_CODE
```

4. Approve the host in the server UI (not needed when a valid one-time code was used). The Hosts card then shows **agent runs as `<user>`**.

Sign in with `claude auth login` **as the agent's user** — the user whose home holds `~/.claude.json`. Not as root, unless the agent itself runs as root. The agent reads one home and only that one.

### Which mode you get

| You run | Mode | Unit | Runs as | Needs linger |
|---|---|---|---|---|
| `bash install-agent.sh` as yourself | user | `~/.config/systemd/user/claude-swap-agent.service` | you | yes |
| `sudo -E bash install-agent.sh` | system | `/etc/systemd/system/claude-swap-agent.service` | `root` — `sudo` makes root the invoking user, so set `CLAUDESWAP_RUN_AS` to pick anyone else | no |
| `sudo -E CLAUDESWAP_RUN_AS=dadeush bash install-agent.sh` | system | `/etc/systemd/system/claude-swap-agent.service` | `dadeush` | no |
| `CLAUDESWAP_SYSTEM=1` or `--system`, as a user who can write `/etc/systemd/system` | system | as above | `CLAUDESWAP_RUN_AS`, default you | no |
| `CLAUDESWAP_RUN_AS=someone-else` without root | refused | — | — | — |

Only root may install for another user: there is no way to write somebody else's home, and quietly installing for yourself instead would be worse.

### The cases, and what each one does

| Case | Outcome |
|---|---|
| run as yourself, no root | per-user unit, `User=` not needed, `loginctl enable-linger` required to outlive your session |
| run under `sudo`, no `CLAUDESWAP_RUN_AS` | system unit with `User=root Group=root`; the agent swaps **root's** credentials |
| run under `sudo` with `CLAUDESWAP_RUN_AS=<user>` | system unit with `User=<user> Group=<user>`; home from `getent passwd`, binary and state dir chowned to that user |
| `CLAUDESWAP_RUN_AS` names a user that does not exist | refused: `user '<name>' does not exist: getent passwd found no entry for it` |
| `CLAUDESWAP_RUN_AS` names a nologin or sub-1000 account | refused, naming the shell or the uid; `CLAUDESWAP_ALLOW_SYSTEM_USER=1` installs for it anyway |
| the home is missing, or not owned and writable by that user | refused, naming the path. Ownership is the test, not `test -w`: root bypasses the mode bits |
| `--reconfigure` | stops the existing unit (system **or** user), rewrites it, keeps the state dir or copies the **whole** directory — token and any unsettled swap journal — into the new one, so the host stays enrolled |
| `--system` / `CLAUDESWAP_SYSTEM=1` without write access to `/etc/systemd/system` | refused, naming the path |
| no `/run/user/<uid>` | warns that the account has no user manager, names `sudo loginctl enable-linger <user>`, falls back to `systemctl --user --machine=<user>@.host` |
| `CLAUDESWAP_DRY_RUN=1` | prints mode, user, uid, home, state dir and unit path; writes, downloads and runs nothing |

**The agent running as root swaps only the `claudeAiOauth` block of root's own credentials.** It is not a privileged helper that swaps logins for everybody on the host: `User=root` simply means the one home it reads and writes is `/root`. Every other user's `~/.claude` is untouched.

**Not yet verified on a real host.** The installer and the Linux session scan have not run on a real host, and the `/proc` start-time (`procStart`) format is unverified. Targets are TSS and SRL-LIN, to be run by Matthew himself.

One script does the whole install: `scripts/install-agent.sh`. It copies or downloads the agent binary, enrols the host, writes a systemd **user** unit and starts it. Every input arrives in the environment, never as a flag, because an enrolment code on a command line is readable by every user on the host through `/proc/<pid>/cmdline`.

Never paste, print, log or commit a token. Do not `cat` a credentials file or a backup; check files by existence, size and key names only.

## Prerequisites

On the Linux host:

- **`~/.claude.json` with an `oauthAccount` object** (an email address, else an account uuid). The agent reads the signed-in identity from it. A host without it can connect but cannot import its login, and the hub refuses the import.
- **Claude Code installed and signed in at least once**, which is what creates `~/.claude.json` and `~/.claude/.credentials.json`.
- **`CLAUDE_CONFIG_DIR` must NOT be set** for the default profile. Set it only for a sandbox config dir — and then keep it identical for `enrol` and for the unit, exactly as with `CLAUDESWAP_STATE_DIR`. The install script never sets it.
- **systemd.** A system unit (the `sudo` path) needs nothing more. A **user** unit needs a running user manager for that account — `systemctl --user` working, which in turn needs `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`; the installer sets both when they are unset. Without any systemd the script still installs and enrols, and tells you to run `agent run` yourself.
- `curl` or `wget`, and `sha256sum` or `shasum`, only if you download the binary instead of copying one.

On the server side, have ready:

- the server URL, `https://<host>:<port>`;
- the certificate **pin**: the server prints `certificate sha256=<HEX>` at startup;
- optionally a **one-time enrolment code**, generated in the admin UI. Without one, the host waits up to 10 minutes for an admin to approve it by matching the fingerprint the enrol step prints.

## Build the Linux binary

From the repo on any machine with Go (a Windows desktop included — this cross-compiles):

```powershell
cd C:\repos\personal\claude-utilities
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -trimpath -o D:\temp\claude-swap-e2e\agent-linux .\cmd\agent
Remove-Item Env:GOOS, Env:GOARCH
```

Or from bash:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -o ./agent-linux ./cmd/agent
sha256sum ./agent-linux   # note this if you will serve the binary over HTTP
```

Use `GOARCH=arm64` for an ARM host. Copy the binary to the target host (`scp`, or a path WSL can see).

## Install

Copy `scripts/install-agent.sh` to the host, then:

```bash
export CLAUDESWAP_SERVER=https://swap.example:8443
export CLAUDESWAP_PIN=<64-hex-cert-sha256>
export CLAUDESWAP_AGENT_BIN=/path/to/agent-linux
read -rs CLAUDESWAP_ENROL_CODE && export CLAUDESWAP_ENROL_CODE   # no echo; omit for admin approval
bash scripts/install-agent.sh
unset CLAUDESWAP_ENROL_CODE
```

`read -rs` keeps the code out of your shell history and off the screen. Omit `CLAUDESWAP_ENROL_CODE` entirely to take the approval path instead.

To install for a particular local user instead of yourself, add `CLAUDESWAP_RUN_AS` and run it under `sudo -E`:

```bash
export CLAUDESWAP_RUN_AS=dadeush      # or root, or any other local account
sudo -E bash scripts/install-agent.sh
```

`sudo -E` is what carries the enrolment code (and the rest) through; without it `sudo` resets the environment and the install fails on a missing `CLAUDESWAP_SERVER`. The code still never appears on a command line, under `sudo` or across the switch to the run-as user: it travels only in the environment, because `/proc/<pid>/cmdline` is world-readable.

A sudoers policy with `env_reset` and no `SETENV` refuses `-E` outright — `sorry, you are not allowed to preserve the environment`. Start a root shell and set the variables inside it instead, which keeps the code off every command line just the same:

```bash
sudo -i
export CLAUDESWAP_SERVER=https://swap.example:8443 CLAUDESWAP_PIN=<64-hex> \
       CLAUDESWAP_AGENT_BIN=/path/to/agent-linux CLAUDESWAP_RUN_AS=dadeush
read -rs CLAUDESWAP_ENROL_CODE && export CLAUDESWAP_ENROL_CODE
bash /path/to/install-agent.sh
```

Flags, and only these two: `--system` forces a system unit when you are not root but can write `/etc/systemd/system`, and `--reconfigure` stops the existing unit before rewriting it. Everything else arrives in the environment, and an unknown argument is refused rather than ignored.

To fetch the binary rather than copy it, replace `CLAUDESWAP_AGENT_BIN` with both of:

```bash
export CLAUDESWAP_AGENT_URL=https://files.example/claude-swap/agent-linux
export CLAUDESWAP_AGENT_SHA256=<64-hex-sha256-of-that-file>
```

The download is refused unless the digest matches, and nothing is installed when it does not.

**See what it would do first:**

```bash
CLAUDESWAP_DRY_RUN=1 bash scripts/install-agent.sh
```

Every action prints as a `DRY-RUN:` line and nothing is executed, written or downloaded. The dry run also names the four decisions that are easy to get wrong:

```text
==> mode system (unit runs as User=dadeush Group=dadeush)
==> run as dadeush (uid 1001), home /srv/dadeush
==> state dir /srv/dadeush/.config/claude-swap-agent
==> unit /etc/systemd/system/claude-swap-agent.service
```

Note the home: it came from `getent passwd`, not from `/home/dadeush`. Read those four lines before the real run.

### What it does

| Step | Result |
|---|---|
| validate | rejects a non-`https` server, a pin that is not 64 hex chars, a URL without a sha256, a missing local binary, an unknown or service run-as user, an unwritable home |
| resolve | the run-as user, its **home from `getent passwd`** (never `/home/<name>`), the state dir, the unit path — all printed before anything is written |
| binary | `<home>/.local/bin/claude-swap-agent`, mode `0700`, replaced by atomic rename, chowned to the run-as user |
| state dir | `<home>/.config/claude-swap-agent`, mode `0700`, chowned to the run-as user |
| enrol | `agent enrol --server … --pin …` as the run-as user, skipped when `agent.json` already exists |
| unit (user mode) | `agent install` writes `<home>/.config/systemd/user/claude-swap-agent.service`, mode `0600` |
| unit (system mode) | the script writes `/etc/systemd/system/claude-swap-agent.service`, mode `0644`, with `User=`/`Group=`, `Restart=always`, `NoNewPrivileges=yes`, `PrivateTmp=yes` and **no `ProtectHome`** |
| start | user mode: `systemctl --user daemon-reload` then `enable --now`. System mode: `systemctl daemon-reload` then `enable --now` |

`ProtectHome` is deliberately absent. The agent's entire job is reading and rewriting `~/.claude.json` and `~/.claude/.credentials.json` in the run-as user's home; `ProtectHome=yes` would hide exactly that.

`CLAUDESWAP_STATE_DIR` is resolved once and exported, so enrolment and the unit's `Environment=` line always name the same directory. If a unit already exists, the script reads the directory **out of that unit** and keeps it — that is where the enrolment token lives, and a one-time code is spent. Override it only if you must, and never change it afterwards.

The binary and state dir are chowned to the run-as user whenever root installs for somebody else — **and so is every directory between the home and them.** `mkdir -p` under the installer's `umask 077` creates a missing `~/.local` or `~/.config` as `root:root 0700`, which that user cannot even traverse: the binary is then unexecutable and `agent.json` unreadable, and systemd reports both as a bare `status=203/EXEC` that names nothing. A fresh service account hits this every time, since nothing has created those directories yet. The walk up stops at the home and never uses `-R` on an ancestor, so the user's own `~/.local/share` is left alone.

**Re-running is safe.** The binary is replaced atomically (so a re-run works while the old one is executing), enrolment is skipped once `agent.json` exists — a one-time code is spent, and a second `enrol` with it would be denied — and the unit is rewritten in place.

### Switch an existing install

`--reconfigure` is the supported way to change the run-as user, or to move between a user unit and a system unit, without losing the enrolment:

```bash
sudo -E CLAUDESWAP_RUN_AS=dadeush bash scripts/install-agent.sh --reconfigure
```

It stops whichever unit is running (system **and** user — a mode switch could go either way), rewrites it, and keeps the state dir or copies `agent.json` into the new one. The host stays enrolled, so no new one-time code is needed.

### Keep it running when logged out

A **user** unit stops when your last session ends. Either enable linger:

```bash
loginctl enable-linger "$USER"
```

…or install a **system** unit, which starts at boot and needs no linger:

```bash
sudo -E bash scripts/install-agent.sh --system --reconfigure
```

Without either, the host simply shows offline in the admin UI between logins.

## Verify

A system unit (`sudo` path) — as root, plain `systemctl` is all you need:

```bash
systemctl is-enabled claude-swap-agent.service   # enabled
systemctl is-active claude-swap-agent.service    # active
systemctl restart claude-swap-agent.service      # works as root, no sudo -u dance
journalctl -u claude-swap-agent.service -n 30 --no-pager
systemctl show -p User -p Group claude-swap-agent.service
```

A user unit — export the session bus first, every time, in any shell that is not a fresh login:

```bash
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
systemctl --user is-enabled claude-swap-agent.service   # enabled
systemctl --user is-active claude-swap-agent.service    # active
journalctl --user -u claude-swap-agent.service -n 30 --no-pager
```

Either way, check the files in the **run-as user's** home, which `getent passwd <user> | cut -d: -f6` names:

```bash
ls -ld  "$(getent passwd dadeush | cut -d: -f6)/.config/claude-swap-agent"   # dir 0700
ls -l   "$(getent passwd dadeush | cut -d: -f6)/.local/bin/claude-swap-agent" # mode 0700, owned by that user
```

Then in the admin UI: the host appears **online**, with the identity from its `~/.claude.json` and **agent runs as `<user>`** on its card. If it is sitting in **Pending connections**, nobody has approved it yet — match the 8-character fingerprint the enrol step printed.

The logs never contain a token or an identity. If you see either, stop and report it.

## Durable tunnels

### Why

The server binds `127.0.0.1` only, so nothing on the LAN can reach it and the hosts open no
inbound port either. Each Linux host therefore reaches the server through a reverse SSH tunnel
that the **Windows machine running the server dials out**:

```text
Linux host 127.0.0.1:8443  ──(ssh -R)──>  Windows 127.0.0.1:8443  ──>  claude-swap server
```

The agent on the host is configured with `https://127.0.0.1:8443`; the tunnel is what makes that
address resolve to the server. No tunnel, no agent: the host logs `connection refused` and retries
with a growing backoff that reaches about a minute, so expect up to ~60 s of lag after a tunnel
comes back before the host reports `connected` again.

A hand-started `ssh -R` dies with its console and never comes back. The two scripts below make it
survive a dropped link, a host reboot and a logon.

> **The scripts are the interim arrangement.** The server supervises the same tunnels itself when
> it is started with `--tunnels`, which puts the key in the encrypted keyring instead of on disk and
> the state on the Tunnels tab. Run one or the other, never both — see
> [Moving to the app-managed supervisor](#moving-to-the-app-managed-supervisor). Everything from
> here to that section describes the scripts, and still applies while you are on them.

### The restricted key

The tunnels authenticate with one dedicated key that does nothing else:

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\id_ed25519_claudeswap" -C claude-swap-tunnel
icacls "$env:USERPROFILE\.ssh\id_ed25519_claudeswap" /inheritance:r /grant:r "$($env:USERNAME):(F)"
icacls "$env:USERPROFILE\.ssh\id_ed25519_claudeswap" /remove:g "BUILTIN\Administrators" "NT AUTHORITY\SYSTEM"
```

**The key has no passphrase, deliberately.** A logon task cannot type one, and an agent-held key
would not survive a reboot unattended. What makes that acceptable is that the key is useless for
anything but this one forward — see the options below — and that only the current Windows user can
read it. Never reuse this key, and never add it to another host.

When creating the key from PowerShell, do not pass `-N '""'`: PowerShell forwards that as a literal
two-character passphrase, and the key then fails to sign with `incorrect passphrase supplied`
*after* the server has already accepted it. Omit `-N` and press Enter twice, or pass a genuinely
empty argument. Check with `ssh-keygen -y -P '' -f <key>`, which must print the public key.

### authorized_keys options

On each host, append **one** line to `~/.ssh/authorized_keys` (`~/.ssh` mode `0700`, the file
`0600`). Keep any lines that are already there; the append is idempotent — skip it when the key
body is already present.

```text
command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:8443" ssh-ed25519 AAAA… claude-swap-tunnel
```

| Option | Effect |
|---|---|
| `command="/bin/false"` | any command or shell request runs `/bin/false` and exits 1 |
| `restrict` | denies agent forwarding, port forwarding, PTY, user rc and X11, plus anything added in a future OpenSSH |
| `port-forwarding` | re-enables forwarding only — it **must** come after `restrict`, which otherwise wins |
| `permitlisten="127.0.0.1:8443"` | the key may ask for that one remote listen address and no other |

No `sudo` is needed, and nothing under `~/.claude*` is touched.

Order matters: a later option overrides an earlier one, so `restrict` first and `port-forwarding`
second is the whole point of the line.

`port-forwarding` re-enables `-L` as well as `-R`, and `permitlisten` constrains only the `-R`
listen address, so a stolen key could still forward *out of* the host. Adding
`permitopen="127.0.0.1:1"` before `permitlisten` should close that:

```text
command="/bin/false",restrict,port-forwarding,permitopen="127.0.0.1:1",permitlisten="127.0.0.1:8443" ssh-ed25519 AAAA… claude-swap-tunnel
```

**Not verified.** Whether that leaves the `-R` forward working has not been tested on a real host,
so it is not what this runbook recommends yet. The app offers it the same way: generated, shown
behind a disclosure on the Tunnels tab, and applied to nothing. Changing a line on a host is always
the operator's own `ssh`; neither the scripts nor the server ever writes one.

### Scripts

| File | Job |
|---|---|
| `scripts/claude-swap-tunnels.ps1` | supervisor: one hidden `ssh.exe` per host, restarted 15 s after any exit, for as long as it runs |
| `scripts/install-tunnels-task.ps1` | registers, or with `-Uninstall` removes, the `claude-swap-tunnels` logon task |

Both take `-DryRun`, which prints every action and changes nothing. Neither file contains a host
address, a username or a password.

The host list lives **outside the repository**, at `%USERPROFILE%\.claude-swap\tunnels.json`,
ACL'd to the current user:

```json
[ { "name": "label-only", "host": "host.example.internal", "user": "someone" } ]
```

`name` is a label the log uses. `host` and `user` are read at task runtime and never logged: the
supervisor redacts them, and every IP literal other than loopback, out of anything it writes.

The log is `%USERPROFILE%\.claude-swap\tunnels.log`, one line per start and per exit with the
label, the pid, the exit code and a redacted reason. It rotates to `tunnels.log.1` at 1 MB, so it
has an explicit bound rather than growing forever.

The installer copies the supervisor next to the config and points the task at that copy, so the
task does not break when a git worktree is pruned. **Re-run the installer after you edit the
script.**

### Install

```powershell
# 1. write %USERPROFILE%\.claude-swap\tunnels.json by hand, then lock it down
icacls "$env:USERPROFILE\.claude-swap\tunnels.json" /inheritance:r /grant:r "$($env:USERNAME):(F)"

# 2. look before you leap
powershell -NoProfile -File scripts\claude-swap-tunnels.ps1 -DryRun
powershell -NoProfile -File scripts\install-tunnels-task.ps1 -DryRun

# 3. register and start
powershell -NoProfile -File scripts\install-tunnels-task.ps1
Start-ScheduledTask -TaskName claude-swap-tunnels
```

The task runs as the current user with `LogonType Interactive`, `RunLevel Limited`, hidden, no
execution time limit, and restarts on failure every minute. No password is stored.

Replacing older hand-started tunnels: find them by command line, not by name, and stop only those.

```powershell
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" |
  Where-Object { $_.CommandLine -match '-R 127\.0\.0\.1:8443:127\.0\.0\.1:8443' }
```

Other `ssh.exe` processes on the machine will not match. Inspect the matched set before stopping
anything, and redact the address if you print it.

### Verify

```powershell
(Get-ScheduledTask -TaskName claude-swap-tunnels).State          # Running
(Get-ScheduledTask -TaskName claude-swap-tunnels).Triggers       # MSFT_TaskLogonTrigger
Get-Content "$env:USERPROFILE\.claude-swap\tunnels.log" -Tail 5  # one 'tunnel start' per host
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" |
  Where-Object { $_.CommandLine -like '*id_ed25519_claudeswap*' } | Select-Object ProcessId
```

Then on each host:

```bash
systemctl --user is-active claude-swap-agent.service                       # active
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/         # 200
journalctl --user -u claude-swap-agent.service -n 5 --no-pager            # ends in "connected"
```

Prove the restriction holds, from the Windows side with the tunnel key:

```powershell
$k = "$env:USERPROFILE\.ssh\id_ed25519_claudeswap"
# a command or a shell: refused, exit 1 with no output (the forced /bin/false)
ssh -i $k -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey <user@host> id
# a PTY: "PTY allocation request failed on channel 0"
ssh -i $k -o IdentitiesOnly=yes -o BatchMode=yes -tt <user@host> id
# any other listen port: "remote port forwarding failed for listen port 18443"
ssh -i $k -o IdentitiesOnly=yes -o BatchMode=yes -o ExitOnForwardFailure=yes -N `
    -R 127.0.0.1:18443:127.0.0.1:8443 <user@host>
```

Always pass `-o PreferredAuthentications=publickey`. Without it a rejected key falls through to
password auth and you get a flat `Permission denied (publickey,password)`, which cannot be told
apart from the key never having authenticated at all.

Resilience: stop one of the tunnel `ssh.exe` processes and watch `tunnels.log`. A `tunnel exit`
line appears at once and a `tunnel start` line about 15-20 s later. The host's own agent then
reconnects on its next backoff tick, up to about a minute behind.

### Remove

```powershell
powershell -NoProfile -File scripts\install-tunnels-task.ps1 -Uninstall -DryRun
powershell -NoProfile -File scripts\install-tunnels-task.ps1 -Uninstall
```

That unregisters the task, stops only the processes it started — matched on the tunnel script name
and on the dedicated key file name — deletes `tunnels.json` and deletes the installed copy of the
supervisor. The log and the key are left behind; delete them by hand if you want them gone, and
drop the key's line from each host's `~/.ssh/authorized_keys`.

### Moving to the app-managed supervisor

The server started with `--tunnels` runs the same `ssh -R` children itself. What changes:

| | Scripts (interim) | `--tunnels` |
|---|---|---|
| Private key | `~\.ssh\id_ed25519_claudeswap`, one key for every host | one key per host, encrypted in `tunnelkeys.bin` beside the vault; written to a temp file for a child's lifetime only |
| Host list | `%USERPROFILE%\.claude-swap\tunnels.json` | the server's own state, seeded by **Import the interim host list** |
| Host key | whatever `known_hosts` the user has | recorded per tunnel; `StrictHostKeyChecking=yes` against a file the app writes |
| State | `tunnels.log` | the Tunnels tab, per host, with the last reason code |
| Lifetime | the logon task: that user, logged on, awake | the server process |

**Do not run both.** Two supervisors dial the same `-R 127.0.0.1:8443`; the second forward is
refused, so the app sits in `forward_refused` for ever while the task quietly keeps the link up.
Unregister the task first.

```powershell
# 1. look at what is running now, so you can tell an orphan from a new child later
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" |
  Where-Object { $_.CommandLine -like '*id_ed25519_claudeswap*' } | Select-Object ProcessId

# 2. keep a copy of the host list: -Uninstall deletes it, and the app's import reads it
Copy-Item "$env:USERPROFILE\.claude-swap\tunnels.json" "$env:USERPROFILE\.claude-swap\tunnels.json.bak"

# 3. stop the interim supervisor
powershell -NoProfile -File scripts\install-tunnels-task.ps1 -Uninstall -DryRun
powershell -NoProfile -File scripts\install-tunnels-task.ps1 -Uninstall

# 4. prove nothing is left holding the forward
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" |
  Where-Object { $_.CommandLine -like '*-R 127.0.0.1:8443*' }      # expect nothing
```

Step 4 matters: a hard kill of the old supervisor can leave an orphan `ssh.exe` that still owns the
listen address on the host. If one is matched, inspect it, then stop that pid alone.

Then restart the server with `--tunnels` and work the Tunnels tab, one host at a time:

1. **Import the interim host list** reads `tunnels.json` from the fixed path above and leaves the
   file where it is. The request cannot name a path; only `CLAUDESWAP_TUNNELS_JSON`, set on the
   server before it starts, points the import somewhere else.
2. **Record the host key.** Take it from the host itself — `ssh-keygen -lf
   /etc/ssh/ssh_host_ed25519_key.pub` prints the fingerprint, and the install command the tab
   generates ends with that same line. Until it is recorded the tunnel cannot start, by design.
3. **Generate a key**, then paste the install command the card shows on that host. This is a *new*
   key: the old `authorized_keys` line keeps working and is not touched by anything here.
4. **Start**, and wait for the card to read `up`. The host's own agent reconnects on its next
   backoff tick — within ~15 s when it is configured with a loopback server URL.
5. Only once that host is up, remove the old line by hand. The tab has no command for it: it belongs
   to the scripts' key, not to any key the app holds.

Rolling back is the same list in reverse: stop the tunnel in the app, re-run the installer with the
host list restored from the `.bak` copy, and start the task. The old line is still in place, which
is why step 5 comes last.

### Caveats

- **The key has no passphrase.** Mitigated, not eliminated, by `restrict`, `permitlisten` for the
  one address, `command="/bin/false"`, and an ACL that admits only the current Windows user.
- **The tunnels only run while that user is logged on and the machine is awake.** `LogonType
  Interactive` is what avoids storing a password; the price is that a locked-but-logged-on session
  keeps them up, a logged-off or sleeping machine does not. Hosts show offline in the admin UI for
  that whole window.
- **The server certificate pin is unaffected** by the tunnel, but a regenerated server certificate
  still invalidates every agent's `--pin`.
- **`ServerAliveInterval` does not catch every stall.** The unconditional restart loop, not the
  keepalive, is what actually keeps the tunnels up.

## Uninstall

A system unit, as root:

```bash
systemctl disable --now claude-swap-agent.service
rm -f /etc/systemd/system/claude-swap-agent.service
systemctl daemon-reload
h="$(getent passwd <user> | cut -d: -f6)"
rm -f  "$h/.local/bin/claude-swap-agent"
rm -rf "$h/.config/claude-swap-agent"   # drops the enrolment token: re-enrolling needs a new code
```

A user unit, as that user:

```bash
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
systemctl --user disable --now claude-swap-agent.service
rm -f ~/.config/systemd/user/claude-swap-agent.service
systemctl --user daemon-reload
rm -f ~/.local/bin/claude-swap-agent
rm -rf ~/.config/claude-swap-agent      # drops the enrolment token: re-enrolling needs a new code
loginctl disable-linger "$USER"         # only if you enabled it for this
```

Removing the host's own Claude credentials is **not** part of this. The agent never owned them, and nothing above touches `~/.claude`.

Also remove the host in the admin UI, so the server stops expecting it.

## Troubleshooting

**`run: … no such file or directory` and the service restarts in a loop.** The agent cannot find `agent.json`. Almost always the state dir differs between `enrol` and the unit. Read the file the agent writes for exactly this:

```bash
cat ~/.config/claude-swap-agent/agent-run.log
grep CLAUDESWAP_STATE_DIR ~/.config/systemd/user/claude-swap-agent.service
```

The log line names the directory it tried. Make that the directory enrolment wrote to — re-run the installer with the same `CLAUDESWAP_STATE_DIR` (or with none at all, which is the default for both), then `systemctl --user daemon-reload && systemctl --user restart claude-swap-agent.service`.

**Enrolment exits 2.** Denied. A one-time code is single use, and a denial records a retry-after that the agent honours before it will dial again. Get a fresh code, or use the approval path.

**`import refused` / the host shows no identity.** `~/.claude.json` has no `oauthAccount`. Sign in to Claude Code on the host once, then restart the service. Note the hub also refuses a login that is already stored: that is `ErrAlreadyStored`, not a failure of this install.

**Sessions never show up for this host.** The Linux scan reads `~/.claude/sessions/<pid>.json` and keeps a record only while `/proc/<pid>` shows a live process that looks like Claude Code — the marker `claude` in `comm` or in the command line. Two known limits:

- The producer's Linux `procStart` format is **unverified**. A value that is not a decimal clock-tick count is treated as no evidence and the session is still reported; a value that *is* numeric must equal `/proc/<pid>/stat` field 22, which is what rules out a reused pid. If a host reports no sessions while Claude Code is plainly running, compare the file's `procStart` against `awk '{print $22}' /proc/<pid>/stat`.
- A Claude Code process whose `comm` and command line never contain `claude` is not recognised. Check with `tr '\0' ' ' < /proc/<pid>/cmdline`.

**`Failed to connect to user scope bus via local transport: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined`.** Exactly what it says: `systemctl --user` needs both variables and this shell has neither. It happens over plain `su`, in `cron`, in a container, and whenever a command is piped into `bash`. Export them and retry:

```bash
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
systemctl --user status claude-swap-agent.service
```

If `/run/user/<uid>` does not exist, there is no user manager for that account at all — logind starts one on login, and keeps it only while the account is logged in or lingering. Either:

```bash
sudo loginctl enable-linger <user>        # then log in once, or wait for the manager
systemctl --user --machine=$(id -un)@.host status claude-swap-agent.service   # reach it via the host bus
```

…or stop fighting it and install a system unit, which needs no bus and no linger: `sudo -E bash scripts/install-agent.sh --system --reconfigure`.

**`Unit claude-swap-agent.service not found` when run as root.** You are looking in the wrong manager. A **user** unit lives in the user's own systemd instance, so `systemctl status claude-swap-agent.service` as root looks at the system manager, finds nothing and says so. Either address that user's manager:

```bash
sudo -u <user> XDG_RUNTIME_DIR=/run/user/$(id -u <user>) systemctl --user restart claude-swap-agent.service
```

…or convert the host to a system unit, after which plain `systemctl restart claude-swap-agent` is correct as root:

```bash
sudo -E CLAUDESWAP_RUN_AS=<user> bash scripts/install-agent.sh --system --reconfigure
systemctl restart claude-swap-agent
```

**`status=203/EXEC` right after a system install.** `User=<name>` cannot reach the binary. The file itself is the obvious suspect, but check the whole path — a `root:root 0700` directory anywhere along it stops that user just as dead:

```bash
h="$(getent passwd <user> | cut -d: -f6)"
namei -l "$h/.local/bin/claude-swap-agent"   # every component, with owner and mode
```

Every directory from the home down must be owned by that user (or at least traversable by them). Re-running the installer as root fixes the ownership; `namei` is how you confirm it did.

**The host shows the wrong user on its card.** `agent runs as <user>` comes from the agent's hello and refreshes on every reconnect, so restart the service after a `--reconfigure`. A blank value means the agent has not dialled in since the server started, or it predates the `runAs` field.

**`claude auth login` signed in, but the host still shows no identity.** The sign-in wrote `~/.claude.json` in *your* home, and the agent reads only the home it was installed for. Check which that is with `systemctl show -p User claude-swap-agent.service` (or `grep User= /etc/systemd/system/claude-swap-agent.service`), then sign in as that user. Running `claude auth login` as root only helps if the agent runs as root.

**The card says "No home directory".** The agent reported `no_home`: `HOME` is empty in its environment and `CLAUDE_CONFIG_DIR` is unset, so there is no `~/.claude.json` to read and no account to report. systemd passes **no** environment to a unit, so a system unit must carry it:

```bash
systemctl show -p Environment -p User claude-swap-agent.service   # expect HOME=<the user's home>
```

`scripts/install-agent.sh` already writes `Environment="HOME=$run_home"`, so a unit without it was written by hand or by an older installer — re-run the installer with `--system --reconfigure` rather than patching the unit. Keep `CLAUDESWAP_STATE_DIR` and `CLAUDE_CONFIG_DIR` identical at `enrol` and `run`, or `run` will not find `agent.json` either.

The same note applies to any wrapper that execs the agent: `env -i` or a `cron` entry leaves `HOME` unset.

What this check **cannot** catch is `HOME` pointing at the *wrong* home. systemd defaults a root service to `HOME=/root`, which resolves fine and simply has no login in it, so the host reads as "no identity" with no reason attached. `systemctl show -p User -p Environment` is still the answer; the user and the home must be the same person's.

Worth being explicit about what a swap then does to that user: it replaces **only** the `claudeAiOauth` block of that user's `~/.claude/.credentials.json`, leaving every other key (`mcpOAuth` among them) byte for byte, and it hands the rewritten file, the `.swap-backups` directory and the backups back to that user's uid and gid when the agent runs as root. It never touches `~/.claude.json`, which is why the card can keep showing the pre-swap account for a while.

**The service runs but the host stays offline.** The agent dials out and pins the certificate, so check the pin first — a wrong `--pin` fails every connection. Re-run the installer with the pin the server prints now; a regenerated server certificate changes it.

## Tests

`_verify/cases/install-agent-sh.sh` runs the installer in a throwaway `HOME` against stub `agent`, `systemctl`, `curl`, `id`, `getent`, `chown` and `runuser` binaries, over a fixture passwd file rather than the real `/etc/passwd`. It covers first run, idempotent re-run, dry run, rejected inputs, the sha256 mismatch, the `systemctl --user` exports and the `--machine` fallback, a missing `/run/user/<uid>`, root writing a system unit, root installing for an unprivileged user, a missing user, a nologin account and its override, an ordinary user refused another user, `--reconfigure` keeping the enrolment, and an assertion that the enrolment code reaches no log, unit, command line or output. It also checks that the directories *between* the home and the binary are handed over (the 203/EXEC trap), that the walk up stops at the home, and that a reconfigure which moves the state dir carries the swap journal with the token. 113 checks in all, plus `shellcheck -S style` over both files when shellcheck is installed.

It needs an unprivileged uid to own its temp homes and exits 77 when run as root. It is part of `bash _verify/run-all.sh`, and `CLAUDESWAP_SYSTEM_UNIT_DIR` and `CLAUDESWAP_RUNTIME_BASE` exist only so it can exercise the system-unit and missing-runtime-dir branches — never set them on a real host.

**Not verified on a real host:** the system unit has not started on a real machine, and no agent has run as a user other than the invoking one outside the stubs.
