# Install the claude-swap agent on a Linux host

## Quick start

1. On a build machine run `GOOS=linux go build -o agent-linux ./cmd/agent` and copy `agent-linux` to the host.
2. Set these environment variables (never flags):
   - `CLAUDESWAP_SERVER`: the server URL, `https://host:port`.
   - `CLAUDESWAP_PIN`: the server certificate sha256 printed at server start (64 hex characters).
   - `CLAUDESWAP_ENROL_CODE`: the one-time code from the admin UI. Optional; without it an admin must approve the host.
   - `CLAUDESWAP_AGENT_BIN`: the path to the `agent-linux` file you copied.
3. Run `CLAUDESWAP_DRY_RUN=1 scripts/install-agent.sh` first, then run `scripts/install-agent.sh` without the dry-run flag.
4. Approve the host in the server UI (not needed when a valid one-time code was used).

**Not yet verified on a real host.** The installer and the Linux session scan have not run on a real host, and the `/proc` start-time (`procStart`) format is unverified. Targets are TSS and SRL-LIN, to be run by Matthew himself.

One script does the whole install: `scripts/install-agent.sh`. It copies or downloads the agent binary, enrols the host, writes a systemd **user** unit and starts it. Every input arrives in the environment, never as a flag, because an enrolment code on a command line is readable by every user on the host through `/proc/<pid>/cmdline`.

Never paste, print, log or commit a token. Do not `cat` a credentials file or a backup; check files by existence, size and key names only.

## Prerequisites

On the Linux host:

- **`~/.claude.json` with an `oauthAccount` object** (an email address, else an account uuid). The agent reads the signed-in identity from it. A host without it can connect but cannot import its login, and the hub refuses the import.
- **Claude Code installed and signed in at least once**, which is what creates `~/.claude.json` and `~/.claude/.credentials.json`.
- **`CLAUDE_CONFIG_DIR` must NOT be set** for the default profile. Set it only for a sandbox config dir — and then keep it identical for `enrol` and for the unit, exactly as with `CLAUDESWAP_STATE_DIR`. The install script never sets it.
- **systemd with a user manager** (`systemctl --user` works). Without it the script still installs and enrols, and tells you to run `agent run` yourself.
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

Every action prints as a `DRY-RUN:` line and nothing is executed, written or downloaded.

### What it does

| Step | Result |
|---|---|
| validate | rejects a non-`https` server, a pin that is not 64 hex chars, a URL without a sha256, a missing local binary |
| binary | `~/.local/bin/claude-swap-agent`, mode `0700`, replaced by atomic rename |
| state dir | `$XDG_CONFIG_HOME/claude-swap-agent` (so `~/.config/claude-swap-agent`), mode `0700` |
| enrol | `agent enrol --server … --pin …`, skipped when `agent.json` already exists |
| unit | `agent install` writes `~/.config/systemd/user/claude-swap-agent.service`, mode `0600` |
| start | `systemctl --user daemon-reload`, then `systemctl --user enable --now claude-swap-agent.service` |

`CLAUDESWAP_STATE_DIR` is resolved once and exported, so enrolment and the unit's `Environment=` line always name the same directory. Override it only if you must, and never change it afterwards.

**Re-running is safe.** The binary is replaced atomically (so a re-run works while the old one is executing), enrolment is skipped once `agent.json` exists — a one-time code is spent, and a second `enrol` with it would be denied — and the unit is rewritten in place.

### Keep it running when logged out

A user unit stops when your last session ends. To keep the agent up:

```bash
loginctl enable-linger "$USER"
```

Without this the host simply shows offline in the admin UI between logins.

## Verify

```bash
systemctl --user is-enabled claude-swap-agent.service   # enabled
systemctl --user is-active claude-swap-agent.service    # active
journalctl --user -u claude-swap-agent.service -n 30 --no-pager
ls -l ~/.config/claude-swap-agent      # agent.json, mode 0600, dir 0700
ls -l ~/.local/bin/claude-swap-agent   # mode 0700
```

Then in the admin UI: the host appears **online**, with the identity from its `~/.claude.json`. If it is sitting in **Pending connections**, nobody has approved it yet — match the 8-character fingerprint the enrol step printed.

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

```bash
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

**`systemctl --user` fails with "Failed to connect to bus".** No user manager in this session (common over plain `su` or in a minimal container). Log in properly, or run the agent in the foreground with `~/.local/bin/claude-swap-agent run` to confirm the install first.

**The service runs but the host stays offline.** The agent dials out and pins the certificate, so check the pin first — a wrong `--pin` fails every connection. Re-run the installer with the pin the server prints now; a regenerated server certificate changes it.

## Tests

`_verify/cases/install-agent-sh.sh` runs the installer in a throwaway `HOME` against stub `agent`, `systemctl` and `curl` binaries: first run, idempotent re-run, dry run, rejected inputs, the sha256 mismatch, and an assertion that the enrolment code reaches no log, unit or output. It is part of `bash _verify/run-all.sh`.
