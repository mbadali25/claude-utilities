# claude-swap end-to-end runbook (plan Task 11)

Run with Matthew at the keyboard. Steps marked **[LIVE CREDS]** touch a real `.credentials.json`; do not run them without his go-ahead. Everything else uses temp dirs and fake credentials.

Never paste, print, log or commit a token. Never `cat` a credentials file or a backup. Check files by existence, size and key names only.

Binaries (built from branch `claude-swap/design`, no install done): `D:\temp\claude-swap-e2e\`
- `server.exe`, `agent.exe` (Windows)
- `server-linux`, `agent-linux` (Linux; also used inside WSL)

Host prerequisites:
- Each host needs `~/.claude.json` with an `oauthAccount` object (email, else account uuid). The agent reads the signed-in identity from it, and a host without it cannot import. For a sandbox config dir, create `<CLAUDE_CONFIG_DIR>/.claude.json` with a fake `oauthAccount` (for example `{"oauthAccount":{"emailAddress":"fake-a@example.invalid"}}`).
- Do not set `CLAUDE_CONFIG_DIR` for the default profile (real hosts). Set it only for a sandbox config dir, and keep `CLAUDESWAP_STATE_DIR` and `CLAUDE_CONFIG_DIR` identical at `enrol` and `run`.

Placeholders: `<LAN_IP>` = the Windows desktop's LAN address; `<PORT>` = e.g. 8443.

## 0. Pre-flight (do first, every host)

### 0.1 [LIVE CREDS] Back up each host's credentials file to a private path

Copy only; never display.

Windows (PowerShell):
```powershell
$bk = "$env:USERPROFILE\claude-swap-preflight"
New-Item -ItemType Directory -Force $bk | Out-Null
icacls $bk /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" | Out-Null
Copy-Item "$env:USERPROFILE\.claude\.credentials.json" "$bk\credentials.$(Get-Date -f yyyyMMddTHHmmss).json"
Get-ChildItem $bk | Select Name, Length
```

Linux, WSL, laptop (bash):
```bash
umask 077
mkdir -p ~/claude-swap-preflight && chmod 700 ~/claude-swap-preflight
cp -p ~/.claude/.credentials.json ~/claude-swap-preflight/credentials.$(date +%Y%m%dT%H%M%S).json
ls -l ~/claude-swap-preflight
```
Each WSL install has its own `~/.claude`. Real hosts should not have `CLAUDE_CONFIG_DIR` set (see Host prerequisites); if one does, use that directory instead.

Do not put the backup folder inside a git repo or a synced folder. Delete it after Step 6 passes.

### 0.2 Confirm the builds and tests
```powershell
cd C:\repos\personal\claude-utilities
go test -race -count=1 ./...
Get-ChildItem D:\temp\claude-swap-e2e
```
Last run: all 13 packages pass on Windows.

### 0.3 Know the facts the UI depends on
- The server prints `server: listening on https://<addr>  certificate sha256=<HEX>`. Copy that HEX; agents need it as `--pin`.
- The certificate is self-signed; the browser will warn. Accept it for the e2e.
- Agents dial out only. No inbound ports on hosts. The Windows firewall must allow inbound TCP `<PORT>` on the server host.

## 1. Sandbox phase (fake credentials only)

### 1.1 Make fake credential files

Use two fake blocks with a future `refreshTokenExpiresAt` and any `mcpOAuth` content (fake). Build them with a script; the values must be obvious fakes (`FAKE-ACCESS-A`). Put each in a temp config dir:

- Windows: `D:\temp\claude-swap-e2e\cfg-win\.credentials.json`
- WSL: `~/cfg-wsl/.credentials.json`
- Laptop: `~/cfg-laptop/.credentials.json`

Shape: `{"claudeAiOauth":{"accessToken":"FAKE-ACCESS-A","refreshToken":"FAKE-REFRESH-A","expiresAt":<future ms>,"refreshTokenExpiresAt":<future ms>,"scopes":["user:inference"],"subscriptionType":"max","subscriptionTypeSource":"x","rateLimitTier":"x"},"mcpOAuth":{"fake-server":{"note":"keep me exactly"}}}`

Record the hash of `mcpOAuth` for later (hash, not content):
```powershell
$j = Get-Content D:\temp\claude-swap-e2e\cfg-win\.credentials.json -Raw | ConvertFrom-Json
($j.mcpOAuth | ConvertTo-Json -Depth 20 -Compress) | % { [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($_))) }
```
(Fake data only, so this is safe to print. Never run this against a real file.)

### 1.2 Start the server (sandbox)
```powershell
$env:CLAUDESWAP_KEY = "<test passphrase, not a real one>"
$env:CLAUDESWAP_ADMIN_PASSWORD = "<test UI password>"
D:\temp\claude-swap-e2e\server.exe --listen <LAN_IP>:<PORT> --data-dir D:\temp\claude-swap-e2e\data
```
- `--listen` is required and has no default. `--data-dir` holds `vault.bin`, `hosts.json`, `tls/`.
- Expect the `listening on https://...` line with the certificate sha256. Keep this window open; logs go to stderr.
- Exit 2 means a missing flag or env var; exit 1 is a runtime failure; exit 4 means this binary cannot read the format of `vault.bin` in `<data-dir>` — either it was written by a newer server (the stderr line says `reason=newer-format`; run `server vault downgrade` on that newer binary) or it is malformed (`reason=malformed`: a bad magic, a truncated file, or a v2 header whose numbers are out of bounds; restore `vault.bin` from a copy). Both print one `format` line on stderr with that `reason` and nothing else — never a path or a file byte. A restart cannot make either readable, so do not retry it, and do **not** rotate the passphrase: exit 4 never means a wrong key. Exit 5 means the server refused the TLS pair in `<data-dir>\tls` — one file of two, unreadable, unparseable, key and certificate mismatched, or expired. It never regenerates the pair, because that would change the sha256 every enrolled agent pins: fix the permissions, or run `server cert renew` and re-enrol the agents on the new pin.
- Open `https://<LAN_IP>:<PORT>/` and log in with the admin password.
- `CLAUDESWAP_ADMIN_PASSWORD` is only the bootstrap password: it works while no `admin-password.json` exists in the data dir. Once a password is set, the stored argon2id hash wins and the variable is ignored (the server also starts without it).
- Change the password offline: `go run ./cmd/server set-password [--data-dir DIR]` (or `server.exe set-password`). It prompts twice with echo off on a terminal, or reads one line from stdin when piped; minimum 12 characters; never an argument. A running server reads the hash at startup, so restart it for the new password to apply.
- Change it in the UI: **Account** (top right) > **Change password**, which opens the **Admin password** dialog (current password plus new password, 12+ characters). A successful change ends every signed-in session, this one included; sign in again with the new password. A wrong current password counts toward the login rate limit.
- Sign out from the same menu: **Account** > **Log out** ends only this session and returns to the sign-in page. Other signed-in sessions keep working; only a password change ends them all.

### 1.3 Enrol agent on Windows via Pending connections
```powershell
$env:CLAUDE_CONFIG_DIR = "D:\temp\claude-swap-e2e\cfg-win"
$env:CLAUDESWAP_STATE_DIR = "D:\temp\claude-swap-e2e\state-win"
D:\temp\claude-swap-e2e\agent.exe enrol --server https://<LAN_IP>:<PORT> --pin <CERT_SHA256_HEX>
```
- The agent prints `Fingerprint: <fp>`. In the UI, find the same fingerprint under **Pending connections** and click **Allow** only if they match.
- Agent prints `Enrolled. Start the agent with: agent run`. Exit 0 = enrolled, 1 = error, 2 = denied.
- Entry expires after 10 minutes; re-run `enrol` if it lapses.
- Then, in the same shell (same env vars): `D:\temp\claude-swap-e2e\agent.exe run`. The host appears in Hosts and goes Online.

The agent reads `CLAUDESWAP_STATE_DIR` and `CLAUDE_CONFIG_DIR` at `enrol` and at `run`; keep them identical for both.

### 1.4 Enrol WSL (Allow menu) and laptop (one-time code)
Copy `agent-linux` to each host (`chmod +x`). WSL reaches the Windows server by `<LAN_IP>` (or the WSL host gateway address); confirm with `curl -k https://<LAN_IP>:<PORT>/` first.

WSL:
```bash
export CLAUDE_CONFIG_DIR=~/cfg-wsl CLAUDESWAP_STATE_DIR=~/state-wsl
./agent-linux enrol --server https://<LAN_IP>:<PORT> --pin <CERT_SHA256_HEX>
# match fingerprint, Allow in the UI, then:
./agent-linux run
```

Laptop (one-time code path): in the UI click **New enrolment code** (single use, 10 minutes). Pass it by environment, never as a flag:
```bash
export CLAUDE_CONFIG_DIR=~/cfg-laptop CLAUDESWAP_STATE_DIR=~/state-laptop
CLAUDESWAP_ENROL_CODE='<code>' ./agent-linux enrol --server https://<LAN_IP>:<PORT> --pin <CERT_SHA256_HEX>
./agent-linux run
```
Expect it enrolled without a Pending entry.

### 1.5 Deny drill
Start a fourth throwaway agent with its own state dir, click **Deny**, confirm exit code 2 and "Do not retry for ...". Re-run `enrol`: it should create a fresh fingerprint on a fresh nonce, per spec, so also confirm that re-dialling the same attempt is not listed (the suppression is by fingerprint for 1 hour). Record what you actually see.

### 1.6 Import the fake accounts
For each fake credential on a host, open **Account** > **Add Claude account** and, in **Add account: import from a logged-in host**, pick the host, type a label (`FakeA`, then change the file on another host to block B and import `FakeB`), click Import. Labels are unique, 1-64 characters. The account appears with an error state in usage (fake token): the page must not break.

### 1.7 Swap A to B on each host and verify
UI: Hosts table, pick the account in **Swap to**, click **Swap**.
Check, per host, without printing secrets:
- `mcpOAuth` hash identical to the 1.1 hash.
- Backup exists: `<config dir>\.swap-backups\*.json` (up to 5 kept, mode 0600 on Linux). List names only.
- No `swap-journal.json` left in the state dir.
- Hosts table shows **Needs reload** on any host with sessions. Start a dummy `claude` process if no session exists, or note that the badge shows only with sessions.
- Usage panel shows an error for the fake token and the page still loads.

### 1.8 Failure drills
- Kill the agent mid-swap (start a swap, `Stop-Process`/`kill -9` the agent). Restart `agent run`: it reads `swap-journal.json` and restores from the backup. Check `.credentials.json` equals the pre-swap block by hash.
- Stop the server (Ctrl+C). The agent should reconnect with backoff when it comes back.
- Start the server with a wrong `CLAUDESWAP_KEY`: it must refuse to start and leave `vault.bin` unchanged (compare file hash and size before and after).

## 2. Real hosts (Matthew present)

Only after Section 1 passes. Pick one real host and one real account.

### 2.1 [LIVE CREDS] Confirm the 0.1 backup exists
List the backup folder. Stop if it is missing.

### 2.2 [LIVE CREDS] Restart the server with real data
Stop the sandbox server. Use a new data dir and a real passphrase held by Matthew (record it somewhere private; losing it means re-importing every account):
```powershell
$env:CLAUDESWAP_KEY = "<real passphrase>"
$env:CLAUDESWAP_ADMIN_PASSWORD = "<real UI password>"
D:\temp\claude-swap-e2e\server.exe --listen <LAN_IP>:<PORT> --data-dir <private data dir>
```

### 2.3 [LIVE CREDS] Enrol the real host
Unset `CLAUDE_CONFIG_DIR` so the default `~/.claude` is used; use a real state dir.
```powershell
Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue
$env:CLAUDESWAP_STATE_DIR = "$env:LOCALAPPDATA\claude-swap-agent-e2e"   # or leave unset for the default
D:\temp\claude-swap-e2e\agent.exe enrol --server https://<LAN_IP>:<PORT> --pin <CERT_SHA256_HEX>
```
Match the fingerprint, Allow, then `agent.exe run`. Do **not** run `agent install` during this e2e; the install path is untested on a real host (see Unverified).

### 2.4 [LIVE CREDS] Import the live account
In the UI, Import from the real host with a label (for example `Main`). This uploads the live `claudeAiOauth` block to the server vault. Confirm `Main` appears with real usage numbers (5-hour, weekly, reset time).

Import a second real account the same way from a host logged in to it, so there is something to swap to. A swap needs the live account to be a known account; otherwise the swap is refused and asks you to import first.

### 2.5 [LIVE CREDS] Swap
Hosts table, choose the second account, click **Swap**. Then:
1. Confirm the host shows the new Active account.
2. Check the **Needs reload** badge on the host and on each running session.
3. In an open Claude Code session run `/reload-plugins` or restart it; in a fresh terminal run `claude` and confirm it starts and shows the new account. Sessions keep the old token in memory until restarted (spec, Risks).

### 2.6 [LIVE CREDS] Swap back
Swap the same host back to the first account. Confirm Claude Code starts. Record results (host, accounts by label, pass/fail, timings). No tokens in the notes. Write them to `docs/superpowers/e2e-results.md`.

## 3. Rollback

Pick the lightest that applies.

1. **Swap returned an error or the agent restored itself.** The agent validates, journals, replaces, reads back, and restores the backup on a failed read-back. Check the server log and the host's `swap-journal.json` is gone. Nothing else to do.
2. **Agent or host died mid-swap.** Start `agent run` again. On start it settles the journal: if the live block is the new one it restores the pre-swap backup; if it is still the old one it drops the journal. A journal with no matching backup stays and the agent reports "interrupted swap and no matching backup": go to 4.
3. **Wrong account but file is valid.** Swap back from the UI.
4. **[LIVE CREDS] Manual restore** (file damaged, or Claude Code will not start). Stop the agent first so it cannot write mid-restore. Then copy the pre-flight file back (Section 0.1 path), do not open it:
   ```powershell
   Copy-Item "$env:USERPROFILE\claude-swap-preflight\credentials.<stamp>.json" "$env:USERPROFILE\.claude\.credentials.json" -Force
   ```
   ```bash
   cp -p ~/claude-swap-preflight/credentials.<stamp>.json ~/.claude/.credentials.json && chmod 600 ~/.claude/.credentials.json
   ```
   Note: the pre-flight copy is a full file. If Claude Code refreshed its token since, the refresh token may have rotated and the copy may be stale; if Claude Code reports "Login expired", run `/login` again.
5. **Last resort.** `/login` in Claude Code on the host. Nothing in claude-swap is needed to recover.

Also: remove a bad host in the UI with **Revoke**; stop the agent with Ctrl+C or by killing the process.

## 4. Clean up
- Stop agents and the server.
- Delete `D:\temp\claude-swap-e2e\data`, `state-*`, `cfg-*`, `~/cfg-*`, `~/state-*` (all fake).
- Delete the pre-flight backups only after Matthew confirms every real host logs in.
- Unset `CLAUDESWAP_KEY`, `CLAUDESWAP_ADMIN_PASSWORD`, `CLAUDESWAP_ENROL_CODE`.

## Unverified at time of writing
- `agent install` (schtasks, icacls, systemd unit) has never run against a real host; tests use a fake runner. Not part of this run.
- The README still says `cmd/agent` does not exist and that there is no `install` subcommand; that is out of date (the subcommand exists in `cmd/agent/main.go`).
- Whether WSL can reach the Windows server by `<LAN_IP>` depends on the WSL network mode; test with `curl -k`.
- Exact session discovery and "needs reload" behaviour on a live Claude Code process is untested on real hosts.
- Token refresh is not implemented on the server (`usage` shows "unauthorized" for expired tokens); an account idle for long may need a re-import.
- The Linux default state dir (when `CLAUDESWAP_STATE_DIR` is unset) is `~/.config/claude-swap-agent`; not exercised here.
