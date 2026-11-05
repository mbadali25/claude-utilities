# Runbooks

| Runbook | Use it when |
|---|---|
| [claude-swap-e2e.md](claude-swap-e2e.md) | Walking the whole server-plus-agents flow by hand, with Matthew at the keyboard. Steps marked **[LIVE CREDS]** touch a real credentials file. |
| [linux-agent-install.md](linux-agent-install.md) | Installing, verifying or removing the agent on a Linux host: build the binary, run `scripts/install-agent.sh`, enrol, systemd user unit, linger, troubleshooting. |
| [session-reload.md](session-reload.md) | A running Claude Code session still shows the old login after a swap and cannot reload it: the UI shows a Needs reload chip and a copyable restart command. |

The Windows host install has no runbook of its own yet. `scripts/install-agent.ps1` takes the same environment variables as the Linux script (`CLAUDESWAP_DRY_RUN=1` shows what it would do) and ends with `agent install`, which registers the `ClaudeSwapAgent` logon task. It refuses to run with `CLAUDESWAP_STATE_DIR` set, because `schtasks` passes no environment and the task could only ever use the default state dir.

Rules that hold in every runbook here:

- Never paste, print, log or commit a token. Check credential files by existence, size and key names only.
- Keep `CLAUDESWAP_STATE_DIR` (and `CLAUDE_CONFIG_DIR`, if you set it at all) identical for `enrol` and for whatever starts `run`. A state dir set only at enrol makes `run` report a missing `agent.json`; see the `agent-run.log` entry in the Linux runbook.
- Do not set `CLAUDE_CONFIG_DIR` for a real host's default profile. It is for a sandbox config dir only.
