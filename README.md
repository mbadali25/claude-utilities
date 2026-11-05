# claude-utilities

Go utilities for Claude Code. The first one is **claude-swap**: a LAN server plus a per-host agent that swaps Claude Code logins between accounts and shows each account's usage.

## Build

```
go build ./...
GOOS=linux go build -o claude-swap-agent ./cmd/agent
```

## Run

```
go run ./cmd/server --listen host:port   # on the LAN host
go run ./cmd/agent run                   # on each machine (the same `<exe> run` the login task starts)
```

`cmd/server` and `cmd/agent` are still being built.

Environment variables:

- `CLAUDESWAP_KEY`: passphrase for the server's account vault. Required for the server only; the agent does not use it.
- `CLAUDESWAP_STATE_DIR`: the agent's state directory (set by the installed unit).
- `CLAUDESWAP_ADMIN_PASSWORD`: password for the web UI.
- `CLAUDE_CONFIG_DIR`: where Claude Code keeps its credential file on a host (optional).

## Enrol an agent

The agent prints a fingerprint when it first connects. Open the server UI, match the fingerprint in **Pending connections**, then click Allow. An optional one-time code skips the manual match; how the agent is given the code and the server address is not decided yet (agent code is not written).

## Start the agent at login

`install.Install(exe, stateDir)` is a Go function, not a command. There is no CLI for it yet; the agent's `install` subcommand is not written, so the install flow cannot be run end to end today. It registers `<exe> run` (absolute path) as a `ClaudeSwapAgent` scheduled task on Windows (`/SC ONLOGON /IT /F /RL LIMITED`, run as `DOMAIN\user`, no password), or as `~/.config/systemd/user/claude-swap-agent.service` on Linux. The unit sets `CLAUDESWAP_STATE_DIR` to the state directory; the agent must read it (open item: agent run mode and how it finds the server are unresolved in the design). The schtasks call has not been run against a real Windows host.

Linux: run `loginctl enable-linger $USER` so it keeps running after you log out. The unit uses `Restart=always`.

Windows: the scheduled task does not match that. It stops after the default 72-hour execution limit, stops on battery power, and does not restart if the agent exits. Adjust these in Task Scheduler (task Settings tab) until the install sets them.

## Caveats

- A swap replaces only the `claudeAiOauth` block. `mcpOAuth` stays as it was, so MCP logins may still belong to the previous account.
- Swapping logins between accounts may breach Anthropic's terms of service. Check them before you use this; the risk is yours.

## Develop

```
go build ./...
go vet ./... && gofmt -l .
go test -race ./...
bash _verify/smoke.sh
```

## More

- Design: [docs/superpowers/specs/2026-11-04-claude-swap-design.md](docs/superpowers/specs/2026-11-04-claude-swap-design.md)
- Plan: [docs/superpowers/plans/2026-11-04-claude-swap.md](docs/superpowers/plans/2026-11-04-claude-swap.md)
- Security and threat model: [SECURITY.md](SECURITY.md)
