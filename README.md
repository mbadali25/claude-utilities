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

`install.Install(exe, stateDir)` is a Go function, not a command. There is no CLI for it yet; the agent's `install` subcommand is not written, so the install flow cannot be run end to end today. `cmd/agent` does not exist, so nothing reads `CLAUDESWAP_STATE_DIR` yet; the agent must read it (open item: agent run mode and how it finds the server are unresolved in the design).

- Windows: creates the state directory with an owner-only ACL (`icacls /inheritance:r`), then registers `ClaudeSwapAgent` from a task XML via `schtasks /Create /F /XML`. The task runs at logon as `DOMAIN\user` in the interactive session (no password), sets `CLAUDESWAP_STATE_DIR` through a `cmd /c set ...` wrapper, has no execution time limit, keeps running on battery, and restarts on failure (every minute, up to 999 times). The paths must not contain `"` `%` `&` `^` `!` `<` `>` or `|`. The state directory is locked to the current user, so SYSTEM and Administrators lose access to it (back it up as that user). Tests cover the XML and the command sequence with a fake runner; schtasks and icacls have not been run against a real Windows host.
- Linux: writes `~/.config/systemd/user/claude-swap-agent.service` (`Restart=always`, starts after `network-online.target`, sets `CLAUDESWAP_STATE_DIR`) and creates the state directory with mode 0700. The install refuses a state directory that is a symlink or junction when it checks (a race between the check and the chmod is not prevented) or that contains a line break. Run `loginctl enable-linger $USER` so it keeps running after you log out.
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
