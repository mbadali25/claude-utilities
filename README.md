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
go run ./cmd/agent                       # on each machine
```

`cmd/server` and `cmd/agent` are still being built.

Environment variables:

- `CLAUDESWAP_KEY`: passphrase for the server's account vault. Required.
- `CLAUDESWAP_ADMIN_PASSWORD`: password for the web UI.
- `CLAUDE_CONFIG_DIR`: where Claude Code keeps its credential file on a host (optional).

## Enrol an agent

The agent prints a fingerprint when it first connects. Open the server UI, match the fingerprint in **Pending connections**, then click Allow. An optional one-time code skips the manual match.

## Start the agent at login

`install.Install` registers the agent: a `ClaudeSwapAgent` scheduled task on Windows, or `~/.config/systemd/user/claude-swap-agent.service` on Linux. On Linux, run `loginctl enable-linger $USER` so it keeps running after you log out.

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
