# Security

## Threat model

claude-swap is for a trusted LAN only. The server is never exposed to the internet; agents dial out to it and open no inbound ports. Anyone who can reach the server on the LAN is inside the trust boundary, so do not publish its port beyond the LAN.

## Tokens

- Account tokens are never logged, shown in the UI, put in error messages or passed in process arguments. Logs emit allowlisted keys only.
- Account tokens are stored encrypted at rest. The key comes from the `CLAUDESWAP_KEY` environment variable at start. Losing the key means re-logging every account.
- A swap replaces only the `claudeAiOauth` block of a host's credentials and keeps everything else, including `mcpOAuth`.
- Each agent holds its own token, stored hashed on the server and revocable from the UI.

## Reporting

Report a vulnerability privately to the repository owner, not in a public issue. Do not include a live token in the report.
