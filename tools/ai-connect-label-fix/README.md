# ai-connect label fix

Removes `name_mode: per-project` from the peer's `config.yaml` so the Bridge server assigns
unique labels (for example `dadeush-buntun` and `dadeush-buntun-TheSelectSource`).

Assumes a Linux peer host with `~/.config/ai-connect/config.yaml` (override with `--config` or `AI_CONNECT_CONFIG`).
It only touches that one file, backs it up first, and never reads tokens.

```bash
git clone https://github.com/mbadali25/claude-utilities.git
cd claude-utilities && git checkout fix/ai-connect-buntun-labels
bash tools/ai-connect-label-fix/fix-labels.sh --dry-run   # preview
bash tools/ai-connect-label-fix/fix-labels.sh             # apply
```

It prints the rollback command (`cp -p <backup> <config>`) and a verified result. It warns if
`AI_CONNECT_PEER_NAME` or `AI_CONNECT_PEER_SUFFIX` is set; remove those yourself.
Restart the MCP service or session afterwards. Re-running is a no-op.
