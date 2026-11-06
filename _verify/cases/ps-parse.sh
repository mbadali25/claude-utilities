#!/usr/bin/env bash
# _verify/cases/ps-parse.sh - parse-only syntax check of the repo's PowerShell scripts.
# Exit 0 = all parse, 1 = a parse error or missing file, 77 = no PowerShell available (skipped, not verified).
# pwsh/powershell native, or pwsh.exe/powershell.exe by WSL interop on this Windows machine.
# readonly: yes
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

for c in pwsh pwsh.exe powershell.exe powershell; do
  if command -v "$c" >/dev/null 2>&1; then PS="$c"; break; fi
done
[ -n "${PS:-}" ] || { echo "no PowerShell available"; exit 77; }

FILES=(scripts/claude-swap-tunnels.ps1 scripts/install-tunnels-task.ps1 scripts/install-agent.ps1 scripts/start-server.ps1)
"$PS" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File _verify/cases/ps-parse.ps1 "${FILES[@]}"
