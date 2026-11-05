#!/usr/bin/env bash
# _verify/cases/go-checks.sh - build, vet, gofmt and test every Go package.
# Exit 0 = all green, 1 = a check failed, 77 = no Go toolchain (skipped, not verified).
# Go is native `go`, or `go.exe` by WSL interop on this Windows machine.
# readonly: yes
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

if command -v go >/dev/null 2>&1; then GO=go; GOFMT=gofmt
elif command -v go.exe >/dev/null 2>&1; then GO=go.exe; GOFMT=gofmt.exe
else echo "go not installed"; exit 77; fi

rc=0
"$GO" build ./... || { echo "FAIL go-build"; rc=1; }
"$GO" vet ./... || { echo "FAIL go-vet"; rc=1; }
o="$("$GOFMT" -l . 2>&1)"
[ -z "$o" ] || { echo "FAIL gofmt: $o"; rc=1; }
"$GO" test -count=1 ./... || { echo "FAIL go-test"; rc=1; }
exit "$rc"
