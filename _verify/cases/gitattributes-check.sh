#!/usr/bin/env bash
# _verify/cases/gitattributes-check.sh - .gitattributes must pin Go and shell files to LF,
# and the Go tree must still be gofmt-clean. Exit 0 = ok, 1 = wrong, 77 = no git/gofmt.
# readonly: yes
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

command -v git >/dev/null 2>&1 || { echo "git not installed"; exit 77; }
if command -v gofmt >/dev/null 2>&1; then GOFMT=gofmt
elif command -v gofmt.exe >/dev/null 2>&1; then GOFMT=gofmt.exe
else echo "gofmt not installed"; exit 77; fi

rc=0
for f in x.go x.sh; do
  v="$(git check-attr eol -- "$f" | sed 's/^.*: //' | tr -d '\r')"
  [ "$v" = "lf" ] || { echo "FAIL .gitattributes: eol for $f is '$v', want 'lf'"; rc=1; }
done
o="$("$GOFMT" -l cmd internal 2>&1)"
[ -z "$o" ] || { echo "FAIL gofmt: $o"; rc=1; }
exit "$rc"
