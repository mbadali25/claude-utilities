#!/usr/bin/env bash
# _verify/cases/install-agent-sh.sh - exercise scripts/install-agent.sh against
# stub `agent` and `systemctl` binaries in a throwaway HOME. No bats, no network,
# and nothing outside the temp dir is read or written: the real ~/.local/bin,
# the real unit dir and the real state dir are never touched.
# Exit 0 = all green, 1 = a check failed, 77 = no bash/shellcheck environment.
# readonly: yes
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
ROOT="$PWD"
SCRIPT="$ROOT/scripts/install-agent.sh"

# run-all.sh calls every case with --env <name>; this case is environment-free.
while [ $# -gt 0 ]; do
  case "$1" in
    --env) shift 2 || shift ;;
    --env=*) shift ;;
    *) shift ;;
  esac
done

[ -f "$SCRIPT" ] || { echo "FAIL install-agent.sh is missing"; exit 1; }
command -v mktemp >/dev/null 2>&1 || { echo "mktemp not installed"; exit 77; }

rc=0
fail() { echo "FAIL $*"; rc=1; }
ok() { echo "ok   $*"; }

# check/refute take a label and a command, so a passing assertion can never
# fall through into the failure branch (which `A && ok || fail` allows).
check() { local label="$1"; shift; if "$@"; then ok "$label"; else fail "$label"; fi; }
refute() { local label="$1"; shift; if "$@"; then fail "$label"; else ok "$label"; fi; }
# shellcheck disable=SC2329  # called indirectly, as the command argument of check
mode_is() { [ "$(stat -c '%a' "$1" 2>/dev/null || echo '?')" = "$2" ]; }

TMP="$(mktemp -d)" || { echo "cannot create a temp dir"; exit 77; }
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------------ stubs

STUB="$TMP/stub"
mkdir -p "$STUB"

# A stub agent that records how it was called and mimics the real subcommands:
# `enrol` writes agent.json, `install` writes the systemd user unit.
cat >"$STUB/fake-agent" <<'STUBEOF'
#!/usr/bin/env bash
set -euo pipefail
log="${STUB_LOG:?STUB_LOG unset}"
printf '%s %s\n' "$1" "${*:2}" >>"$log"
# Record whether the secret reached us, without ever writing the secret itself.
if [ -n "${CLAUDESWAP_ENROL_CODE:-}" ]; then printf 'code-present %s\n' "$1" >>"$log"; fi
printf 'state-dir %s %s\n' "$1" "${CLAUDESWAP_STATE_DIR:-<unset>}" >>"$log"
if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then printf 'config-dir-set %s\n' "$1" >>"$log"; fi
case "$1" in
  enrol)
    mkdir -p "$CLAUDESWAP_STATE_DIR"
    printf '{"serverUrl":"x","token":"t"}\n' >"$CLAUDESWAP_STATE_DIR/agent.json"
    ;;
  install)
    mkdir -p "$CLAUDESWAP_STATE_DIR" "$HOME/.config/systemd/user"
    chmod 0700 "$CLAUDESWAP_STATE_DIR"
    unit="$HOME/.config/systemd/user/claude-swap-agent.service"
    { echo '[Service]'
      echo "ExecStart=\"$0\" run"
      echo "Environment=\"CLAUDESWAP_STATE_DIR=$CLAUDESWAP_STATE_DIR\""; } >"$unit"
    chmod 0600 "$unit"
    ;;
esac
STUBEOF
chmod 0755 "$STUB/fake-agent"

cat >"$STUB/systemctl" <<'STUBEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"${STUB_LOG:?}"
STUBEOF
chmod 0755 "$STUB/systemctl"

export PATH="$STUB:$PATH"
PIN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SECRET=super-secret-one-time-code

# invoke <home> -- run the installer in an isolated HOME. Only the variables
# the script documents are exported; CLAUDE_CONFIG_DIR is never set.
invoke() {
  env -i \
    PATH="$PATH" \
    HOME="$1" \
    STUB_LOG="$STUB_LOG" \
    CLAUDESWAP_SERVER="https://swap.example:8443" \
    CLAUDESWAP_PIN="$PIN" \
    CLAUDESWAP_ENROL_CODE="$SECRET" \
    CLAUDESWAP_AGENT_BIN="$STUB/fake-agent" \
    ${CLAUDESWAP_DRY_RUN:+CLAUDESWAP_DRY_RUN="$CLAUDESWAP_DRY_RUN"} \
    bash "$SCRIPT"
}

# ------------------------------------------------------------- 1. first run

H1="$TMP/home1"
mkdir -p "$H1"
STUB_LOG="$TMP/log1"
: >"$STUB_LOG"
if out="$(invoke "$H1" 2>&1)"; then ok "first run exits 0"; else
  fail "first run exited non-zero"; printf '%s\n' "$out" | sed 's/^/     | /'
fi
printf '%s\n' "$out" >"$TMP/out1"

sdir="$H1/.config/claude-swap-agent"
unit="$H1/.config/systemd/user/claude-swap-agent.service"
bin="$H1/.local/bin/claude-swap-agent"

check "binary installed" test -x "$bin"
check "binary mode 0700" mode_is "$bin" 700
check "enrolled (agent.json written)" test -f "$sdir/agent.json"
check "state dir mode 0700" mode_is "$sdir" 700
check "unit written" test -f "$unit"

check "enrol called with server and pin" \
  grep -q "^enrol --server https://swap.example:8443 --pin $PIN\$" "$STUB_LOG"
check "enrol received the code from the environment" \
  grep -q '^code-present enrol$' "$STUB_LOG"
check "enrol used the resolved state dir" grep -q "^state-dir enrol $sdir\$" "$STUB_LOG"
check "install used the same state dir as enrol" grep -q "^state-dir install $sdir\$" "$STUB_LOG"
refute "CLAUDE_CONFIG_DIR left unset" grep -q '^config-dir-set' "$STUB_LOG"
refute "code not passed to install" grep -q '^code-present install$' "$STUB_LOG"
check "daemon-reload called" grep -q '^systemctl --user daemon-reload$' "$STUB_LOG"
check "service enabled --now" \
  grep -q '^systemctl --user enable --now claude-swap-agent.service$' "$STUB_LOG"
check "linger note printed" grep -q 'loginctl enable-linger' "$TMP/out1"

# The secret must appear nowhere a later reader could find it.
refute "enrol code absent from output, log and unit" \
  grep -rq "$SECRET" "$TMP/out1" "$STUB_LOG" "$unit" "$sdir"

# ------------------------------------------------- 2. idempotent second run

: >"$STUB_LOG"
if out2="$(invoke "$H1" 2>&1)"; then ok "re-run exits 0"; else
  fail "re-run exited non-zero"; printf '%s\n' "$out2" | sed 's/^/     | /'
fi
printf '%s\n' "$out2" >"$TMP/out2"
refute "re-run skipped enrol" grep -q '^enrol ' "$STUB_LOG"
check "re-run rewrote the unit" grep -q '^install ' "$STUB_LOG"
check "re-run says why enrol was skipped" grep -q 'already enrolled' "$TMP/out2"

# ------------------------------------------------------------ 3. dry run

H2="$TMP/home2"
mkdir -p "$H2"
: >"$STUB_LOG"
CLAUDESWAP_DRY_RUN=1
if out3="$(invoke "$H2" 2>&1)"; then ok "dry run exits 0"; else
  fail "dry run exited non-zero"; printf '%s\n' "$out3" | sed 's/^/     | /'
fi
unset CLAUDESWAP_DRY_RUN
printf '%s\n' "$out3" >"$TMP/out3"
check "dry run printed DRY-RUN lines" grep -q 'DRY-RUN' "$TMP/out3"
refute "dry run invoked nothing" test -s "$STUB_LOG"
refute "dry run installed nothing" test -e "$H2/.local/bin/claude-swap-agent"
refute "dry run wrote no unit" test -e "$H2/.config/systemd/user/claude-swap-agent.service"

# --------------------------------------------------- 4. input validation

badrun() { # badrun <label> <env assignments...>
  local label="$1"; shift
  if env -i PATH="$PATH" HOME="$TMP/home3" STUB_LOG="$STUB_LOG" "$@" bash "$SCRIPT" >/dev/null 2>&1; then
    fail "$label was accepted"
  else
    ok "$label rejected"
  fi
}
mkdir -p "$TMP/home3"
badrun "missing server" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_BIN="$STUB/fake-agent"
badrun "http server" CLAUDESWAP_SERVER="http://x:1" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_BIN="$STUB/fake-agent"
badrun "short pin" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="abc" CLAUDESWAP_AGENT_BIN="$STUB/fake-agent"
badrun "no binary source" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="$PIN"
badrun "url without sha256" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_URL="https://x/agent"
badrun "missing local binary" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_BIN="$TMP/nope"

# ------------------------------------------- 5. download with sha256 check

# A stub curl stands in for the network: the only thing under test is whether
# the script refuses a payload whose digest does not match.
cat >"$STUB/curl" <<STUBEOF
#!/usr/bin/env bash
set -euo pipefail
out=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    *) shift ;;
  esac
done
cp -f -- "$STUB/fake-agent" "\${out:?curl stub: no -o}"
STUBEOF
chmod 0755 "$STUB/curl"
PAYLOAD_SHA="$(sha256sum "$STUB/fake-agent" | cut -d' ' -f1)"
BAD_SHA=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

dlrun() { # dlrun <home> <sha256>
  env -i PATH="$STUB:$PATH" HOME="$1" STUB_LOG="$STUB_LOG" \
    CLAUDESWAP_SERVER="https://swap.example:8443" CLAUDESWAP_PIN="$PIN" \
    CLAUDESWAP_AGENT_URL="https://dl.example/claude-swap-agent" \
    CLAUDESWAP_AGENT_SHA256="$2" \
    bash "$SCRIPT" 2>&1
}

H4="$TMP/home4"; mkdir -p "$H4"
if out4="$(dlrun "$H4" "$BAD_SHA")"; then
  fail "a sha256 mismatch was accepted"
else
  ok "sha256 mismatch rejected"
fi
printf '%s\n' "$out4" >"$TMP/out4"
check "mismatch names the digest problem" grep -q 'sha256 mismatch' "$TMP/out4"
refute "no binary installed after a mismatch" test -e "$H4/.local/bin/claude-swap-agent"

H5="$TMP/home5"; mkdir -p "$H5"
: >"$STUB_LOG"
if out5="$(dlrun "$H5" "$PAYLOAD_SHA")"; then ok "matching sha256 accepted"; else
  fail "matching sha256 rejected"; printf '%s\n' "$out5" | sed 's/^/     | /'
fi
check "downloaded binary installed" test -x "$H5/.local/bin/claude-swap-agent"
check "downloaded binary mode 0700" mode_is "$H5/.local/bin/claude-swap-agent" 700

# ------------------------------------------------------------ 6. shellcheck

if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S style "$SCRIPT" "$0"; then ok "shellcheck clean"; else fail "shellcheck"; fi
else
  echo "ok   shellcheck not installed: skipped (not verified)"
fi

[ "$rc" -eq 0 ] && echo "install-agent-sh: all checks passed"
exit "$rc"
