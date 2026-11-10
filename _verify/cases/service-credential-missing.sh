#!/usr/bin/env bash
# _verify/cases/service-credential-missing.sh - the negative case for the server unit's credential:
# a unit whose credential has gone missing must try five times, then stop as `failed`, leave a
# last-fatal marker that names what went wrong, and never restart after that. No restart loop.
#
# Exit 0 = every check passed, 1 = a check failed, 77 = cannot run here (SKIPPED, NOT verified).
#
# BLAST RADIUS, before the assertions. run-all.sh globs _verify/cases/*.sh and runs this file on
# whatever machine runs the gate - a laptop, SRL-LIN, a CI runner. The naive form of this case
# ("rename the credential aside, systemctl start claude-swap-server") would move a REAL
# /etc/credstore*/claude-swap.vault-kek and start the REAL unit: a production outage triggered by a
# gate run. So, non-negotiable:
#   - Transient units only. The units live under /run/systemd/system (volatile, gone at reboot) with
#     a name unique to this run (claude-swap-verify-<pid>-<nanos>). Nothing under /etc/systemd/system,
#     /etc/credstore, /etc/credstore.encrypted or /var/lib/systemd is read, written, moved or deleted,
#     and credential.secret is never touched. The credential "renamed aside" is this case's own
#     fixture inside its own temp dir. The real unit name is never started, stopped or reloaded.
#   - Cleanup is unconditional: a trap on EXIT stops and resets exactly those two unit names, removes
#     exactly those two files and the temp tree, so an aborted run leaves nothing.
#   - Exit 77, with the reason printed, for: no systemd (not PID 1 - a container, or WSL without
#     systemd), no systemctl / systemd-run / journalctl, no root and no passwordless sudo, a systemd
#     older than 249 (the OnFailure unit reads $MONITOR_*), the REAL claude-swap-server.service
#     already installed on this host (refuse rather than risk a collision), no Go toolchain, or
#     cmd/server that will not build.
#   - FAIL, never 77, for everything this case can check once it is running: the unit starting with a
#     missing credential, fewer or more than five attempts, no failure notice, a marker or notice
#     that does not name the credential, or a restart after the limit. A 77 for any of those would
#     read green for ever.
#
# Why LoadCredentialEncrypted= and not LoadCredential=: only the encrypted form is KNOWN to fail the
# start when its file is gone. The first CI run showed a plain LoadCredential= with a missing file
# does NOT stop systemd from exec'ing the server - the plain-rung host instead falls through to the
# passphrase and exits 3 or 4 (non-restarting, so no loop either, but a different failure and not
# one this case can pin down without a real vault). The host-key rungs use the encrypted form.
#
# What differs from the real unit, deliberately: RestartSec=1 and no RestartSteps/RestartMaxDelaySec
# (the real ramp takes minutes; the COUNT and the LIMIT are what is under test), no User=/
# StateDirectory= (so nothing is created under /var/lib), and the credential path is the fixture's.
# Everything else - Type, NotifyAccess, StartLimit*, Restart, RestartPreventExitStatus, ExecStart -
# is copied out of service.RenderServerUnit, so a change to the real unit changes this case.
#
# It does not declare `# readonly: yes`, so a --read-only gate run skips it, which is correct: it writes.
# readonly: no
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

skip() { echo "SKIP service-credential-missing: $*"; exit 77; }

[ -d /run/systemd/system ] || skip "systemd is not PID 1 here (a container, or WSL without systemd)"
for t in systemctl systemd-run journalctl; do
  command -v "$t" >/dev/null 2>&1 || skip "$t not installed"
done
if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then SUDO="sudo -n"
else skip "not root and no passwordless sudo"; fi

SDV="$(systemctl --version 2>/dev/null | awk 'NR==1{print $2}')"
case "$SDV" in ''|*[!0-9]*) skip "cannot read the systemd version" ;; esac
[ "$SDV" -ge 249 ] || skip "systemd $SDV is older than 249 (the failure unit reads \$MONITOR_*)"

REAL=claude-swap-server.service
if [ -e "/etc/systemd/system/$REAL" ] || [ -e "/usr/lib/systemd/system/$REAL" ] \
   || systemctl list-unit-files "$REAL" --no-legend 2>/dev/null | grep -q .; then
  skip "server service installed here; this case does not run beside a real install"
fi

if command -v go >/dev/null 2>&1; then GO=go
elif command -v go.exe >/dev/null 2>&1; then GO=go.exe
else skip "go not installed"; fi

TMP="$(mktemp -d)" || { echo "FAIL mktemp"; exit 1; }
chmod 755 "$TMP"   # the units run as root, but do not depend on that
ID="claude-swap-verify-$$-$(date +%s%N)"
MAIN="$ID.service"; FAILED="$ID-failed.service"
RUNDIR=/run/systemd/system
MADE=""

cleanup() {
  if [ -n "$MADE" ]; then
    $SUDO systemctl stop "$MAIN" "$FAILED" >/dev/null 2>&1
    $SUDO systemctl reset-failed "$MAIN" "$FAILED" >/dev/null 2>&1
    $SUDO rm -f "$RUNDIR/$MAIN" "$RUNDIR/$FAILED"
    $SUDO systemctl daemon-reload >/dev/null 2>&1
  fi
  # As root when we are not: the failure unit runs as root and may have created files in here.
  $SUDO rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

BIN="$TMP/claude-swap-server"
"$GO" build -o "$BIN" ./cmd/server >/dev/null 2>&1 || skip "cmd/server did not build"

DATA="$TMP/data"; CRED="$TMP/credstore/claude-swap.vault-kek"
mkdir -p "$DATA" "$TMP/credstore" "$TMP/units" || { echo "FAIL mkdir"; exit 1; }

# Render the real units from the real renderers.
VERIFY_UNIT_DIR="$TMP/units" VERIFY_EXE="$BIN" VERIFY_DATA_DIR="$DATA" \
  "$GO" test -count=1 -run '^TestRenderUnitsForVerify$' ./internal/service >"$TMP/render.log" 2>&1 \
  || { echo "FAIL cannot render the units"; tail -n 5 "$TMP/render.log"; exit 1; }
[ -s "$TMP/units/server.service" ] && [ -s "$TMP/units/failed.service" ] \
  || { echo "FAIL the renderer wrote no unit files"; exit 1; }

# The fixture credential: written, then renamed aside, so the unit names a path that is not there.
head -c 32 /dev/urandom >"$CRED" && chmod 600 "$CRED" && mv "$CRED" "$CRED.aside" \
  || { echo "FAIL cannot stage the fixture credential"; exit 1; }

rc=0
fail() { echo "FAIL $*"; rc=1; }

# The verify unit: the restart block and ExecStart of the real unit, our credential, our OnFailure.
{
  echo "[Unit]"
  echo "Description=claude-swap verify (credential missing)"
  grep -E '^(StartLimitIntervalSec|StartLimitBurst)=' "$TMP/units/server.service"
  echo "OnFailure=$FAILED"
  echo
  echo "[Service]"
  grep -E '^(Type|NotifyAccess|Restart|RestartPreventExitStatus|ExecStart)=' "$TMP/units/server.service"
  echo "RestartSec=1"
  echo "LoadCredentialEncrypted=vault-kek:$CRED"
} >"$TMP/units/verify.service"
for k in StartLimitIntervalSec StartLimitBurst Type NotifyAccess Restart RestartPreventExitStatus ExecStart; do
  grep -q "^$k=" "$TMP/units/verify.service" || fail "the real unit has no $k= line to copy"
done
[ "$rc" -eq 0 ] || exit 1

MADE=1
$SUDO install -m 0644 "$TMP/units/verify.service" "$RUNDIR/$MAIN" \
  && $SUDO install -m 0644 "$TMP/units/failed.service" "$RUNDIR/$FAILED" \
  || { echo "FAIL cannot place the transient units"; exit 1; }
$SUDO systemctl daemon-reload || { echo "FAIL daemon-reload"; exit 1; }

# Start it. A start that fails is the expected outcome, so the exit status of this is not checked.
$SUDO systemctl start --no-block "$MAIN" >/dev/null 2>&1

prop() { $SUDO systemctl show -p "$1" --value "$MAIN" 2>/dev/null; }
journal() { $SUDO journalctl -u "$MAIN" -o cat --no-pager 2>/dev/null; }
# One line per exec attempt: systemd 255 logs "Main process exited, code=exited, status=243/CREDENTIALS" each time.
attempts() { journal | grep -c 'status=243/CREDENTIALS'; }

# Wait for the unit to settle as failed: five attempts one second apart is a few seconds.
state=""
for _ in $(seq 1 120); do
  state="$(prop ActiveState)"
  [ "$state" = "failed" ] && break
  sleep 0.5
done
[ "$state" = "failed" ] || fail "the unit is '$state' after 60 s, want failed"

# systemd 255 leaves Result=exit-code when the limit trips; the journal line is the evidence of the limit.
limit="$(journal | grep -c 'Start request repeated too quickly')"
[ "$limit" -eq 1 ] || fail "the start limit tripped $limit times, want exactly once (five tries, then the limit)"
n="$(attempts)"
[ "$n" -eq 5 ] || fail "$n attempts failed at the credential step, want exactly 5"
[ "$(prop ExecMainStatus)" = "243" ] || fail "ExecMainStatus is '$(prop ExecMainStatus)', want 243 (credentials)"

# The OnFailure unit is a oneshot started when the unit fails; give it a moment, then read what it left.
MARKER="$DATA/logs/last-fatal.json"
for _ in $(seq 1 40); do [ -s "$MARKER" ] && break; sleep 0.5; done
if [ -s "$MARKER" ]; then
  grep -q '"reason":"credential-missing"' "$MARKER" || fail "the marker does not say credential-missing: $(cat "$MARKER")"
  grep -q '"exit":243' "$MARKER" || fail "the marker does not carry exit 243: $(cat "$MARKER")"
else
  fail "no last-fatal marker was written under the data dir's logs directory"
fi
notice="$($SUDO journalctl -u "$FAILED" -o cat --no-pager 2>/dev/null)"
case "$notice" in
  *credential=vault-kek*) : ;;
  *) fail "the failure notice does not name the credential; journal said: $notice" ;;
esac
case "$notice" in *"$CRED"*|*"$TMP"*) fail "the failure notice names a path" ;; esac

# No restart loop: nothing more may happen after the limit.
sleep 4
[ "$(prop ActiveState)" = "failed" ] || fail "the unit left failed after the limit: '$(prop ActiveState)'"
[ "$(attempts)" -eq 5 ] || fail "a restart happened after the limit: $(attempts) attempts"

if [ "$rc" -ne 0 ]; then
  # run-all.sh shows only the last five lines of a failing case, so the evidence goes on one line.
  diag="$($SUDO journalctl -u "$MAIN" -o cat --no-pager 2>/dev/null | tail -n 30 | cut -c1-110 | tr '\n' '|')"
  echo "FAIL diag: Result=$(prop Result) ExecMainStatus=$(prop ExecMainStatus) NRestarts=$(prop NRestarts) journal: $diag"
fi
[ "$rc" -eq 0 ] && echo "PASS service-credential-missing: 5 attempts, the start limit, marker and notice name the credential, no restart after"
exit "$rc"
