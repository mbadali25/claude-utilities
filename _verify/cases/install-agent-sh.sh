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

# The installer judges a home by its owner, because root bypasses the mode bits.
# The stub users must therefore carry the uid that actually owns $TMP, which is
# whoever is running this case. As root that uid is 0, which the installer reads
# as "root" everywhere and the user-unit cases could not run at all.
REAL_UID="$(id -u)"
if [ "$REAL_UID" = "0" ]; then
  echo "running as root: this case needs an unprivileged uid to own its temp homes"
  exit 77
fi

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

# The identity stubs. STUB_PASSWD is a passwd-format file the case writes per
# scenario, and STUB_SELF is the uid the script sees itself running as. Nothing
# here reads the real /etc/passwd, so a case can be "root" without being root
# and the installer can never resolve a real user's real home.
cat >"$STUB/id" <<'STUBEOF'
#!/usr/bin/env bash
set -uo pipefail
pw="${STUB_PASSWD:?STUB_PASSWD unset}"
self="${STUB_SELF:-1000}"
mode=uid; who=""
for a in "$@"; do
  case "$a" in
    -u) mode=uid ;;
    -un|-nu) mode=name ;;
    -*) ;;
    *) who="$a" ;;
  esac
done
while IFS=: read -r n _ u _ _ _ _; do
  if { [ -n "$who" ] && [ "$n" = "$who" ]; } || { [ -z "$who" ] && [ "$u" = "$self" ]; }; then
    if [ "$mode" = name ]; then printf '%s\n' "$n"; else printf '%s\n' "$u"; fi
    exit 0
  fi
done <"$pw"
echo "id: no such user" >&2
exit 1
STUBEOF
chmod 0755 "$STUB/id"

cat >"$STUB/getent" <<'STUBEOF'
#!/usr/bin/env bash
set -uo pipefail
pw="${STUB_PASSWD:?STUB_PASSWD unset}"
db="${1:-}"; want="${2:-}"
case "$db" in
  passwd)
    while IFS=: read -r n p u g c h s; do
      if [ "$n" = "$want" ] || [ "$u" = "$want" ]; then
        printf '%s:%s:%s:%s:%s:%s:%s\n' "$n" "$p" "$u" "$g" "$c" "$h" "$s"; exit 0
      fi
    done <"$pw" ;;
  group)
    # One group per user, named after it: enough for Group= in the unit.
    while IFS=: read -r n _ _ g _ _ _; do
      if [ "$g" = "$want" ] || [ "$n" = "$want" ]; then printf '%s:x:%s:\n' "$n" "$g"; exit 0; fi
    done <"$pw" ;;
esac
exit 2
STUBEOF
chmod 0755 "$STUB/getent"

# chown and runuser only record themselves: the case runs unprivileged, so a
# real chown would fail and a real runuser would need root.
cat >"$STUB/chown" <<'STUBEOF'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >>"${STUB_LOG:?}"
STUBEOF
chmod 0755 "$STUB/chown"

cat >"$STUB/runuser" <<'STUBEOF'
#!/usr/bin/env bash
set -uo pipefail
printf 'runuser %s\n' "$*" >>"${STUB_LOG:?}"
shift 2            # -u <user>
[ "${1:-}" = "--" ] && shift
exec "$@"
STUBEOF
chmod 0755 "$STUB/runuser"

# A stub curl stands in for the network in section 5. It serves the stub agent,
# so the digest the script verifies is the digest of a binary that then works.
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

export PATH="$STUB:$PATH"

# The stubs must win every PATH lookup. This case declares itself read-only, so
# run-all.sh may run it in a production pass: reaching the real user manager
# would enable a real unit. Refuse to run at all rather than risk it.
for tool in systemctl curl id getent chown runuser; do
  if [ "$(command -v "$tool" 2>/dev/null)" != "$STUB/$tool" ]; then
    echo "$tool resolves outside the stub dir: refusing to run"
    exit 77
  fi
done
PIN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SECRET=super-secret-one-time-code

# The default identity: one ordinary user, uid 1000, whose home is whichever
# throwaway HOME the case under test passes. passwd_for rewrites it per case.
UID_DEF="$REAL_UID"
STUB_PASSWD="$TMP/passwd"
SYSUNITS="$TMP/system-units"
RUNBASE="$TMP/run-user"
mkdir -p "$SYSUNITS" "$RUNBASE/$UID_DEF"   # a present runtime dir = a live user bus
export STUB_PASSWD
EXTRA_PASSWD=()

# passwd_for <home> [extra lines...] -- the ordinary user plus anything else.
passwd_for() {
  local home="$1"; shift
  printf 'tester:x:%s:%s::%s:/bin/bash\n' "$UID_DEF" "$UID_DEF" "$home" >"$STUB_PASSWD"
  for line in "$@"; do [ -n "$line" ] && printf '%s\n' "$line" >>"$STUB_PASSWD"; done
  return 0
}

# invoke <home> -- run the installer in an isolated HOME. Only the variables
# the script documents are exported; CLAUDE_CONFIG_DIR is never set.
invoke() {
  local home="$1"; shift
  passwd_for "$home" "${EXTRA_PASSWD[@]}"
  env -i \
    PATH="$PATH" \
    HOME="$home" \
    STUB_LOG="$STUB_LOG" \
    STUB_PASSWD="$STUB_PASSWD" \
    ${STUB_SELF:+STUB_SELF="$STUB_SELF"} \
    CLAUDESWAP_SYSTEM_UNIT_DIR="$SYSUNITS" \
    CLAUDESWAP_RUNTIME_BASE="${RUNBASE_OVERRIDE:-$RUNBASE}" \
    CLAUDESWAP_SERVER="https://swap.example:8443" \
    CLAUDESWAP_PIN="$PIN" \
    CLAUDESWAP_ENROL_CODE="$SECRET" \
    CLAUDESWAP_AGENT_BIN="$STUB/fake-agent" \
    ${CLAUDESWAP_RUN_AS:+CLAUDESWAP_RUN_AS="$CLAUDESWAP_RUN_AS"} \
    ${CLAUDESWAP_ALLOW_SYSTEM_USER:+CLAUDESWAP_ALLOW_SYSTEM_USER="$CLAUDESWAP_ALLOW_SYSTEM_USER"} \
    ${CLAUDESWAP_STATE_DIR:+CLAUDESWAP_STATE_DIR="$CLAUDESWAP_STATE_DIR"} \
    ${CLAUDESWAP_DRY_RUN:+CLAUDESWAP_DRY_RUN="$CLAUDESWAP_DRY_RUN"} \
    bash "$SCRIPT" "$@"
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
  if env -i PATH="$PATH" HOME="$TMP/home3" STUB_LOG="$STUB_LOG" STUB_PASSWD="$STUB_PASSWD" \
      CLAUDESWAP_SYSTEM_UNIT_DIR="$SYSUNITS" CLAUDESWAP_RUNTIME_BASE="$RUNBASE" \
      "$@" bash "$SCRIPT" >/dev/null 2>&1; then
    fail "$label was accepted"
  else
    ok "$label rejected"
  fi
}
mkdir -p "$TMP/home3"
passwd_for "$TMP/home3"
badrun "missing server" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_BIN="$STUB/fake-agent"
badrun "http server" CLAUDESWAP_SERVER="http://x:1" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_BIN="$STUB/fake-agent"
badrun "short pin" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="abc" CLAUDESWAP_AGENT_BIN="$STUB/fake-agent"
badrun "no binary source" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="$PIN"
badrun "url without sha256" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_URL="https://x/agent"
badrun "missing local binary" CLAUDESWAP_SERVER="https://x:1" CLAUDESWAP_PIN="$PIN" CLAUDESWAP_AGENT_BIN="$TMP/nope"

# ------------------------------------------- 5. download with sha256 check

# The only thing under test here is whether the script refuses a payload whose
# digest does not match. The stub curl is set up with the other stubs above.
PAYLOAD_SHA="$(sha256sum "$STUB/fake-agent" | cut -d' ' -f1)"
BAD_SHA=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

dlrun() { # dlrun <home> <sha256>
  passwd_for "$1"
  env -i PATH="$PATH" HOME="$1" STUB_LOG="$STUB_LOG" STUB_PASSWD="$STUB_PASSWD" \
    CLAUDESWAP_SYSTEM_UNIT_DIR="$SYSUNITS" CLAUDESWAP_RUNTIME_BASE="$RUNBASE" \
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

# ------------------------------------- 6. the systemd --user environment fix

# `systemctl --user` needs XDG_RUNTIME_DIR and a bus address, and section 1 ran
# with neither in the environment (env -i). The script must have supplied them
# rather than fall back, because $RUNBASE/$UID_DEF exists.
check "user mode exported the runtime dir in its hint" \
  grep -q "export XDG_RUNTIME_DIR=$RUNBASE/$UID_DEF\$" "$TMP/out1"
check "user mode exported the bus address in its hint" \
  grep -q "export DBUS_SESSION_BUS_ADDRESS=unix:path=$RUNBASE/$UID_DEF/bus\$" "$TMP/out1"
check "hint names systemctl --user status" \
  grep -q "^  systemctl --user status claude-swap-agent.service\$" "$TMP/out1"
check "hint names journalctl --user" \
  grep -q "^  journalctl --user -u claude-swap-agent.service -f\$" "$TMP/out1"
refute "no --machine fallback while the runtime dir exists" \
  grep -q 'machine=' "$TMP/out1"

# With no /run/user/<uid> there is no user manager: say so, name the remedy, and
# fall back to the --machine form rather than failing silently.
H6="$TMP/home6"; mkdir -p "$H6"
: >"$STUB_LOG"
RUNBASE_OVERRIDE="$TMP/run-empty"; mkdir -p "$RUNBASE_OVERRIDE"
if out6="$(invoke "$H6" 2>&1)"; then ok "missing runtime dir still exits 0"; else
  fail "missing runtime dir exited non-zero"; printf '%s\n' "$out6" | sed 's/^/     | /'
fi
unset RUNBASE_OVERRIDE
printf '%s\n' "$out6" >"$TMP/out6"
check "missing runtime dir named" grep -q "$TMP/run-empty/$UID_DEF does not exist" "$TMP/out6"
check "says there is no user manager / linger is off" \
  grep -q 'no systemd user manager' "$TMP/out6"
check "names the linger remedy" grep -q 'sudo loginctl enable-linger tester' "$TMP/out6"
check "fell back to the --machine form" \
  grep -q '^systemctl --user --machine=tester@.host daemon-reload$' "$STUB_LOG"
check "--machine form used for enable too" \
  grep -q '^systemctl --user --machine=tester@.host enable --now claude-swap-agent.service$' "$STUB_LOG"

# ------------------------------------------------- 7. root writes a system unit

# STUB_SELF=0 makes the script believe it runs as root, so it must choose system
# mode by itself. run_as defaults to root, whose home is the throwaway one.
H7="$TMP/home7"; mkdir -p "$H7"
: >"$STUB_LOG"
STUB_SELF=0
EXTRA_PASSWD=("root:x:0:0::$H7:/bin/bash")
if out7="$(invoke "$H7" 2>&1)"; then ok "root run exits 0"; else
  fail "root run exited non-zero"; printf '%s\n' "$out7" | sed 's/^/     | /'
fi
printf '%s\n' "$out7" >"$TMP/out7"
sysunit="$SYSUNITS/claude-swap-agent.service"

check "root chose system mode" grep -q '^==> mode system' "$TMP/out7"
check "system unit written" test -f "$sysunit"
check "system unit mode 0644" mode_is "$sysunit" 644
check "unit runs as root" grep -q '^User=root$' "$sysunit"
check "unit sets a group" grep -q '^Group=root$' "$sysunit"
check "unit hardening: NoNewPrivileges" grep -q '^NoNewPrivileges=yes$' "$sysunit"
check "unit hardening: PrivateTmp" grep -q '^PrivateTmp=yes$' "$sysunit"
refute "no ProtectHome (the agent must read ~/.claude.json)" grep -q 'ProtectHome' "$sysunit"
check "unit restarts always" grep -q '^Restart=always$' "$sysunit"
check "unit wanted by multi-user.target" grep -q '^WantedBy=multi-user.target$' "$sysunit"
check "unit bakes in the state dir" \
  grep -q "^Environment=\"CLAUDESWAP_STATE_DIR=$H7/.config/claude-swap-agent\"\$" "$sysunit"
check "system systemctl daemon-reload" grep -q '^systemctl daemon-reload$' "$STUB_LOG"
check "system unit enabled --now" \
  grep -q '^systemctl enable --now claude-swap-agent.service$' "$STUB_LOG"
refute "root mode never touched systemctl --user" grep -q '^systemctl --user' "$STUB_LOG"
refute "root mode calls no agent install (it writes the unit itself)" \
  grep -q '^install ' "$STUB_LOG"
check "root mode documents plain systemctl restart" \
  grep -q '^  restart: systemctl restart claude-swap-agent.service$' "$TMP/out7"
refute "root mode prints no sudo -u workaround" grep -q 'sudo -u' "$TMP/out7"
check "root mode says linger is not needed" grep -q 'needs no linger' "$TMP/out7"
check "root enrolled" test -f "$H7/.config/claude-swap-agent/agent.json"
refute "enrol code absent from the root run's output and log" \
  grep -rq "$SECRET" "$TMP/out7" "$STUB_LOG" "$sysunit"

# ------------------------------- 8. root installs for an unprivileged user

# The home comes from getent, never from /home/<name>: this one is a temp dir.
H8="$TMP/home8"; mkdir -p "$H8"
: >"$STUB_LOG"
rm -f "$sysunit"
STUB_SELF=0
EXTRA_PASSWD=("root:x:0:0::$TMP/home7:/bin/bash")
CLAUDESWAP_RUN_AS=tester
if out8="$(invoke "$H8" 2>&1)"; then ok "root-for-user run exits 0"; else
  fail "root-for-user run exited non-zero"; printf '%s\n' "$out8" | sed 's/^/     | /'
fi
printf '%s\n' "$out8" >"$TMP/out8"
check "unit runs as the named user" grep -q '^User=tester$' "$sysunit"
check "unit group is the named user's" grep -q '^Group=tester$' "$sysunit"
check "state dir sits under the getent home" \
  grep -q "^Environment=\"CLAUDESWAP_STATE_DIR=$H8/.config/claude-swap-agent\"\$" "$sysunit"
check "unit HOME is the getent home" grep -q "^Environment=\"HOME=$H8\"\$" "$sysunit"
check "ExecStart points into that home" grep -q "^ExecStart=\"$H8/.local/bin/claude-swap-agent\" run\$" "$sysunit"
check "enrol ran through runuser as that user" grep -q '^runuser -u tester -- ' "$STUB_LOG"
check "the binary was handed to that user" \
  grep -q "^chown -R $UID_DEF:$UID_DEF $H8/.local/bin\$" "$STUB_LOG"
check "the state dir was handed to that user" \
  grep -q "^chown -R $UID_DEF:$UID_DEF $H8/.config/claude-swap-agent\$" "$STUB_LOG"

# The ancestors matter too. umask 077 makes a missing ~/.local or ~/.config
# root:root 0700, which the run-as user cannot traverse: the binary is then
# unexecutable and agent.json unreadable, and systemd says only
# status=203/EXEC. $H8 starts with neither directory, so this is the real path.
check "the home's .local was handed over too (traversal)" \
  grep -q "^chown $UID_DEF:$UID_DEF $H8/.local\$" "$STUB_LOG"
check "the home's .config was handed over too (traversal)" \
  grep -q "^chown $UID_DEF:$UID_DEF $H8/.config\$" "$STUB_LOG"
# Walking up must stop at the home: chowning it, or anything above it, would
# rewrite ownership the installer has no business touching.
refute "the walk up stopped at the home" grep -qE "^chown $UID_DEF:$UID_DEF ($H8|$TMP|/)\$" "$STUB_LOG"
check "enrol used the state dir under that home" \
  grep -q "^state-dir enrol $H8/.config/claude-swap-agent\$" "$STUB_LOG"
check "report names the chosen user" grep -q "^==> run as tester (uid $UID_DEF)" "$TMP/out8"
refute "enrol code never reached a command line" grep -q "$SECRET" "$STUB_LOG"
unset CLAUDESWAP_RUN_AS

# --------------------------------------------- 9. refusals around the user

norun() { # norun <label> <pattern> -- expect a non-zero exit naming pattern
  local label="$1" pat="$2"
  if o="$(invoke "$TMP/home9" 2>&1)"; then
    fail "$label was accepted"
  else
    if printf '%s\n' "$o" | grep -q "$pat"; then ok "$label rejected and explained"; else
      fail "$label rejected without naming '$pat'"; printf '%s\n' "$o" | sed 's/^/     | /'
    fi
  fi
}
mkdir -p "$TMP/home9"

STUB_SELF=0
EXTRA_PASSWD=("root:x:0:0::$TMP/home7:/bin/bash")
CLAUDESWAP_RUN_AS=ghost
norun "a user that does not exist" "does not exist"

CLAUDESWAP_RUN_AS=svc
# svc carries the uid that owns the temp home, so the only thing left to refuse
# is its login shell.
EXTRA_PASSWD=("root:x:0:0::$TMP/home7:/bin/bash" "svc:x:$UID_DEF:$UID_DEF::$TMP/home9:/usr/sbin/nologin")
norun "a nologin account" "service account"

# The same account installs once the override says so, which proves the refusal
# is a gate and not a hard no.
: >"$STUB_LOG"
rm -f "$sysunit"
CLAUDESWAP_ALLOW_SYSTEM_USER=1
if out10="$(invoke "$TMP/home9" 2>&1)"; then ok "nologin account accepted with the override"; else
  fail "override did not admit the nologin account"; printf '%s\n' "$out10" | sed 's/^/     | /'
fi
check "override unit runs as that account" grep -q '^User=svc$' "$sysunit"
unset CLAUDESWAP_ALLOW_SYSTEM_USER

# An ordinary user cannot install for somebody else: there is no way to write
# another home, and silently installing for themselves would be worse.
unset STUB_SELF
EXTRA_PASSWD=("other:x:1002:1002::$TMP/home9:/bin/bash")
CLAUDESWAP_RUN_AS=other
norun "another user without root" "only root can install"
unset CLAUDESWAP_RUN_AS
EXTRA_PASSWD=()

# ------------------------------------------------------- 10. --reconfigure

# A host already enrolled in user mode is moved to a system unit. The enrolment
# must survive: a one-time code is spent, so losing agent.json loses the host.
H11="$TMP/home11"; mkdir -p "$H11"
: >"$STUB_LOG"
rm -f "$sysunit"
invoke "$H11" >/dev/null 2>&1 || fail "user-mode seed run failed"
check "seed run enrolled" test -f "$H11/.config/claude-swap-agent/agent.json"
seedtoken="$(cat "$H11/.config/claude-swap-agent/agent.json")"
# An unsettled swap journal must survive a reconfigure as well: the agent
# settles a leftover one on start, and losing it leaves credentials half-written
# on a host that looks clean.
printf '{"stage":"written"}\n' >"$H11/.config/claude-swap-agent/swap-journal.json"

: >"$STUB_LOG"
STUB_SELF=0
EXTRA_PASSWD=("root:x:0:0::$TMP/home7:/bin/bash")
CLAUDESWAP_RUN_AS=tester
if out11="$(invoke "$H11" --reconfigure 2>&1)"; then ok "--reconfigure exits 0"; else
  fail "--reconfigure exited non-zero"; printf '%s\n' "$out11" | sed 's/^/     | /'
fi
printf '%s\n' "$out11" >"$TMP/out11"
check "--reconfigure stopped the old user unit" \
  grep -q 'disable --now claude-swap-agent.service' "$STUB_LOG"
check "--reconfigure wrote the system unit" test -f "$sysunit"
check "--reconfigure kept the enrolment" test -f "$H11/.config/claude-swap-agent/agent.json"
check "the enrolment token is the same file" \
  test "$seedtoken" = "$(cat "$H11/.config/claude-swap-agent/agent.json")"
refute "--reconfigure did not re-enrol" grep -q '^enrol ' "$STUB_LOG"
check "--reconfigure says why enrol was skipped" grep -q 'already enrolled' "$TMP/out11"
check "--reconfigure kept the swap journal" \
  test -f "$H11/.config/claude-swap-agent/swap-journal.json"

# A reconfigure that moves the state dir has to carry the whole directory over,
# journal included, not just the token.
: >"$STUB_LOG"
CLAUDESWAP_STATE_DIR="$H11/.claude-swap-state"
if out11b="$(invoke "$H11" --reconfigure 2>&1)"; then ok "state-dir move exits 0"; else
  fail "state-dir move exited non-zero"; printf '%s\n' "$out11b" | sed 's/^/     | /'
fi
unset CLAUDESWAP_STATE_DIR
printf '%s\n' "$out11b" >"$TMP/out11b"
check "the move said it was migrating" grep -q 'migrating the existing enrolment' "$TMP/out11b"
check "the token arrived at the new state dir" test -f "$H11/.claude-swap-state/agent.json"
check "the journal arrived with it" test -f "$H11/.claude-swap-state/swap-journal.json"
refute "the move did not re-enrol" grep -q '^enrol ' "$STUB_LOG"
check "the new state dir is baked into the unit" \
  grep -q "^Environment=\"CLAUDESWAP_STATE_DIR=$H11/.claude-swap-state\"\$" "$sysunit"
unset CLAUDESWAP_RUN_AS
unset STUB_SELF
EXTRA_PASSWD=()

# ------------------------------------------- 11. dry run names every choice

H12="$TMP/home12"; mkdir -p "$H12"
: >"$STUB_LOG"
rm -f "$sysunit"   # section 10 left one behind; the dry run must write none
STUB_SELF=0
EXTRA_PASSWD=("root:x:0:0::$TMP/home7:/bin/bash")
CLAUDESWAP_RUN_AS=tester
CLAUDESWAP_DRY_RUN=1
if out12="$(invoke "$H12" 2>&1)"; then ok "system-mode dry run exits 0"; else
  fail "system-mode dry run exited non-zero"; printf '%s\n' "$out12" | sed 's/^/     | /'
fi
unset CLAUDESWAP_DRY_RUN CLAUDESWAP_RUN_AS
unset STUB_SELF
EXTRA_PASSWD=()
printf '%s\n' "$out12" >"$TMP/out12"
check "dry run names the user" grep -q '^==> run as tester (uid 1000)' "$TMP/out12"
check "dry run names the home" grep -q "home $H12\$" "$TMP/out12"
check "dry run names the state dir" grep -q "^==> state dir $H12/.config/claude-swap-agent\$" "$TMP/out12"
check "dry run names the unit path" grep -q "^==> unit $SYSUNITS/claude-swap-agent.service\$" "$TMP/out12"
check "dry run names the mode" grep -q '^==> mode system' "$TMP/out12"
refute "dry run wrote no system unit" test -e "$SYSUNITS/claude-swap-agent.service"
refute "dry run invoked nothing" test -s "$STUB_LOG"

# ------------------------------------------------------------ 12. shellcheck

if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S style "$SCRIPT" "$0"; then ok "shellcheck clean"; else fail "shellcheck"; fi
else
  echo "ok   shellcheck not installed: skipped (not verified)"
fi

[ "$rc" -eq 0 ] && echo "install-agent-sh: all checks passed"
exit "$rc"
