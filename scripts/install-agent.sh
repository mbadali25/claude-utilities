#!/usr/bin/env bash
# scripts/install-agent.sh - install and enrol the claude-swap agent on a Linux host.
#
# Almost no flags: every secret arrives in the environment, because an enrolment
# code on a command line is readable by every user on the host through
# /proc/<pid>/cmdline.
#
#   flags     --system         force a system unit even when not run as root
#             --reconfigure    stop the existing unit, rewrite it, keep the enrolment
#
#   required  CLAUDESWAP_SERVER          https://host:port of the server
#             CLAUDESWAP_PIN             server certificate sha256 (64 hex chars)
#   binary    CLAUDESWAP_AGENT_BIN       path to a linux agent binary to copy, OR
#             CLAUDESWAP_AGENT_URL       URL to download, which then requires
#             CLAUDESWAP_AGENT_SHA256    its expected sha256 (64 hex chars)
#   optional  CLAUDESWAP_ENROL_CODE      one-time code; without it the enrolment
#                                        waits for an admin to approve this host
#             CLAUDESWAP_RUN_AS          local user the agent runs as; default the
#                                        invoking user. Only root may name another.
#             CLAUDESWAP_ALLOW_SYSTEM_USER=1
#                                        permit a nologin or sub-1000 account
#             CLAUDESWAP_SYSTEM=1        same as --system
#             CLAUDESWAP_STATE_DIR       state dir override; the same value is
#                                        used for enrol and baked into the unit
#             CLAUDESWAP_DRY_RUN=1       print every action, change nothing
#
# Two modes:
#   system mode (root, --system or CLAUDESWAP_SYSTEM=1) writes
#     /etc/systemd/system/claude-swap-agent.service with User=/Group=, so the
#     agent survives logout with no linger and `systemctl restart
#     claude-swap-agent` works as root.
#   user mode (run as the target user, no root) writes the systemd *user* unit
#     ~/.config/systemd/user/claude-swap-agent.service, which needs
#     `loginctl enable-linger` to outlive your session.
#
# Re-running is safe: the binary is replaced atomically, enrolment is skipped
# once agent.json exists (a one-time code is spent), and the unit is rewritten.
#
# CLAUDE_CONFIG_DIR is deliberately never set: the agent must read the default
# profile's ~/.claude.json to see which account is signed in.
set -euo pipefail

readonly BIN_NAME=claude-swap-agent
readonly UNIT_NAME=claude-swap-agent.service

DRY_RUN="${CLAUDESWAP_DRY_RUN:-0}"
RECONFIGURE=0
FORCE_SYSTEM="${CLAUDESWAP_SYSTEM:-0}"
run_group=""

# Test seams. Both default to the real paths and exist only so
# _verify/cases/install-agent-sh.sh can exercise the system-unit and
# missing-runtime-dir branches without root. Do not set them on a real host.
SYSTEM_UNIT_DIR="${CLAUDESWAP_SYSTEM_UNIT_DIR:-/etc/systemd/system}"
RUNTIME_BASE="${CLAUDESWAP_RUNTIME_BASE:-/run/user}"

die() { printf 'install-agent: %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }
warn() { printf 'install-agent: %s\n' "$*" >&2; }

# act runs a command, or prints it under CLAUDESWAP_DRY_RUN. Only commands whose
# arguments hold no secret are passed here; the enrolment code travels in the
# environment and is never an argument.
act() {
  if [ "$DRY_RUN" = "1" ]; then
    printf 'DRY-RUN: %s\n' "$*"
    return 0
  fi
  "$@"
}

is_hex64() { printf '%s' "$1" | grep -Eq '^[0-9a-fA-F]{64}$'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --system) FORCE_SYSTEM=1 ;;
    --reconfigure) RECONFIGURE=1 ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) die "unknown argument '$1'; only --system, --reconfigure and --help are flags, everything else arrives in the environment" ;;
  esac
  shift
done

# ---------------------------------------------------------------- inputs

[ -n "${CLAUDESWAP_SERVER:-}" ] || die "CLAUDESWAP_SERVER is not set (https://host:port)"
case "$CLAUDESWAP_SERVER" in
  https://*) ;;
  *) die "CLAUDESWAP_SERVER must be an https:// URL" ;;
esac
[ -n "${CLAUDESWAP_PIN:-}" ] || die "CLAUDESWAP_PIN is not set (the server prints it at startup)"
is_hex64 "${CLAUDESWAP_PIN}" || die "CLAUDESWAP_PIN must be 64 hex characters"

if [ -z "${CLAUDESWAP_AGENT_BIN:-}" ] && [ -z "${CLAUDESWAP_AGENT_URL:-}" ]; then
  die "set CLAUDESWAP_AGENT_BIN (a local linux binary) or CLAUDESWAP_AGENT_URL + CLAUDESWAP_AGENT_SHA256"
fi
if [ -n "${CLAUDESWAP_AGENT_URL:-}" ] && [ -z "${CLAUDESWAP_AGENT_BIN:-}" ]; then
  [ -n "${CLAUDESWAP_AGENT_SHA256:-}" ] || die "CLAUDESWAP_AGENT_URL needs CLAUDESWAP_AGENT_SHA256"
  is_hex64 "${CLAUDESWAP_AGENT_SHA256}" || die "CLAUDESWAP_AGENT_SHA256 must be 64 hex characters"
fi

# ------------------------------------------------------------- run-as user

command -v id >/dev/null 2>&1 || die "id is not installed"
command -v getent >/dev/null 2>&1 || die "getent is not installed: cannot resolve a user's home directory"

invoking_uid="$(id -u)"
invoking_user="$(id -un)"
invoking_home="${HOME:-}"
run_as="${CLAUDESWAP_RUN_AS:-$invoking_user}"
[ -n "$run_as" ] || die "CLAUDESWAP_RUN_AS is empty; unset it to install for the invoking user"
case "$run_as" in
  *[!A-Za-z0-9._-]*) die "CLAUDESWAP_RUN_AS '$run_as' is not a plain user name" ;;
esac

pwline="$(getent passwd "$run_as" 2>/dev/null || true)"
[ -n "$pwline" ] || die "user '$run_as' does not exist: getent passwd found no entry for it"
IFS=: read -r _ _ run_uid run_gid _ run_home run_shell <<<"$pwline"
[ -n "$run_uid" ] || die "getent passwd '$run_as' returned no uid"
# Never assume /home/<name>: a home can be /root, /var/lib/<svc> or anywhere else.
[ -n "$run_home" ] || die "user '$run_as' has no home directory in passwd; the agent needs one for ~/.claude.json"

allow_system_user="${CLAUDESWAP_ALLOW_SYSTEM_USER:-0}"
case "$run_shell" in
  ""|*/nologin|*/false)
    [ "$allow_system_user" = "1" ] || die "user '$run_as' has login shell '${run_shell:-<none>}', which marks it a service account; set CLAUDESWAP_ALLOW_SYSTEM_USER=1 to install for it anyway" ;;
esac
if [ "$run_uid" != "0" ] && [ "$run_uid" -lt 1000 ]; then
  [ "$allow_system_user" = "1" ] || die "user '$run_as' has uid $run_uid, below the 1000 the distribution reserves for people; set CLAUDESWAP_ALLOW_SYSTEM_USER=1 to install for it anyway"
fi

# owner_writable judges the home by ownership and the owner write bit, because
# root bypasses the permission bits and a plain `test -w` would always pass.
owner_writable() { # <dir> <uid>
  local mode owner
  owner="$(stat -c '%u' "$1" 2>/dev/null)" || return 0 # no stat: do not block the install
  mode="$(stat -c '%a' "$1" 2>/dev/null)" || return 0
  [ "$owner" = "$2" ] || return 1
  mode="${mode: -3}" # drop a leading setuid/sticky digit
  case "${mode%??}" in 2|3|6|7) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------- mode

# Authority first, filesystem second: a user who may not install for '$run_as'
# at all should hear that, not a complaint about somebody else's home.
system_mode=0
if [ "$FORCE_SYSTEM" = "1" ] || [ "$invoking_uid" = "0" ]; then
  system_mode=1
fi
if [ "$system_mode" = "1" ] && [ "$invoking_uid" != "0" ] && [ ! -w "$SYSTEM_UNIT_DIR" ]; then
  die "system mode writes $SYSTEM_UNIT_DIR/$UNIT_NAME, which you cannot write: re-run under sudo, or drop --system/CLAUDESWAP_SYSTEM to install a user unit"
fi
if [ "$run_uid" != "$invoking_uid" ] && [ "$invoking_uid" != "0" ]; then
  die "only root can install the agent for another user: re-run under sudo with CLAUDESWAP_RUN_AS=$run_as, or unset CLAUDESWAP_RUN_AS"
fi

[ -d "$run_home" ] || die "home '$run_home' of user '$run_as' does not exist; create it before installing the agent there"
if [ "$run_uid" = "$invoking_uid" ]; then
  [ -w "$run_home" ] || die "home '$run_home' is not writable by you"
else
  owner_writable "$run_home" "$run_uid" || die "home '$run_home' is not owned and writable by user '$run_as' (uid $run_uid); fix its ownership or pick another user"
fi

sys_unit_path="$SYSTEM_UNIT_DIR/$UNIT_NAME"
user_unit_path="$run_home/.config/systemd/user/$UNIT_NAME"
if [ "$system_mode" = "1" ]; then
  unit_path="$sys_unit_path"
else
  unit_path="$user_unit_path"
fi

# ---------------------------------------------------------------- state dir

# unit_state_dir reads the CLAUDESWAP_STATE_DIR an existing unit baked in. That
# file is the only record of where a host's enrolment token actually lives.
unit_state_dir() { # <unit file>
  [ -f "$1" ] || return 0
  sed -n 's/^Environment="\{0,1\}CLAUDESWAP_STATE_DIR=\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$1" | tail -n 1
}

under_dir() { # <path> <parent> -- true when path is parent or lies below it
  case "$1" in "$2"|"$2"/*) return 0 ;; *) return 1 ;; esac
}

prev_state_dir="$(unit_state_dir "$sys_unit_path")"
[ -n "$prev_state_dir" ] || prev_state_dir="$(unit_state_dir "$user_unit_path")"
if [ -z "$prev_state_dir" ] && [ -n "$invoking_home" ] && [ "$invoking_home" != "$run_home" ]; then
  prev_state_dir="$(unit_state_dir "$invoking_home/.config/systemd/user/$UNIT_NAME")"
fi

if [ -n "${CLAUDESWAP_STATE_DIR:-}" ]; then
  state_dir="$CLAUDESWAP_STATE_DIR"
elif [ -n "$prev_state_dir" ] && [ -f "$prev_state_dir/agent.json" ] && under_dir "$prev_state_dir" "$run_home"; then
  # Already enrolled under this user's home: keep the directory, because the
  # enrolment token lives in it and a fresh enrol would need a new code.
  state_dir="$prev_state_dir"
elif [ "$run_uid" = "$invoking_uid" ] && [ -n "${XDG_CONFIG_HOME:-}" ]; then
  state_dir="$XDG_CONFIG_HOME/$BIN_NAME"
else
  state_dir="$run_home/.config/$BIN_NAME"
fi

# A state dir outside the run-as user's home cannot be read by User=<name>.
if [ "$system_mode" = "1" ] && [ "$run_uid" != "0" ] && ! under_dir "$state_dir" "$run_home"; then
  warn "state dir '$state_dir' is outside '$run_home'; the unit runs as '$run_as' and must be able to read it"
fi

migrate_from=""
if [ -n "$prev_state_dir" ] && [ "$prev_state_dir" != "$state_dir" ] &&
   [ -f "$prev_state_dir/agent.json" ] && [ ! -f "$state_dir/agent.json" ]; then
  migrate_from="$prev_state_dir"
fi

# The state dir must be identical for enrol and for the unit that runs `run`,
# or `run` reports a missing agent.json. Resolve it once, here.
export HOME="$run_home"
export CLAUDESWAP_STATE_DIR="$state_dir"

bin_dir="$run_home/.local/bin"
bin_path="$bin_dir/$BIN_NAME"

# -------------------------------------------------------- systemd --user bus

# `systemctl --user` needs both of these, and a non-login shell (su, cron, a
# pipe into bash) has neither. Export them before every --user call and print
# them in every hint, so a copied command works in the next shell too.
user_bus_ok=0
user_runtime_dir="$RUNTIME_BASE/$run_uid"
setup_user_bus() {
  if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    export XDG_RUNTIME_DIR="$user_runtime_dir"
  fi
  if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
  fi
  if [ -d "$XDG_RUNTIME_DIR" ]; then
    user_bus_ok=1
    return 0
  fi
  # No /run/user/<uid> means logind never started a user manager for this
  # account: either nobody is logged in as it, or linger is off.
  warn "$XDG_RUNTIME_DIR does not exist: there is no systemd user manager for '$run_as' (linger is not enabled, or the account has never logged in)"
  warn "remedy: sudo loginctl enable-linger $run_as    (or install a system unit instead: sudo CLAUDESWAP_RUN_AS=$run_as bash $0 --system)"
  warn "falling back to systemctl --user --machine=$run_as@.host"
  return 0
}

# uctl runs one `systemctl --user` command, with the --machine fallback when
# this session has no runtime dir of its own.
uctl() {
  if [ "$user_bus_ok" = "1" ]; then
    act systemctl --user "$@"
  else
    act systemctl --user --machine="$run_as@.host" "$@"
  fi
}

# user_bus_hint prints the two exports a hint needs, indented and resolved, so
# the lines can be pasted into any shell as they stand.
user_bus_hint() {
  printf '  export XDG_RUNTIME_DIR=%s\n' "$XDG_RUNTIME_DIR"
  printf '  export DBUS_SESSION_BUS_ADDRESS=unix:path=%s/bus\n' "$XDG_RUNTIME_DIR"
}

if [ "$system_mode" = "0" ]; then
  setup_user_bus
fi

# ---------------------------------------------------------------- plan

if [ "$DRY_RUN" = "1" ]; then
  step "dry run: nothing below is executed"
fi
if [ "$system_mode" = "1" ]; then
  step "mode system (unit runs as User=$run_as Group=$run_as)"
else
  step "mode user (systemd --user unit for $run_as)"
fi
step "run as $run_as (uid $run_uid), home $run_home"
step "state dir $state_dir"
step "unit $unit_path"
step "server $CLAUDESWAP_SERVER, pin ${CLAUDESWAP_PIN:0:8}..."
if [ -n "$migrate_from" ]; then
  step "migrating the existing enrolment from $migrate_from"
fi

# as_run_as runs a command as the run-as user. The inherited environment, and
# with it CLAUDESWAP_ENROL_CODE, travels through: the code is never an argument.
as_run_as() {
  if [ "$run_uid" = "$invoking_uid" ]; then
    "$@"
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "$run_as" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$run_as" --preserve-env=CLAUDESWAP_ENROL_CODE -- "$@"
  else
    die "neither runuser nor sudo is installed: cannot run the agent as '$run_as'"
  fi
}

# own hands a path to the run-as user. A no-op unless we are root installing for
# somebody else; without it the unit's User= cannot exec the binary or read
# agent.json, and systemd fails with a bare status=203/EXEC.
own() { # <path...>
  if [ "$run_uid" = "$invoking_uid" ] || [ "$invoking_uid" != "0" ]; then
    return 0
  fi
  act chown -R "$run_uid:$run_gid" "$@"
}

# ------------------------------------------------------------- reconfigure

# Stop whichever unit is already running before the binary and the unit under it
# are replaced, so a switch between the two modes does not leave two agents up.
if [ "$RECONFIGURE" = "1" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    if [ -f "$sys_unit_path" ]; then
      step "stopping the existing system unit"
      act systemctl disable --now "$UNIT_NAME" || warn "could not stop the system unit; continuing"
    fi
    if [ -f "$user_unit_path" ]; then
      step "stopping the existing user unit"
      if [ "$system_mode" = "1" ] && [ "$run_uid" != "$invoking_uid" ]; then
        # A user unit of another account is only reachable through its own bus.
        act systemctl --user --machine="$run_as@.host" disable --now "$UNIT_NAME" ||
          warn "could not stop the user unit of '$run_as'; stop it by hand with: sudo -u $run_as XDG_RUNTIME_DIR=$user_runtime_dir systemctl --user disable --now $UNIT_NAME"
      else
        setup_user_bus
        uctl disable --now "$UNIT_NAME" || warn "could not stop the user unit; continuing"
      fi
    fi
  else
    warn "systemctl not found: stop any running agent yourself before continuing"
  fi
fi

# ---------------------------------------------------------------- binary

umask 077
act mkdir -p "$bin_dir"
[ -d "$bin_dir" ] || [ "$DRY_RUN" = "1" ] || die "could not create $bin_dir"

# A fresh download lands in its own empty directory and is never executed from there.
work=""
cleanup() { [ -z "$work" ] || rm -rf "$work"; }
trap cleanup EXIT

source_bin="${CLAUDESWAP_AGENT_BIN:-}"
if [ -n "$source_bin" ]; then
  [ -f "$source_bin" ] || die "CLAUDESWAP_AGENT_BIN $source_bin is not a file"
  step "using local binary $source_bin"
else
  step "downloading $CLAUDESWAP_AGENT_URL"
  if [ "$DRY_RUN" = "1" ]; then
    printf 'DRY-RUN: download %s and verify sha256 %s\n' "$CLAUDESWAP_AGENT_URL" "$CLAUDESWAP_AGENT_SHA256"
    source_bin=""
  else
    work="$(mktemp -d)"
    source_bin="$work/$BIN_NAME"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=https' --tlsv1.2 -o "$source_bin" -- "$CLAUDESWAP_AGENT_URL"
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$source_bin" -- "$CLAUDESWAP_AGENT_URL"
    else
      die "neither curl nor wget is installed"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      got="$(sha256sum "$source_bin" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
      got="$(shasum -a 256 "$source_bin" | cut -d' ' -f1)"
    else
      die "neither sha256sum nor shasum is installed: cannot verify the download"
    fi
    want="$(printf '%s' "$CLAUDESWAP_AGENT_SHA256" | tr '[:upper:]' '[:lower:]')"
    [ "$got" = "$want" ] || die "sha256 mismatch: got $got, expected $want"
    step "sha256 verified"
  fi
fi

# Replace by rename, so re-running while the agent is executing the old file works.
if [ "$DRY_RUN" = "1" ]; then
  printf 'DRY-RUN: install binary to %s (mode 0700)\n' "$bin_path"
else
  staged="$bin_path.new.$$"
  cp -f -- "$source_bin" "$staged"
  chmod 0700 "$staged"
  mv -f -- "$staged" "$bin_path"
  step "installed $bin_path"
fi
own "$bin_dir"

# ---------------------------------------------------------------- enrol

if [ -n "$migrate_from" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    printf 'DRY-RUN: copy %s to %s so the host stays enrolled\n' "$migrate_from/agent.json" "$state_dir"
  else
    mkdir -p "$state_dir"
    chmod 0700 "$state_dir"
    cp -p -- "$migrate_from/agent.json" "$state_dir/agent.json"
    step "kept the enrolment: copied agent.json into $state_dir"
  fi
  own "$state_dir"
fi

if [ -f "$state_dir/agent.json" ]; then
  step "already enrolled ($state_dir/agent.json exists): skipping enrol"
elif [ "$DRY_RUN" = "1" ]; then
  printf 'DRY-RUN: %s enrol --server %s --pin <pin> (code from CLAUDESWAP_ENROL_CODE, as user %s)\n' "$bin_path" "$CLAUDESWAP_SERVER" "$run_as"
else
  act mkdir -p "$state_dir"
  act chmod 0700 "$state_dir"
  own "$state_dir"
  if [ -n "${CLAUDESWAP_ENROL_CODE:-}" ]; then
    step "enrolling with a one-time code"
  else
    step "enrolling: an admin must approve this host in the web UI (up to 10 minutes)"
  fi
  # The code reaches the child through the environment it already arrived in.
  # It is never an argument and never printed. HOME and the state dir are not
  # secret, so they may cross the user switch on the command line.
  if [ "$run_uid" = "$invoking_uid" ]; then
    "$bin_path" enrol --server "$CLAUDESWAP_SERVER" --pin "$CLAUDESWAP_PIN"
  else
    as_run_as env "HOME=$run_home" "CLAUDESWAP_STATE_DIR=$state_dir" \
      "$bin_path" enrol --server "$CLAUDESWAP_SERVER" --pin "$CLAUDESWAP_PIN"
  fi
  own "$state_dir"
fi
unset CLAUDESWAP_ENROL_CODE

# ---------------------------------------------------------------- service

# render_system_unit prints the system unit. No ProtectHome: the agent must read
# the run-as user's ~/.claude.json and ~/.claude/.credentials.json, which is the
# whole job. NoNewPrivileges and PrivateTmp cost it nothing.
render_system_unit() {
  cat <<UNITEOF
[Unit]
Description=Claude Swap agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=$run_as
Group=$run_group
ExecStart="$bin_path" run
Environment="CLAUDESWAP_STATE_DIR=$state_dir"
Environment="HOME=$run_home"
WorkingDirectory=$run_home
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNITEOF
}

if [ "$system_mode" = "1" ]; then
  # Group=: the user's primary group by gid, so a distribution that puts people
  # in a shared group (users, staff) still gets a unit systemd will start.
  run_group="$(getent group "$run_gid" 2>/dev/null | cut -d: -f1 || true)"
  [ -n "$run_group" ] || run_group="$run_as"

  step "writing the systemd system unit $unit_path"
  if [ "$DRY_RUN" = "1" ]; then
    printf 'DRY-RUN: write %s with User=%s Group=%s (mode 0644)\n' "$unit_path" "$run_as" "$run_group"
  else
    mkdir -p "$SYSTEM_UNIT_DIR"
    staged_unit="$unit_path.new.$$"
    render_system_unit >"$staged_unit"
    chmod 0644 "$staged_unit" # a system unit is read by systemd, and holds no secret
    mv -f -- "$staged_unit" "$unit_path"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    act systemctl daemon-reload
    act systemctl enable --now "$UNIT_NAME"
    step "service enabled and started"
  else
    step "systemctl not found: start the agent yourself with '$bin_path run'"
  fi
else
  # `agent install` is what writes the user unit: it bakes in this exe path and
  # CLAUDESWAP_STATE_DIR, creates the state dir 0700 and writes the unit 0600.
  step "writing the systemd user unit"
  act "$bin_path" install

  if command -v systemctl >/dev/null 2>&1; then
    uctl daemon-reload
    uctl enable --now "$UNIT_NAME"
    step "service enabled and started"
  else
    step "systemctl not found: start the agent yourself with '$bin_path run'"
  fi
fi

if [ "$system_mode" = "1" ]; then
  cat <<EOF

done. unit: $unit_path, running as $run_as

  status:  systemctl status $UNIT_NAME
  logs:    journalctl -u $UNIT_NAME -f
  restart: systemctl restart $UNIT_NAME

A system unit needs no linger: it starts at boot and survives every logout.

Sign in on this host as '$run_as', not as root unless that is the run-as user:
'claude auth login' writes ~/.claude.json in the home of the user that runs it,
and the agent only reads the one home it was installed for ($run_home).
EOF
else
  cat <<EOF

done. unit: $unit_path

'systemctl --user' needs a session bus. Export these first, in any shell:

$(user_bus_hint)
  systemctl --user status $UNIT_NAME
  journalctl --user -u $UNIT_NAME -f

To keep the agent running when you are not logged in:

  loginctl enable-linger $run_as

Or install a system unit instead, which needs no linger:

  sudo CLAUDESWAP_RUN_AS=$run_as bash $0 --system --reconfigure

Sign in with 'claude auth login' as '$run_as': the agent reads the ~/.claude.json
in $run_home and nowhere else.
EOF
fi

if [ "$bin_dir" != "/usr/local/bin" ]; then
  printf "\nIf '%s' is not on PATH, add it to run '%s' by name.\n" "$bin_dir" "$BIN_NAME"
fi
