#!/usr/bin/env bash
# scripts/install-agent.sh - install and enrol the claude-swap agent on a Linux host.
#
# One command, no flags: every input arrives in the environment, because an
# enrolment code on a command line is readable by every user on the host
# through /proc/<pid>/cmdline.
#
#   required  CLAUDESWAP_SERVER          https://host:port of the server
#             CLAUDESWAP_PIN             server certificate sha256 (64 hex chars)
#   binary    CLAUDESWAP_AGENT_BIN       path to a linux agent binary to copy, OR
#             CLAUDESWAP_AGENT_URL       URL to download, which then requires
#             CLAUDESWAP_AGENT_SHA256    its expected sha256 (64 hex chars)
#   optional  CLAUDESWAP_ENROL_CODE      one-time code; without it the enrolment
#                                        waits for an admin to approve this host
#             CLAUDESWAP_STATE_DIR       state dir override; the same value is
#                                        used for enrol and baked into the unit
#             CLAUDESWAP_DRY_RUN=1       print every action, change nothing
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

die() { printf 'install-agent: %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }

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
[ -n "${HOME:-}" ] || die "HOME is not set"

# The state dir must be identical for enrol and for the unit that runs `run`,
# or `run` reports a missing agent.json. Resolve it once, here.
config_base="${XDG_CONFIG_HOME:-$HOME/.config}"
state_dir="${CLAUDESWAP_STATE_DIR:-$config_base/claude-swap-agent}"
export CLAUDESWAP_STATE_DIR="$state_dir"

bin_dir="$HOME/.local/bin"
bin_path="$bin_dir/$BIN_NAME"
unit_path="$HOME/.config/systemd/user/$UNIT_NAME"

if [ "$DRY_RUN" = "1" ]; then
  step "dry run: nothing below is executed"
fi
step "server $CLAUDESWAP_SERVER, pin ${CLAUDESWAP_PIN:0:8}..., state dir $state_dir"

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

# ---------------------------------------------------------------- enrol

if [ -f "$state_dir/agent.json" ]; then
  step "already enrolled ($state_dir/agent.json exists): skipping enrol"
elif [ "$DRY_RUN" = "1" ]; then
  printf 'DRY-RUN: %s enrol --server %s --pin <pin> (code from CLAUDESWAP_ENROL_CODE)\n' "$bin_path" "$CLAUDESWAP_SERVER"
else
  act mkdir -p "$state_dir"
  act chmod 0700 "$state_dir"
  if [ -n "${CLAUDESWAP_ENROL_CODE:-}" ]; then
    step "enrolling with a one-time code"
  else
    step "enrolling: an admin must approve this host in the web UI (up to 10 minutes)"
  fi
  # The code reaches the child through the environment it already arrived in.
  # It is never an argument and never printed.
  "$bin_path" enrol --server "$CLAUDESWAP_SERVER" --pin "$CLAUDESWAP_PIN"
fi
unset CLAUDESWAP_ENROL_CODE

# ---------------------------------------------------------------- service

# `agent install` is what writes the unit: it bakes in this exe path and
# CLAUDESWAP_STATE_DIR, creates the state dir 0700 and writes the unit 0600.
step "writing the systemd user unit"
act "$bin_path" install

if command -v systemctl >/dev/null 2>&1; then
  act systemctl --user daemon-reload
  act systemctl --user enable --now "$UNIT_NAME"
  step "service enabled and started"
else
  step "systemctl not found: start the agent yourself with '$bin_path run'"
fi

cat <<EOF

done. unit: $unit_path

  status:  systemctl --user status $UNIT_NAME
  logs:    journalctl --user -u $UNIT_NAME -f

To keep the agent running when you are not logged in:

  loginctl enable-linger \$USER

If '$bin_dir' is not on your PATH, add it to run '$BIN_NAME' by name.
EOF
