#!/usr/bin/env bash
# _verify/cases/vault-migrate.sh - migrate the committed v1 golden in a throwaway data dir and
# prove the four claims the command makes: a dry run writes nothing, the v1 copy is kept, the file
# opens under every slot afterwards, and the certificate fingerprint every agent pins is unchanged.
#
# Exit 0 = all green, 1 = a check failed, 77 = cannot run here (skipped, NOT verified).
#
# Nothing here goes near a real data dir, a real credstore or a host's live vault: the data dir is a
# mktemp -d that is removed on exit, the passphrase is the golden fixture's own fake one, and the KEK
# is 32 bytes of /dev/urandom written into that same temp dir and pointed at by CLAUDESWAP_KEK_FILE.
# readonly: no
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

if command -v go >/dev/null 2>&1; then GO=go
elif command -v go.exe >/dev/null 2>&1; then GO=go.exe
else echo "go not installed"; exit 77; fi
command -v openssl >/dev/null 2>&1 || { echo "openssl not installed (needed for the tls fixture)"; exit 77; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum not installed"; exit 77; }

GOLDEN_V1="internal/vault/testdata/vault-v1.bin"
[ -f "$GOLDEN_V1" ] || { echo "FAIL $GOLDEN_V1 is missing"; exit 1; }

# The golden fixture's own fake passphrase, as internal/vault/golden_test.go declares it. It seals a
# fixture holding a fake account and a fake token; it is not a secret and it opens nothing real.
FIXTURE_PASS="golden-fixture-passphrase-not-a-real-one"

TMP="$(mktemp -d)" || { echo "FAIL mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/server"
[ "$GO" = "go.exe" ] && BIN="$TMP/server.exe"

"$GO" build -o "$BIN" ./cmd/server || { echo "cannot build cmd/server"; exit 77; }

D="$TMP/data"
mkdir -p "$D/tls" || { echo "FAIL mkdir"; exit 1; }
cp "$GOLDEN_V1" "$D/vault.bin" || { echo "FAIL copy the golden"; exit 1; }
chmod 600 "$D/vault.bin"

# A throwaway TLS pair, so the pin continuity check has something to compare. It is never used to
# serve anything.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=claude-swap-verify" \
  -keyout "$D/tls/server-key.pem" -out "$D/tls/server-cert.pem" >/dev/null 2>&1 \
  || { echo "cannot generate a tls fixture with openssl"; exit 77; }
chmod 600 "$D/tls/server-key.pem" "$D/tls/server-cert.pem"

# A throwaway 32-byte KEK for the machine slot. On this script's platforms the kek-file route is the
# one that needs no credstore, no unit and no root.
head -c 32 /dev/urandom > "$TMP/kek" || { echo "FAIL write the kek"; exit 1; }
chmod 600 "$TMP/kek"
export CLAUDESWAP_KEK_FILE="$TMP/kek"
export CLAUDESWAP_KEY="$FIXTURE_PASS"
unset CREDENTIALS_DIRECTORY

rc=0
fail() { echo "FAIL $*"; rc=1; }

fp_before="$(sha256sum "$D/tls/server-cert.pem" | cut -d' ' -f1)"
# Everything in the data dir except the lock, which every mutator takes before it knows whether it
# will refuse.
snapshot() { find "$D" -type f ! -name '.claude-swap.lock' -print0 | sort -z | xargs -0 sha256sum 2>/dev/null; }
snap_before="$(snapshot)"

# 1. The dry run writes nothing at all.
out="$("$BIN" vault migrate --data-dir "$D" --dry-run 2>&1)"
code=$?
[ "$code" -eq 0 ] || fail "vault migrate --dry-run exit $code: $out"
case "$out" in
  *"dry run, nothing was written"*) ;;
  *) fail "the dry run does not say it wrote nothing: $out" ;;
esac
[ "$(snapshot)" = "$snap_before" ] || fail "the dry run changed the data dir"
[ -e "$D/vaultop.journal" ] && fail "the dry run wrote the journal"

# 2. The real run.
out="$("$BIN" vault migrate --data-dir "$D" 2>&1)"
code=$?
[ "$code" -eq 0 ] || fail "vault migrate exit $code: $out"
head -c 4 "$D/vault.bin" | grep -q 'CSV2' || fail "vault.bin is not CSV2 after the migration"
copies="$(find "$D" -maxdepth 1 -type f -name 'vault.bin.v1.*' | wc -l)"
[ "$copies" -eq 1 ] || fail "found $copies vault.bin.v1.<ts> copies, want 1"
for c in "$D"/vault.bin.v1.*; do
  head -c 4 "$c" | grep -q 'CSV1' || fail "$(basename "$c") is not a CSV1 copy"
  cmp -s "$c" "$GOLDEN_V1" || fail "$(basename "$c") is not the v1 file it copied"
done
case "$out" in
  *"and proved it opens with the passphrase"*) ;;
  *) fail "the run does not report proving the v1 copy: $out" ;;
esac
[ -e "$D/vaultop.journal" ] && fail "the journal survived a finished migration"
# No temp file: a .vault-*.tmp beside the vault is how an operator copies a half-written envelope
# over a working one.
leftovers="$(find "$D" -maxdepth 1 -type f -name '*.tmp' | wc -l)"
[ "$leftovers" -eq 0 ] || fail "$leftovers temp files were left behind"

# 3. Every slot opens it.
out="$("$BIN" vault verify --data-dir "$D" --all-slots 2>&1)"
code=$?
[ "$code" -eq 0 ] || fail "vault verify --all-slots exit $code: $out"
case "$out" in
  *"opened and parsed"*) ;;
  *) fail "verify does not report the payload: $out" ;;
esac

# 4. The pin is unchanged. This is the one failure that would de-enrol a whole fleet.
fp_after="$(sha256sum "$D/tls/server-cert.pem" | cut -d' ' -f1)"
[ "$fp_before" = "$fp_after" ] || fail "the certificate changed across the migration"

# 5. Idempotent: a second migrate is exit 0 with nothing done, which is what an installer calls.
out="$("$BIN" vault migrate --data-dir "$D" 2>&1)"
code=$?
[ "$code" -eq 0 ] || fail "a second vault migrate exit $code, want 0: $out"
case "$out" in
  *"already v2"*) ;;
  *) fail "a second migrate does not say the vault was already v2: $out" ;;
esac

# 6. The rollback, read by a binary that only has to read CSV1 - here, the format test.
out="$("$BIN" vault downgrade --data-dir "$D" 2>&1)"
code=$?
[ "$code" -eq 0 ] || fail "vault downgrade exit $code: $out"
head -c 4 "$D/vault.bin" | grep -q 'CSV1' || fail "vault.bin is not CSV1 after the downgrade"
kept="$(find "$D" -maxdepth 1 -type f -name 'vault.bin.v2.*' | wc -l)"
[ "$kept" -eq 1 ] || fail "found $kept vault.bin.v2.<ts> generations, want 1"

[ "$rc" -eq 0 ] && echo "ok vault-migrate"
exit "$rc"
