package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/vault"
)

// Tests for `server vault migrate` and `server vault downgrade`.
//
// Every fixture is a t.TempDir() with every environment input pinned: no inherited passphrase, no
// credentials directory, no KEK file but the one the test wrote. Nothing here can reach a real data
// dir, a real credstore, a real certificate or a host's live vault.
//
// The two seams that shell out or read the machine are replaced in every test by migrateFixture:
// serviceState (the SCM) and fdeStatus (manage-bde / lsblk). A test that let either through would be
// asserting the machine it runs on, and on a developer's Windows box fdeStatus would be a real
// BitLocker query from a unit test.

// v1DataDir is a data dir holding a real v1 vault.bin, and a v1 tunnelkeys.bin when keyring is set.
// Both go through the exported openers, which is what a pre-v2 server left behind: create-on-open
// writes v1 and still does (TestADefaultRunCannotCreateAV2Vault).
func v1DataDir(t *testing.T, keyring bool) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(keyEnv, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("CLAUDESWAP_KEK_FILE", "")
	v, err := vault.Open(filepath.Join(dir, "vault.bin"), typedKey{pass: fixturePass})
	if err != nil {
		t.Fatalf("seed a v1 vault: %v", err)
	}
	if err := v.Put(vault.Account{ID: "acct-1", Label: "Account One", Identity: "one@example.invalid",
		Block: json.RawMessage(`{"accessToken":"FAKE-TEST-TOKEN"}`), Updated: time.Unix(1700000000, 0).UTC()}); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	if keyring {
		k, kerr := vault.OpenKeyring(filepath.Join(dir, vault.KeyringFileName), typedKey{pass: fixturePass})
		if kerr != nil {
			t.Fatalf("seed a v1 keyring: %v", kerr)
		}
		if _, kerr := k.Generate("host-1"); kerr != nil {
			t.Fatalf("seed Generate: %v", kerr)
		}
	}
	return dir
}

// withTLSFixture writes a throwaway self-signed pair under dir/tls and returns the sha256 of its
// DER - the value every enrolled agent would pin. It is computed here with its own hash call, so
// the assertion that migrate prints the right fingerprint is not certFingerprint agreeing with
// itself.
func withTLSFixture(t *testing.T, dir string) string {
	t.Helper()
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatalf("mkdir tls: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "claude-swap-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(tlsDir, "server-cert.pem"), certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// The number migrate prints has to be the number agents pin, and migrate computes it itself rather
// than through internal/hub (see certFingerprint for why: the only exported route CREATES a pair).
// This is the assertion that makes that duplication safe rather than merely small - the two agree
// on a pair hub generated.
//
// They could disagree: hub hashes cert.Raw from the pair it just wrote, and certFingerprint hashes
// the DER it gets from a pem.Decode plus an x509 parse. For a well-formed single-certificate PEM
// those are the same bytes; for a PEM with leading text or a chain they would not be, and the
// failure mode of being wrong here is de-enrolling every agent.
func TestCertFingerprintAgreesWithTheValueHubReports(t *testing.T) {
	dir := t.TempDir()
	_, _, hubFP, err := hub.EnsureCert(filepath.Join(dir, "tls"))
	if err != nil {
		t.Fatalf("hub.EnsureCert: %v", err)
	}
	ours, err := certFingerprint(dir)
	if err != nil {
		t.Fatalf("certFingerprint: %v", err)
	}
	if ours != hubFP {
		t.Fatalf("certFingerprint = %s and hub reports %s: migrate would print a value no agent pins",
			ours, hubFP)
	}
}

// And the test fixture's own hash agrees too, so every assertion below that compares against
// withTLSFixture's return value is comparing against the real pin.
func TestCertFingerprintAgreesWithTheFixturesOwnHash(t *testing.T) {
	dir := t.TempDir()
	want := withTLSFixture(t, dir)
	got, err := certFingerprint(dir)
	if err != nil {
		t.Fatalf("certFingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("certFingerprint = %s, the fixture's own sha256 of the DER = %s", got, want)
	}
}

// migrateFixture is a data dir ready for a scripted migrate: a v1 vault (and keyring), a TLS pair,
// this host's machine key, the passphrase in the environment, and both machine-reading seams
// replaced. It returns the dir and the fingerprint.
func migrateFixture(t *testing.T, keyring bool) (string, string) {
	t.Helper()
	dir := v1DataDir(t, keyring)
	fp := withTLSFixture(t, dir)
	withHostMachineKey(t)
	t.Setenv(keyEnv, fixturePass)
	pinMachineSeams(t, true)
	return dir, fp
}

// pinMachineSeams replaces the two seams that would otherwise read the machine: the registered
// service's state and the full-disk-encryption probe.
func pinMachineSeams(t *testing.T, serviceStopped bool) {
	t.Helper()
	prevSvc, prevFDE := serviceState, fdeStatus
	serviceState = func() (string, bool, bool, error) {
		return "ClaudeSwapServer", serviceStopped, !serviceStopped, nil
	}
	fdeStatus = func() (bool, string, error) { return false, "the test's pinned answer", nil }
	t.Cleanup(func() { serviceState, fdeStatus = prevSvc, prevFDE })
}

// dirSnapshot is every regular file under dir with its bytes, recursively. It is the "nothing was
// written" recorder: a dry run that created a KEK, a drop-in, a copy or a journal changes it.
//
// The data-dir lock file is excluded, and only it. Every mutator takes the lock as its first act -
// before it knows whether it will refuse - so its creation and its holder line are not a write to
// the vault's state; they are how the command announces itself to the next one. Everything else
// under the dir, tls/ included, is compared byte for byte.
func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Name() == vault.LockFileName {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Clean(p))
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

func assertSnapshotUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	after := dirSnapshot(t, dir)
	if len(before) != len(after) {
		t.Fatalf("the data dir went from %d files to %d: %v -> %v", len(before), len(after),
			keysOf(before), keysOf(after))
	}
	for name, want := range before {
		got, ok := after[name]
		if !ok {
			t.Fatalf("%s disappeared", name)
		}
		if got != want {
			t.Fatalf("%s changed", name)
		}
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// migrateRun runs a scripted migrate and returns its exit code and output.
func migrateRun(t *testing.T, dir string, dryRun bool) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := vaultMigrate(dir, dryRun, "", false, strings.NewReader(""), &out)
	return code, out.String()
}

// --- the happy path ---

// The baseline, and the ordering with it: the copy is kept and PROVED before the file is replaced,
// which the printed order is the recorder for - the "kept ... and proved it opens" line has to come
// before the line that reports the new format.
func TestMigrateWritesTheV1CopyBeforeTheV2File(t *testing.T) {
	dir, _ := migrateFixture(t, true)
	v1Bytes := mustRead(t, filepath.Join(dir, "vault.bin"))

	code, out := migrateRun(t, dir, false)
	if code != 0 {
		t.Fatalf("vault migrate exit %d, want 0: %s", code, out)
	}
	kept := strings.Index(out, "and proved it opens with the passphrase")
	became := strings.Index(out, "vault.bin is v2")
	if kept < 0 || became < 0 || kept > became {
		t.Fatalf("the copy was not reported before the replacement (kept at %d, v2 at %d): %s", kept, became, out)
	}
	// And the copy is on disk, byte-identical to the file that was there.
	copies := generationsIn(t, dir, ".v1.")
	if len(copies) != 2 {
		t.Fatalf("found %d v1 copies, want one per migrated file: %v", len(copies), copies)
	}
	for _, name := range copies {
		if strings.HasPrefix(name, "vault.bin") {
			if got := mustRead(t, filepath.Join(dir, name)); !bytes.Equal(got, v1Bytes) {
				t.Fatalf("%s is not the v1 file it copied", name)
			}
		}
		if info, err := vault.Inspect(filepath.Join(dir, name)); err != nil || info.Format != vault.FormatV1 {
			t.Fatalf("%s is %s (err %v), want v1", name, info.Format, err)
		}
	}
	for _, name := range []string{"vault.bin", vault.KeyringFileName} {
		info, err := vault.Inspect(filepath.Join(dir, name))
		if err != nil || info.Format != vault.FormatV2 || len(info.Slots) != 2 {
			t.Fatalf("%s is %s with %d slots (err %v), want v2 with 2", name, info.Format, len(info.Slots), err)
		}
	}
	// The journal is gone again: a finished migration leaves nothing for the next command to settle.
	if _, ok, err := vault.ReadVaultOp(dir); ok || err != nil {
		t.Fatalf("the journal survived a finished migrate: ok %v err %v", ok, err)
	}
}

// generationsIn lists the stored generations in dir whose name contains frag.
func generationsIn(t *testing.T, dir, frag string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.Contains(e.Name(), frag) {
			out = append(out, e.Name())
		}
	}
	return out
}

// Both slots are proved, with the two checks that mean different things, and the migrated vault
// still holds the account it held.
func TestMigrateVerifiesWithEachSlotAndKeepsTheAccounts(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	if code, out := migrateRun(t, dir, false); code != 0 {
		t.Fatalf("vault migrate exit %d: %s", code, out)
	}
	path := filepath.Join(dir, "vault.bin")
	// The machine slot alone - exactly what a service has.
	res, err := vault.VerifyFile(path, vault.WithMachineKeys(nil, hostKeyOptions()), false)
	if err != nil || !res.PayloadOK {
		t.Fatalf("the migrated vault does not open under the machine slot alone: %v", err)
	}
	v, err := vault.Open(path, typedKey{pass: fixturePass})
	if err != nil {
		t.Fatalf("the migrated vault does not open under the passphrase: %v", err)
	}
	got, ok := v.Get("acct-1")
	if !ok || got.Label != "Account One" || !strings.Contains(string(got.Block), "FAKE-TEST-TOKEN") {
		t.Fatalf("the account did not survive the migration: %+v ok=%v", got, ok)
	}
}

// The passphrase is re-wrapped and not changed, and the output says so: the operator's mental model
// after a migration is "the vault is machine-sealed now", and the same secret is still the key.
func TestMigrateReWrapsThePassphraseItDoesNotChangeIt(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	_, out := migrateRun(t, dir, false)
	if !strings.Contains(out, "RE-WRAPPED, not changed") {
		t.Fatalf("the output does not say the passphrase was re-wrapped rather than changed: %s", out)
	}
	if _, err := vault.Open(filepath.Join(dir, "vault.bin"), typedKey{pass: fixturePass}); err != nil {
		t.Fatalf("the passphrase that opened the v1 vault does not open the v2 one: %v", err)
	}
	if _, err := vault.Open(filepath.Join(dir, "vault.bin"), typedKey{pass: "something-else"}); !errors.Is(err, vault.ErrBadKey) {
		t.Fatalf("a passphrase that never opened this vault opens the migrated one: %v", err)
	}
}

// The fingerprint is printed before and after and compared, and the value is the real one: computed
// here with its own sha256 over the DER rather than taken from certFingerprint.
func TestMigrateComparesTheFingerprintBeforeAndAfter(t *testing.T) {
	dir, fp := migrateFixture(t, false)
	code, out := migrateRun(t, dir, false)
	if code != 0 {
		t.Fatalf("vault migrate exit %d: %s", code, out)
	}
	if strings.Count(out, fp) < 2 {
		t.Fatalf("the output does not carry the fingerprint %s twice:\n%s", fp, out)
	}
	if !strings.Contains(out, "unchanged, so every agent's pin still matches") {
		t.Fatalf("the output does not say the pin is unchanged: %s", out)
	}
}

// The three ways back, and the date finalize becomes advisable. They are what an operator writes
// down at that moment, so a migration that succeeded and said nothing would be a worse outcome than
// one that failed loudly.
func TestMigratePrintsTheThreeRecoveryLinesAndTheFinalizeDate(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	_, out := migrateRun(t, dir, false)
	for _, want := range []string{
		"recovery, three ways:",
		"`server vault downgrade` writes v1 files again",
		"back over vault.bin and start the old binary",
		"`server vault finalize-migration` deletes those copies",
		time.Now().UTC().Add(finalizeAfter).Format("2006-01-02"),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output is missing %q:\n%s", want, out)
		}
	}
}

// A v1 `.bak` is renamed into the `*.v1.<ts>` inventory. Nothing in normal use would ever replace
// it, so left under its own name it would outlive every other v1 artefact and keep every account
// openable by the passphrase alone indefinitely.
func TestMigrateRenamesACSV1BakToBakV1Timestamp(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	live := filepath.Join(dir, "vault.bin")
	bak := live + ".bak"
	if err := os.WriteFile(bak, mustRead(t, live), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := migrateRun(t, dir, false)
	if code != 0 {
		t.Fatalf("vault migrate exit %d: %s", code, out)
	}
	if _, err := os.Stat(bak); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("vault.bin.bak is still there under its own name (stat err %v)", err)
	}
	found := false
	for _, name := range generationsIn(t, dir, ".bak.v1.") {
		found = true
		if info, ierr := vault.Inspect(filepath.Join(dir, name)); ierr != nil || info.Format != vault.FormatV1 {
			t.Fatalf("%s is %s (err %v), want v1", name, info.Format, ierr)
		}
	}
	if !found {
		t.Fatalf("no vault.bin.bak.v1.<ts> was created: %v", generationsIn(t, dir, "bak"))
	}
	if !strings.Contains(out, "renamed the v1 recovery copy") {
		t.Fatalf("the output does not report the rename: %s", out)
	}
}

// --- the dry run ---

// Nothing at all, on either OS: no KEK, no drop-in, no daemon-reload, no v1 copy, no journal, and
// no replaced file. The recorder is every byte under the data dir.
func TestMigrateDryRunWritesNothing(t *testing.T) {
	dir, _ := migrateFixture(t, true)
	before := dirSnapshot(t, dir)
	code, out := migrateRun(t, dir, true)
	if code != 0 {
		t.Fatalf("vault migrate --dry-run exit %d, want 0: %s", code, out)
	}
	assertSnapshotUnchanged(t, dir, before)
	if _, ok, err := vault.ReadVaultOp(dir); ok || err != nil {
		t.Fatalf("a dry run wrote the journal: ok %v err %v", ok, err)
	}
}

// What the plan has to say, including the one line Decision 14 exists for: which of the threats an
// operator is actually relying on being closed.
func TestMigrateDryRunPrintsThePlanAndTheEncryptionStatus(t *testing.T) {
	dir, fp := migrateFixture(t, false)
	_, out := migrateRun(t, dir, true)
	for _, want := range []string{
		"dry run, nothing was written",
		"vault.bin is v1 and would become v2",
		"read back and opened with the passphrase before anything is replaced",
		"machine slot ",
		"volume encryption: OFF - the test's pinned answer",
		"nothing here protects a disk image",
		fp,
		"run it again without --dry-run",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the dry run's output is missing %q:\n%s", want, out)
		}
	}
}

// A probe that is not there is UNKNOWN, never "off". Claiming a volume is unencrypted because
// manage-bde is missing is the same class of lie as claiming it is encrypted because it is present.
func TestMigrateDryRunReportsAnUnavailableEncryptionProbeAsUnknown(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	prev := fdeStatus
	fdeStatus = func() (bool, string, error) { return false, "", errors.New("injected: no probe here") }
	t.Cleanup(func() { fdeStatus = prev })
	_, out := migrateRun(t, dir, true)
	if !strings.Contains(out, "volume encryption: UNKNOWN") {
		t.Fatalf("an unavailable probe was not reported as unknown: %s", out)
	}
	if strings.Contains(out, "volume encryption: OFF") {
		t.Fatalf("an unavailable probe was reported as off: %s", out)
	}
}

// --- the refusals ---

func TestMigrateRefusesWithNoVault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(keyEnv, fixturePass)
	withHostMachineKey(t)
	pinMachineSeams(t, true)
	withTLSFixture(t, dir)
	code, out := migrateRun(t, dir, false)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "run `server vault init`") {
		t.Fatalf("the refusal does not name init: %s", out)
	}
}

// The pin continuity check needs the pair, so a data dir without it is refused with nothing written
// - including on a dry run, which is where an operator would otherwise read a plan that cannot run.
func TestMigrateRefusesWhenTLSIsMissing(t *testing.T) {
	for _, dry := range []bool{false, true} {
		dir := v1DataDir(t, false)
		withHostMachineKey(t)
		t.Setenv(keyEnv, fixturePass)
		pinMachineSeams(t, true)
		before := dirSnapshot(t, dir)
		code, out := migrateRun(t, dir, dry)
		if code != exitUsage {
			t.Fatalf("dry=%v exit %d, want %d: %s", dry, code, exitUsage, out)
		}
		if !strings.Contains(out, "the pin continuity check needs") {
			t.Fatalf("the refusal does not name the pin: %s", out)
		}
		assertSnapshotUnchanged(t, dir, before)
	}
}

// A mutator while the server runs is last-writer-wins on the next save, so a held lock is exit 2
// with the holder's pid - the fix is to stop that process.
func TestMigrateRefusesWhileTheLockIsHeld(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	held, err := vault.AcquireLock(dir, "run")
	if err != nil {
		t.Fatalf("take the lock: %v", err)
	}
	defer func() { _ = held.Release() }()
	code, out := migrateRun(t, dir, false)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "stop it first") {
		t.Fatalf("the refusal does not say to stop the holder: %s", out)
	}
}

// On Windows the lock alone does not cover a registered service that is mid-start, so the service's
// own state is checked too.
func TestMigrateRefusesWhenTheServiceIsNotStopped(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	pinMachineSeams(t, false)
	before := dirSnapshot(t, dir)
	code, out := migrateRun(t, dir, false)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "is not stopped: stop it first") {
		t.Fatalf("the refusal does not name the service's state: %s", out)
	}
	assertSnapshotUnchanged(t, dir, before)
}

// Step 2's rule, and it has to be its own step: on a dry run there is no replacement to discover a
// wrong passphrase, so an operator would be shown a plan that cannot run.
func TestMigrateWrongPassphraseStopsWithNothingWritten(t *testing.T) {
	for _, dry := range []bool{false, true} {
		dir, _ := migrateFixture(t, true)
		t.Setenv(keyEnv, "not-the-fixture-passphrase")
		before := dirSnapshot(t, dir)
		code, out := migrateRun(t, dir, dry)
		if code != exitVaultLocked {
			t.Fatalf("dry=%v exit %d, want %d: %s", dry, code, exitVaultLocked, out)
		}
		if !strings.Contains(out, "does not open with that passphrase") {
			t.Fatalf("the refusal does not name the passphrase: %s", out)
		}
		assertSnapshotUnchanged(t, dir, before)
	}
}

// Already v2 is exit 0, not 2: the installer calls migrate idempotently and a non-zero exit there
// would fail an install that is in fact correct.
func TestMigrateOnAnAlreadyV2FileExitsZero(t *testing.T) {
	dir, _ := migrateFixture(t, true)
	if code, out := migrateRun(t, dir, false); code != 0 {
		t.Fatalf("the first migrate exit %d: %s", code, out)
	}
	before := dirSnapshot(t, dir)
	code, out := migrateRun(t, dir, false)
	if code != 0 {
		t.Fatalf("a second migrate exit %d, want 0: %s", code, out)
	}
	if !strings.Contains(out, "already v2") || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("the output does not say it was already v2: %s", out)
	}
	assertSnapshotUnchanged(t, dir, before)
}

// --- the mixed pair, and the one repair migrate is allowed to make ---

// mixedPairDir is a data dir whose vault is v2 and whose keyring is still v1: what a crash between
// the two writes leaves.
func mixedPairDir(t *testing.T) string {
	t.Helper()
	dir, _ := migrateFixture(t, true)
	// Migrate the vault alone by moving the keyring out of the way and back.
	ring := filepath.Join(dir, vault.KeyringFileName)
	stash := filepath.Join(t.TempDir(), "ring")
	if err := os.Rename(ring, stash); err != nil {
		t.Fatal(err)
	}
	if code, out := migrateRun(t, dir, false); code != 0 {
		t.Fatalf("seed migrate exit %d: %s", code, out)
	}
	if err := os.Rename(stash, ring); err != nil {
		t.Fatal(err)
	}
	// The copies and the journal from the seeding run are cleared, so the assertions below are about
	// the state under test and not about its scaffolding.
	for _, name := range generationsIn(t, dir, ".v1.") {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A mixed pair with no journal: migrate proceeds on the v1 half, says which, and leaves the v2 half
// exactly as it was.
func TestMigrateOnAMixedPairMigratesOnlyTheV1Half(t *testing.T) {
	dir := mixedPairDir(t)
	vaultBefore := mustRead(t, filepath.Join(dir, "vault.bin"))

	code, out := migrateRun(t, dir, false)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	if !strings.Contains(out, "a mixed pair") || !strings.Contains(out, "Only "+vault.KeyringFileName) {
		t.Fatalf("the output does not say which half is being migrated: %s", out)
	}
	if got := mustRead(t, filepath.Join(dir, "vault.bin")); !bytes.Equal(got, vaultBefore) {
		t.Fatal("the v2 half was rewritten by a migrate that had nothing to do to it")
	}
	if info, err := vault.Inspect(filepath.Join(dir, vault.KeyringFileName)); err != nil || info.Format != vault.FormatV2 {
		t.Fatalf("the keyring is %s (err %v), want v2", info.Format, err)
	}
	// Only the half that was migrated got a copy.
	if copies := generationsIn(t, dir, ".v1."); len(copies) != 1 ||
		!strings.HasPrefix(copies[0], vault.KeyringFileName) {
		t.Fatalf("v1 copies = %v, want one for the keyring alone", copies)
	}
}

// The REPAIR the spec gives migrate and no other command: a mixed pair WITH a journal. Every other
// mutator refuses, because neither branch of a settle is safe there; migrate carries on, because
// migrating the v1 half is what resolves it.
//
// The permission comes from the command, never from the journal: a journal lives in the data dir, so
// anyone who can write there can write one claiming to be a migrate.
func TestMigrateRepairsAMixedPairWithAJournalWhileOtherMutatorsRefuse(t *testing.T) {
	dir := mixedPairDir(t)
	// A journal shaped like the one a crash between the two writes would have left behind.
	interrupted := vault.VaultOp{Op: "migrate", Files: []string{"vault.bin", vault.KeyringFileName},
		Stage: vault.StageBak}
	if err := vault.WriteVaultOp(dir, interrupted); err != nil {
		t.Fatalf("write the journal: %v", err)
	}

	// Every other mutator refuses, and changes nothing.
	before := dirSnapshot(t, dir)
	var addOut bytes.Buffer
	if code := vaultAddSlot(dir, slotTypePassphrase, false, strings.NewReader("new-pass\n"), &addOut); code != exitUsage {
		t.Fatalf("add-slot exit %d, want %d on a mixed pair with a journal: %s", code, exitUsage, addOut.String())
	}
	if !strings.Contains(addOut.String(), "could not be settled") {
		t.Fatalf("add-slot's refusal does not name the settle: %s", addOut.String())
	}
	assertSnapshotUnchanged(t, dir, before)

	// migrate repairs it.
	code, out := migrateRun(t, dir, false)
	if code != 0 {
		t.Fatalf("migrate exit %d, want 0: %s", code, out)
	}
	if !strings.Contains(out, "this is the one command that repairs that") {
		t.Fatalf("migrate does not say it is the repair: %s", out)
	}
	if info, err := vault.Inspect(filepath.Join(dir, vault.KeyringFileName)); err != nil || info.Format != vault.FormatV2 {
		t.Fatalf("the keyring is %s (err %v), want v2 after the repair", info.Format, err)
	}
	if _, ok, err := vault.ReadVaultOp(dir); ok || err != nil {
		t.Fatalf("the journal survived the repair: ok %v err %v", ok, err)
	}
	// And the state is resolved for the command that was blocked, not merely for Inspect: the
	// mutator that refused above now runs. Without this the claim "the repair worked" would rest on
	// a format test rather than on the thing the mixed pair was stopping.
	var addAgain bytes.Buffer
	if code := vaultAddSlot(dir, slotTypePassphrase, false, strings.NewReader("a-second-passphrase\n"),
		&addAgain); code != 0 {
		t.Fatalf("add-slot still refuses after the repair: exit %d: %s", code, addAgain.String())
	}
}

// A journal this binary cannot read is never acted on, by migrate either: it says which files to
// deal with, and believing a forged or torn one is how a data dir loses files.
func TestMigrateRefusesAnUnreadableJournal(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	if err := os.WriteFile(vault.VaultOpPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := dirSnapshot(t, dir)
	code, out := migrateRun(t, dir, false)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	assertSnapshotUnchanged(t, dir, before)
}

// --- downgrade ---

// The rollback: v1 files again, the v2 bytes kept, and the passphrase still the key. The bytes are
// read back with internal/vault's own v1 path here; the assertion that a reader which knows ONLY v1
// can open them is in internal/vault's golden test, against a copy of that reader.
func TestDowngradeWritesV1FilesAndKeepsTheV2Bytes(t *testing.T) {
	dir, _ := migrateFixture(t, true)
	if code, out := migrateRun(t, dir, false); code != 0 {
		t.Fatalf("seed migrate exit %d: %s", code, out)
	}
	v2Bytes := mustRead(t, filepath.Join(dir, "vault.bin"))

	var out bytes.Buffer
	if code := vaultDowngrade(dir, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("vault downgrade exit %d, want 0: %s", code, out.String())
	}
	for _, name := range []string{"vault.bin", vault.KeyringFileName} {
		info, err := vault.Inspect(filepath.Join(dir, name))
		if err != nil || info.Format != vault.FormatV1 {
			t.Fatalf("%s is %s (err %v), want v1", name, info.Format, err)
		}
	}
	kept := generationsIn(t, dir, ".v2.")
	if len(kept) != 2 {
		t.Fatalf("found %d kept v2 generations, want one per file: %v", len(kept), kept)
	}
	for _, name := range kept {
		if strings.HasPrefix(name, "vault.bin") {
			if got := mustRead(t, filepath.Join(dir, name)); !bytes.Equal(got, v2Bytes) {
				t.Fatalf("%s is not the v2 file it copied", name)
			}
		}
	}
	// The vault still opens with the passphrase and still holds the account.
	v, err := vault.Open(filepath.Join(dir, "vault.bin"), typedKey{pass: fixturePass})
	if err != nil {
		t.Fatalf("the downgraded vault does not open: %v", err)
	}
	if got, ok := v.Get("acct-1"); !ok || got.Label != "Account One" {
		t.Fatalf("the account did not survive the downgrade: %+v ok=%v", got, ok)
	}
	// And the output says what an operator has just given up.
	if !strings.Contains(out.String(), "open with the passphrase ALONE") {
		t.Fatalf("the output does not say the machine slot is gone: %s", out.String())
	}
	if _, ok, jerr := vault.ReadVaultOp(dir); ok || jerr != nil {
		t.Fatalf("the journal survived a finished downgrade: ok %v err %v", ok, jerr)
	}
}

// A pair that is already v1 is exit 0 and nothing done, for migrate's reason: a rollback script
// that runs this twice must not fail the second time.
func TestDowngradeOnAV1PairExitsZero(t *testing.T) {
	dir, _ := migrateFixture(t, true)
	before := dirSnapshot(t, dir)
	var out bytes.Buffer
	if code := vaultDowngrade(dir, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "nothing to downgrade") {
		t.Fatalf("the output does not say there was nothing to do: %s", out.String())
	}
	assertSnapshotUnchanged(t, dir, before)
}

func TestDowngradeRefusesWhileTheLockIsHeld(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	held, err := vault.AcquireLock(dir, "run")
	if err != nil {
		t.Fatalf("take the lock: %v", err)
	}
	defer func() { _ = held.Release() }()
	var out bytes.Buffer
	if code := vaultDowngrade(dir, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out.String())
	}
}

// --- the dispatch, and the rule the whole slice rests on ---

// The four new subcommands are reachable and each one takes --data-dir. A command registered in the
// usage text and not in the switch is the failure this catches.
func TestTheFourNewSubcommandsAreReachable(t *testing.T) {
	for _, sub := range []string{"migrate", "downgrade", "finalize-migration", "purge-backups"} {
		dir := t.TempDir()
		t.Setenv(keyEnv, "")
		t.Setenv("CREDENTIALS_DIRECTORY", "")
		t.Setenv("CLAUDESWAP_KEK_FILE", "")
		pinMachineSeams(t, true)
		var out, errOut bytes.Buffer
		code := vaultCmd([]string{sub, "--data-dir", dir}, strings.NewReader(""), &out, &errOut)
		// Each refuses something about an empty data dir; none of them may report "unknown subcommand".
		if strings.Contains(errOut.String(), "unknown subcommand") {
			t.Fatalf("%s is in the usage text and not in the dispatch: %s", sub, errOut.String())
		}
		// downgrade is the exemption and it is by design: an empty data dir has nothing that is v2,
		// which is "nothing to downgrade" and exit 0, for the reason a rollback script run twice must
		// not fail the second time. The other three refuse something about an empty dir.
		if code == 0 && sub != "downgrade" {
			t.Fatalf("%s exit 0 against an empty data dir: %s%s", sub, out.String(), errOut.String())
		}
		if !strings.Contains(vaultUsage, sub) {
			t.Fatalf("%s is not in the usage text", sub)
		}
	}
}

// The rule this whole slice rests on, re-asserted now that two more doors into the v2 format exist:
// a default `server run` still cannot create or write one. The branch is on whether the file arrived
// with a data key, so there is no flag and no argument that turns create-on-open into a v2 write -
// and the only ways in are the three explicit subcommands.
func TestADefaultRunStillCannotWriteV2NowThatMigrateExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(keyEnv, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("CLAUDESWAP_KEK_FILE", "")
	withHostMachineKey(t)
	path := filepath.Join(dir, "vault.bin")
	// Create-on-open, with a machine key available on this host and a passphrase in hand: the
	// strongest form of the run path, and it still writes v1.
	v, err := vault.Open(path, vault.WithMachineKeys(typedKey{pass: fixturePass}, hostKeyOptions()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(vault.Account{ID: "x", Label: "x", Identity: "x", Block: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := mustRead(t, path); !bytes.HasPrefix(got, []byte("CSV1")) {
		t.Fatalf("create-on-open wrote %q, want a CSV1 file", got[:4])
	}
	// And a save over a v1 file keeps writing v1.
	if err := v.Put(vault.Account{ID: "y", Label: "y", Identity: "y", Block: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if got := mustRead(t, path); !bytes.HasPrefix(got, []byte("CSV1")) {
		t.Fatalf("a save over a v1 file wrote %q", got[:4])
	}
}
