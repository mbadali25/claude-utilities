package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claude-utilities/internal/vault"
)

// Tests for `server vault finalize-migration` and `server vault purge-backups`.
//
// Every fixture is a migrated t.TempDir() with the same pinning the migrate tests use. The two
// commands are tested together because they differ in exactly one thing - which generations they
// consider theirs - and because the gate they share is the part that must not be got wrong: both
// keys open every live file, or nothing is deleted.

// migratedFixture is a data dir that has been through `migrate`, so it holds v2 files and the
// `*.v1.<ts>` copies beside them. It returns the dir.
func migratedFixture(t *testing.T, keyring bool) string {
	t.Helper()
	dir, _ := migrateFixture(t, keyring)
	if code, out := migrateRun(t, dir, false); code != 0 {
		t.Fatalf("seed migrate exit %d: %s", code, out)
	}
	return dir
}

// migratedKEKFixture is migratedFixture with the machine slot forced to kek-file through --add, so
// a test can take the machine key away by pointing CLAUDESWAP_KEK_FILE elsewhere. On Windows the
// default slot is dpapi, which no test can un-wrap.
func migratedKEKFixture(t *testing.T) string {
	t.Helper()
	dir, _ := migrateFixture(t, false)
	// This second withKEKFile is load-bearing on Windows and not a repeat: migrateFixture's
	// withHostMachineKey is a no-op there (dpapi needs nothing), so without this there is no
	// kek-file opener for --add kek-file to resolve.
	withKEKFile(t, fixtureKEK())
	var out bytes.Buffer
	if code := vaultMigrate(dir, false, slotTypeKEKFile, false, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("seed migrate --add kek-file exit %d: %s", code, out.String())
	}
	return dir
}

func finalizeRun(t *testing.T, dir string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	return vaultFinalizeMigration(dir, strings.NewReader(""), &out), out.String()
}

func purgeRun(t *testing.T, dir string, keepBak bool) (int, string) {
	t.Helper()
	var out bytes.Buffer
	return vaultPurgeBackups(dir, keepBak, strings.NewReader(""), &out), out.String()
}

// namesIn is every regular file name in dir, so an assertion can name what survived.
func namesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	return out
}

func assertGone(t *testing.T, dir, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s is still there (stat err %v); dir holds %v", name, err, namesIn(t, dir))
	}
}

func assertStillThere(t *testing.T, dir, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("%s was removed: %v; dir holds %v", name, err, namesIn(t, dir))
	}
}

// --- finalize-migration ---

// The baseline: every v1 artefact goes, each one is named, and the live v2 files stay.
func TestFinalizeDeletesEveryV1ArtefactAndPrintsWhat(t *testing.T) {
	dir := migratedFixture(t, true)
	// A bare `.bak` still in CSV1, which a pre-slice-3 binary could have written after the
	// migration, and which finalize is explicitly told to remove.
	oldBak := filepath.Join(dir, "vault.bin.bak")
	v1Copy := ""
	for _, name := range generationsIn(t, dir, ".v1.") {
		if strings.HasPrefix(name, "vault.bin") {
			v1Copy = name
		}
	}
	if v1Copy == "" {
		t.Fatalf("the fixture has no vault.bin v1 copy: %v", namesIn(t, dir))
	}
	if err := os.WriteFile(oldBak, mustRead(t, filepath.Join(dir, v1Copy)), 0o600); err != nil {
		t.Fatal(err)
	}

	before := generationsIn(t, dir, ".v1.")
	code, out := finalizeRun(t, dir)
	if code != 0 {
		t.Fatalf("finalize exit %d, want 0: %s", code, out)
	}
	for _, name := range before {
		assertGone(t, dir, name)
		if !strings.Contains(out, name) {
			t.Fatalf("the output does not name %s: %s", name, out)
		}
	}
	assertGone(t, dir, "vault.bin.bak")
	for _, name := range []string{"vault.bin", vault.KeyringFileName} {
		assertStillThere(t, dir, name)
		if info, err := vault.Inspect(filepath.Join(dir, name)); err != nil || info.Format != vault.FormatV2 {
			t.Fatalf("%s is %s (err %v) after finalize, want v2", name, info.Format, err)
		}
	}
	// And it does not claim what it did not do.
	if !strings.Contains(out, "No overwrite pass was attempted and none is claimed") {
		t.Fatalf("the output overstates the deletion: %s", out)
	}
}

// finalize is "the migration is over", not "tidy the directory". A v2 `.bak` and a `*.v2.<ts>`
// generation are purge-backups' business, and leaving them is the line the spec draws.
func TestFinalizeLeavesV2ArtefactsAlone(t *testing.T) {
	dir := migratedFixture(t, false)
	v2Bak := filepath.Join(dir, "vault.bin.bak")
	v2Gen := filepath.Join(dir, "vault.bin.v2.20261108T000000Z")
	live := mustRead(t, filepath.Join(dir, "vault.bin"))
	for _, p := range []string{v2Bak, v2Gen} {
		if err := os.WriteFile(p, live, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := finalizeRun(t, dir); code != 0 {
		t.Fatalf("finalize exit %d: %s", code, out)
	}
	assertStillThere(t, dir, "vault.bin.bak")
	assertStillThere(t, dir, "vault.bin.v2.20261108T000000Z")
}

// Both keys, not one. A data dir whose machine slot works and whose passphrase does not is one lost
// host away from being unopenable, and deleting the v1 copies there reaches the Anti-goal a
// fortnight later by a command whose name sounds like tidying.
func TestFinalizeRequiresBothKeysToOpen(t *testing.T) {
	t.Run("the machine key is gone", func(t *testing.T) {
		// A kek-file machine slot on purpose, on every OS. A dpapi slot cannot be taken away from the
		// machine that wrapped it, so on Windows the default fixture would have no way to express
		// "this host has lost its machine key" - which is the case the recovery rung exists for.
		dir := migratedKEKFixture(t)
		before := namesIn(t, dir)
		t.Setenv("CLAUDESWAP_KEK_FILE", filepath.Join(t.TempDir(), "not-there"))
		code, out := finalizeRun(t, dir)
		if code == 0 {
			t.Fatalf("finalize succeeded with no machine key: %s", out)
		}
		if !strings.Contains(out, "nothing was removed") {
			t.Fatalf("the refusal does not say nothing was removed: %s", out)
		}
		if got := namesIn(t, dir); len(got) != len(before) {
			t.Fatalf("files went from %v to %v", before, got)
		}
	})
	t.Run("the passphrase is wrong", func(t *testing.T) {
		dir := migratedFixture(t, false)
		before := namesIn(t, dir)
		t.Setenv(keyEnv, "not-the-fixture-passphrase")
		code, out := finalizeRun(t, dir)
		if code == 0 {
			t.Fatalf("finalize succeeded with the wrong passphrase: %s", out)
		}
		if !strings.Contains(out, "nothing was removed") {
			t.Fatalf("the refusal does not say nothing was removed: %s", out)
		}
		if got := namesIn(t, dir); len(got) != len(before) {
			t.Fatalf("files went from %v to %v", before, got)
		}
	})
}

// A wrong passphrase must be caught even though the machine slot opens the file first. VerifyFile
// takes the data key from the FIRST slot that gives it up, so without the all-slots check a broken
// passphrase slot verifies clean - and the passphrase rung is the alternative these copies ARE.
func TestFinalizeRefusesWhenOnlyTheMachineSlotWorks(t *testing.T) {
	dir := migratedFixture(t, false)
	t.Setenv(keyEnv, "not-the-fixture-passphrase")
	code, out := finalizeRun(t, dir)
	if code == 0 {
		t.Fatalf("finalize succeeded on a machine-slot-only open: %s", out)
	}
	if !strings.Contains(out, "of its slots did not") {
		t.Fatalf("the refusal does not come from the all-slots check: %s", out)
	}
	if code != exitVaultLocked {
		t.Fatalf("exit %d, want %d: a key that does not open is the vault-locked code", code, exitVaultLocked)
	}
}

// A data dir that is still v1 has no machine slot to prove, and its copies are not leftovers.
func TestRetentionRefusesWhileTheVaultIsStillV1(t *testing.T) {
	dir, _ := migrateFixture(t, false)
	stray := filepath.Join(dir, "vault.bin.v1.20261108T000000Z")
	if err := os.WriteFile(stray, mustRead(t, filepath.Join(dir, "vault.bin")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, run := range []func(*testing.T, string) (int, string){
		finalizeRun,
		func(t *testing.T, d string) (int, string) { return purgeRun(t, d, false) },
	} {
		code, out := run(t, dir)
		if code != exitNewerFormat {
			t.Fatalf("exit %d, want %d: %s", code, exitNewerFormat, out)
		}
		if !strings.Contains(out, "Run `server vault migrate` first") {
			t.Fatalf("the refusal does not name migrate: %s", out)
		}
		assertStillThere(t, dir, filepath.Base(stray))
	}
}

// A data dir with no vault and copies beside it is exactly the state those copies are for.
func TestRetentionRefusesWhenTheLiveVaultIsGone(t *testing.T) {
	dir := migratedFixture(t, false)
	if err := os.Remove(filepath.Join(dir, "vault.bin")); err != nil {
		t.Fatal(err)
	}
	copies := generationsIn(t, dir, ".v1.")
	code, out := finalizeRun(t, dir)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "may be the only ones left") {
		t.Fatalf("the refusal does not say why: %s", out)
	}
	for _, name := range copies {
		assertStillThere(t, dir, name)
	}
}

// --- purge-backups ---

// Every generation, in either format, plus the `.bak`. It exists because a v2 `.bak` or a
// `*.v2.<ts>` still opens with a key `remove-slot` has since taken away.
func TestPurgeBackupsDeletesV1AndV2GenerationsAndBak(t *testing.T) {
	dir := migratedFixture(t, true)
	live := mustRead(t, filepath.Join(dir, "vault.bin"))
	extra := []string{"vault.bin.bak", "vault.bin.v2.20261108T000000Z", "tunnelkeys.bin.bak"}
	for _, name := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), live, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v1Copies := generationsIn(t, dir, ".v1.")
	code, out := purgeRun(t, dir, false)
	if code != 0 {
		t.Fatalf("purge-backups exit %d, want 0: %s", code, out)
	}
	for _, name := range append(extra, v1Copies...) {
		assertGone(t, dir, name)
	}
	for _, name := range []string{"vault.bin", vault.KeyringFileName} {
		assertStillThere(t, dir, name)
	}
	// The sharp edge is said out loud: copies made elsewhere are untouched.
	if !strings.Contains(out, "Copies you made elsewhere") {
		t.Fatalf("the output does not warn about copies outside the data dir: %s", out)
	}
}

// --keep-bak spares the one-generation undo for a Delete or a ReplaceBlock an operator regrets on
// the spot, and takes everything else.
func TestPurgeBackupsKeepBakKeepsIt(t *testing.T) {
	dir := migratedFixture(t, false)
	bak := "vault.bin.bak"
	if err := os.WriteFile(filepath.Join(dir, bak), mustRead(t, filepath.Join(dir, "vault.bin")), 0o600); err != nil {
		t.Fatal(err)
	}
	v1Copies := generationsIn(t, dir, ".v1.")
	if code, out := purgeRun(t, dir, true); code != 0 {
		t.Fatalf("purge-backups --keep-bak exit %d: %s", code, out)
	}
	assertStillThere(t, dir, bak)
	for _, name := range v1Copies {
		assertGone(t, dir, name)
	}
}

func TestPurgeBackupsRequiresBothKeys(t *testing.T) {
	dir := migratedFixture(t, false)
	before := namesIn(t, dir)
	t.Setenv(keyEnv, "not-the-fixture-passphrase")
	code, out := purgeRun(t, dir, false)
	if code == 0 {
		t.Fatalf("purge-backups succeeded with the wrong passphrase: %s", out)
	}
	if got := namesIn(t, dir); len(got) != len(before) {
		t.Fatalf("files went from %v to %v", before, got)
	}
}

// --- what neither command may ever touch ---

// A command called "purge-backups" must not reach anything but a stored generation of the two vault
// files. Deleting tls/server-cert.pem de-enrols every agent, which is an Anti-goal reached by a flag
// whose name promises tidiness; admin-password.json and hosts.json are the server's own state.
func TestRetentionNeverTouchesTheRestOfTheDataDir(t *testing.T) {
	dir := migratedFixture(t, true)
	bystanders := map[string]string{
		"admin-password.json":     `{"hash":"not-a-real-hash"}`,
		"hosts.json":              `[{"id":"host-1"}]`,
		"agent-run.log":           "a log line\n",
		"vault.bin.notagenration": "not a generation of anything",
	}
	for name, body := range bystanders {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certPath := filepath.Join(dir, "tls", "server-cert.pem")
	certBefore := mustRead(t, certPath)

	if code, out := purgeRun(t, dir, false); code != 0 {
		t.Fatalf("purge-backups exit %d: %s", code, out)
	}
	for name, body := range bystanders {
		assertStillThere(t, dir, name)
		if got := string(mustRead(t, filepath.Join(dir, name))); got != body {
			t.Fatalf("%s was rewritten", name)
		}
	}
	if got := mustRead(t, certPath); !bytes.Equal(got, certBefore) {
		t.Fatal("tls/server-cert.pem was touched: every enrolled agent pins it")
	}
}

// Both commands take the data-dir lock, because both delete the files a running server's next save
// might be the only other copy of.
func TestRetentionCommandsTakeTheLock(t *testing.T) {
	for _, run := range []func(*testing.T, string) (int, string){
		finalizeRun,
		func(t *testing.T, d string) (int, string) { return purgeRun(t, d, false) },
	} {
		dir := migratedFixture(t, false)
		held, err := vault.AcquireLock(dir, "run")
		if err != nil {
			t.Fatalf("take the lock: %v", err)
		}
		code, out := run(t, dir)
		_ = held.Release()
		if code != exitUsage {
			t.Fatalf("exit %d, want %d with the lock held: %s", code, exitUsage, out)
		}
		if !strings.Contains(out, "stop it first") {
			t.Fatalf("the refusal does not say to stop the holder: %s", out)
		}
	}
}

// An interrupted operation is settled or refused before either command deletes anything: the copies
// a rotation might be the only way back from are the worst possible thing to be wrong about.
func TestRetentionRefusesAnUnsettleableJournal(t *testing.T) {
	dir := migratedFixture(t, false)
	if err := os.WriteFile(vault.VaultOpPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := namesIn(t, dir)
	code, out := finalizeRun(t, dir)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if got := namesIn(t, dir); len(got) != len(before) {
		t.Fatalf("files went from %v to %v", before, got)
	}
}

// Nothing to remove is exit 0 and says so: a cron or a runbook step that runs finalize twice must
// not read the second run as a failure.
func TestRetentionWithNothingToRemoveExitsZero(t *testing.T) {
	dir := migratedFixture(t, false)
	if code, out := finalizeRun(t, dir); code != 0 {
		t.Fatalf("the first finalize exit %d: %s", code, out)
	}
	code, out := finalizeRun(t, dir)
	if code != 0 {
		t.Fatalf("a second finalize exit %d, want 0: %s", code, out)
	}
	if !strings.Contains(out, "there is nothing to remove") {
		t.Fatalf("the output does not say there was nothing to remove: %s", out)
	}
}

// The set `status` lists and the set these commands delete are the same set, and neither predicate
// may reach a name that is not a generation of one of the two live files.
func TestTheGenerationPredicatesAgree(t *testing.T) {
	cases := []struct {
		name       string
		generation bool
		v1Shape    bool
	}{
		{"vault.bin", false, false},
		{"tunnelkeys.bin", false, false},
		{"vault.bin.v1.20261108T000000Z", true, true},
		{"vault.bin.bak.v1.20261108T000000Z", true, true},
		{"tunnelkeys.bin.v1.20261108T000000Z", true, true},
		{"vault.bin.v2.20261108T000000Z", true, false},
		{"vault.bin.bak", true, true},
		{"tunnelkeys.bin.bak", true, true},
		{"admin-password.json", false, false},
		{"hosts.json", false, false},
		{".claude-swap.lock", false, false},
		{"vaultop.journal", false, false},
		{"notvault.bin.v1.x", false, false},
	}
	for _, c := range cases {
		if got := isVaultGenerationName(c.name); got != c.generation {
			t.Fatalf("isVaultGenerationName(%q) = %v, want %v", c.name, got, c.generation)
		}
		if got := isV1ArtefactName(c.name); got != c.v1Shape {
			t.Fatalf("isV1ArtefactName(%q) = %v, want %v", c.name, got, c.v1Shape)
		}
		// Every v1 shape is a generation: status must never name a file retention cannot reach.
		if c.v1Shape && !c.generation {
			t.Fatalf("%q is a v1 artefact status would list and not a generation finalize can delete", c.name)
		}
	}
}
