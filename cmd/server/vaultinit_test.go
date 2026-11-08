package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"claude-utilities/internal/vault"
)

// Tests for `server vault init`, the one command that creates a v2 vault and keyring.
//
// Every fixture is a t.TempDir() with every environment input pinned by emptyDataDir: no inherited
// passphrase, no credentials directory, no KEK file. Nothing here can reach a real data dir, a real
// credstore or a host's live vault, and no test here runs `init` against anything but a temp
// directory it made itself.

// emptyDataDir is a data dir with nothing in it and every environment input pinned, which is the
// one state `init` is for. It is v2DataDir's sibling: same pinning, no fixture file.
func emptyDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(keyEnv, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("CLAUDESWAP_KEK_FILE", "")
	return dir
}

// withHostMachineKey gives this host the machine key `init` will wrap under. On Windows that is
// DPAPI, which is always there and needs nothing; everywhere else it is a KEK file, which is the
// route a non-systemd host and every test use.
func withHostMachineKey(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	withKEKFile(t, fixtureKEK())
}

// initOK runs a scripted `init` - the passphrase in CLAUDESWAP_KEY, nothing on stdin - and fails the
// test if it did not exit 0.
func initOK(t *testing.T, dir string) (string, *bytes.Buffer) {
	t.Helper()
	t.Setenv(keyEnv, fixturePass)
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("vault init exit %d, want 0: %s", code, out.String())
	}
	return out.String(), &out
}

// assertNoVaultFiles is the "nothing was written" half of every refusal, and it covers the journal
// too: a journal left behind by a command that never started would make the next mutator settle an
// operation that did not happen.
func assertNoVaultFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"vault.bin", vault.KeyringFileName, vault.VaultOpFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after a run that should have written nothing (stat err %v)", name, err)
		}
	}
}

// The baseline: both files land as v2, each with a passphrase slot and a machine slot, and the
// journal that recorded the creation is gone again.
func TestInitWritesBothFilesAsV2(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	initOK(t, dir)

	for _, f := range []struct{ name, magic string }{
		{"vault.bin", "CSV2"},
		{vault.KeyringFileName, "CSK2"},
	} {
		path := filepath.Join(dir, f.name)
		if got := mustRead(t, path); !bytes.HasPrefix(got, []byte(f.magic)) {
			t.Fatalf("%s does not start with %s", f.name, f.magic)
		}
		info, err := vault.Inspect(path)
		if err != nil {
			t.Fatalf("Inspect %s: %v", f.name, err)
		}
		if info.Format != vault.FormatV2 || len(info.Slots) != 2 {
			t.Fatalf("%s = %s with %d slots, want v2 with 2", f.name, info.Format, len(info.Slots))
		}
		var pass, machine int
		for _, s := range info.Slots {
			if s.Type == slotTypePassphrase {
				pass++
			} else {
				machine++
			}
		}
		if pass != 1 || machine != 1 {
			t.Fatalf("%s has %d passphrase and %d machine slots, want 1 and 1", f.name, pass, machine)
		}
	}
	if _, ok, err := vault.ReadVaultOp(dir); ok || err != nil {
		t.Fatalf("the journal survived a finished init: ok %v err %v", ok, err)
	}
}

// The command prints the slot ids it chose - an operator cannot run `remove-slot --id` without them
// - and the machine slot's type, which is what says whether the service can start unattended.
func TestInitPrintsTheSlotIDsAndTheMachineSlotType(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	out, _ := initOK(t, dir)

	wantType := slotTypeKEKFile
	if runtime.GOOS == "windows" {
		wantType = slotTypeDPAPI
	}
	if !strings.Contains(out, wantType) {
		t.Fatalf("the output does not name the machine slot type %s: %s", wantType, out)
	}
	for _, name := range []string{"vault.bin", vault.KeyringFileName} {
		info, err := vault.Inspect(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range info.Slots {
			if !strings.Contains(out, s.ID) {
				t.Fatalf("the output does not name slot %s of %s: %s", s.ID, name, out)
			}
		}
	}
}

// Both slots are proved before the command returns, with the two checks that mean different things:
// the machine slot ALONE (can the service start with no operator present) and every slot in turn
// (is each key good). A created vault nobody proved is a vault whose first failure is a restart.
func TestInitVerifiesBothSlotsBeforeReturning(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	out, _ := initOK(t, dir)
	for _, want := range []string{"the machine slot alone", "every slot"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output does not report the %q check: %s", want, out)
		}
	}
	// And the claim is true, not just printed: the files open with each key on its own.
	machineOnly := vault.WithMachineKeys(nil, hostKeyOptions())
	for _, name := range []string{"vault.bin", vault.KeyringFileName} {
		res, err := vault.VerifyFile(filepath.Join(dir, name), machineOnly, false)
		if err != nil || !res.PayloadOK {
			t.Fatalf("%s did not open under the machine slot alone: err %v payloadOK %v", name, err, res.PayloadOK)
		}
	}
}

// `init` is for a data dir with no vault. A file that is already there is never written over, and
// the message says which command owns the state it found: `migrate` for a v1 file, nothing at all
// for a v2 one.
func TestInitRefusesWhenAVaultExists(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withHostMachineKey(t)
	t.Setenv(keyEnv, fixturePass)
	before := mustRead(t, vaultPath(dir))
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("exit %d over an existing vault, want %d: %s", code, exitUsage, out.String())
	}
	if !strings.Contains(out.String(), "migrate") {
		t.Fatalf("the refusal does not name `migrate`: %s", out.String())
	}
	if !bytes.Equal(before, mustRead(t, vaultPath(dir))) {
		t.Fatal("a refused init wrote to the existing vault")
	}
	if _, err := os.Stat(filepath.Join(dir, vault.KeyringFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused init created the keyring")
	}
}

// Half a data dir is still a data dir. A keyring with no vault beside it is the state a crash
// between the two files leaves, and creating a fresh vault next to it would seal the two under
// different passphrases with nothing saying so.
func TestInitRefusesWhenOnlyTheKeyringExists(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	ringPath := filepath.Join(dir, vault.KeyringFileName)
	writeV2Fixture(t, ringPath, "CSK2", []fixSpec{{id: "slot0001", pass: fixturePass}}, []byte(`{"keys":[]}`))
	before := mustRead(t, ringPath)
	t.Setenv(keyEnv, fixturePass)
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("exit %d with only a keyring, want %d: %s", code, exitUsage, out.String())
	}
	if !strings.Contains(out.String(), vault.KeyringFileName) {
		t.Fatalf("the refusal does not name the file it found: %s", out.String())
	}
	if !bytes.Equal(before, mustRead(t, ringPath)) {
		t.Fatal("a refused init wrote to the existing keyring")
	}
	if _, err := os.Stat(vaultPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused init created the vault")
	}
}

// No passphrase anywhere - nothing in CLAUDESWAP_KEY, nothing on stdin - is exit 2 and nothing
// written. There is no invented passphrase in this command, and a vault whose passphrase nobody
// chose is a vault nobody can recover.
func TestInitNeverInventsAPassphrase(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("exit %d with no passphrase, want %d: %s", code, exitUsage, out.String())
	}
	assertNoVaultFiles(t, dir)
}

// A passphrase on stdin is one line, and the confirm-it-twice prompt is a terminal's. That is the
// rule readNewPassphrase and `set-password` already follow: a pipe cannot be asked twice, so asking
// would hang a scripted run. Pinned here because `init` is the command that CREATES the passphrase,
// which is the one place a typo is unrecoverable.
func TestInitTakesOnePassphraseLineFromAPipe(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader("typed-at-the-pipe\n"), &out); code != 0 {
		t.Fatalf("exit %d with a passphrase on stdin, want 0: %s", code, out.String())
	}
	if _, err := vault.Open(vaultPath(dir), typedKey{pass: "typed-at-the-pipe"}); err != nil {
		t.Fatalf("the vault does not open under the piped passphrase: %v", err)
	}
}

// The scripted path the installers and the e2e scripts use: the passphrase in the environment and
// nothing on stdin. The environment wins, so a scripted run never prompts and never hangs.
func TestInitAcceptsCLAUDESWAPKEYForAScriptedRun(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	initOK(t, dir)
	if _, err := vault.Open(vaultPath(dir), typedKey{pass: fixturePass}); err != nil {
		t.Fatalf("the vault does not open under the environment passphrase: %v", err)
	}
}

// `init` is a mutator and takes the data-dir lock for the length of the command. A lock held by a
// running server is exit 2 naming the holder, never a creation that races the server's own header.
func TestInitTakesTheLock(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	t.Setenv(keyEnv, fixturePass)
	lock, err := vault.AcquireLock(dir, "run")
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release() }()
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("exit %d while the lock was held, want %d: %s", code, exitUsage, out.String())
	}
	if !strings.Contains(out.String(), "stop it first") {
		t.Fatalf("the refusal does not name the holder: %s", out.String())
	}
	assertNoVaultFiles(t, dir)
}

// A dry run writes nothing at all: no vault, no keyring, no journal. It is the command an operator
// runs to see what would happen on a host they cannot afford to guess about.
func TestInitDryRunWritesNothing(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	t.Setenv(keyEnv, fixturePass)
	var out bytes.Buffer
	if code := vaultInit(dir, true, false, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("dry-run exit %d, want 0: %s", code, out.String())
	}
	assertNoVaultFiles(t, dir)
	if !strings.Contains(out.String(), "dry run") {
		t.Fatalf("the dry run does not say it wrote nothing: %s", out.String())
	}
	// Nothing but the lock file, which every mutator takes and which carries no vault state.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".lock") {
			t.Fatalf("the dry run left %s in the data dir", e.Name())
		}
	}
}

// A machine slot whose key this host cannot reach is exit 2 with nothing written, and it is reported
// as a key that is out of reach rather than a bad one: an operator pushed towards rotating a correct
// passphrase is a stated Anti-goal.
func TestInitRefusesWhenNoMachineKeyIsReachable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DPAPI is always available on Windows, so this host always has a machine key")
	}
	dir := emptyDataDir(t)
	t.Setenv(keyEnv, fixturePass)
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("exit %d with no reachable KEK, want %d: %s", code, exitUsage, out.String())
	}
	assertNoVaultFiles(t, dir)
}

// Nothing the command prints is key material, on the success path or any refusal. The output goes
// to a terminal, into a log and into whatever an operator pastes into a ticket.
func TestInitOutputCarriesNoKeyMaterial(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	out, _ := initOK(t, dir)
	for _, secret := range []string{fixturePass, string(fixtureKEK())} {
		if strings.Contains(out, secret) {
			t.Fatalf("the output carries key material: %s", out)
		}
	}
	// And no file in the data dir carries the passphrase either, journal included.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if bytes.Contains(mustRead(t, filepath.Join(dir, e.Name())), []byte(fixturePass)) {
			t.Fatalf("%s carries the passphrase", e.Name())
		}
	}
}

// The invariant the whole slice rests on: a default `server run` cannot produce a v2 file. The key
// source a console run hands the vault is EnvKey, whose Machine() is nil, and the write path
// branches on whether the file arrived with a data key - so create-on-open is CSV1 and stays CSV1.
// The v2 creator is behind `vault init`, which is a separate subcommand and refuses without a
// passphrase an operator typed for it.
func TestADefaultRunCannotCreateAV2Vault(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	t.Setenv(keyEnv, fixturePass)

	// The create-on-open path, reached exactly as serve reaches it.
	v, err := vault.Open(vaultPath(dir), vault.EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(vault.Account{ID: "a1", Label: "one", Identity: "one@example.test"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := mustRead(t, vaultPath(dir)); !bytes.HasPrefix(got, []byte("CSV1")) {
		t.Fatalf("a console run created %q, want CSV1", string(got[:4]))
	}
	// And the only door to v2 refuses on a data dir that now has a vault, so there is no sequence of
	// run-then-init that upgrades a file in place either. That is `migrate`'s job, by that name.
	var out bytes.Buffer
	if code := vaultInit(dir, false, false, strings.NewReader(""), &out); code != exitUsage {
		t.Fatalf("init over the v1 vault a run created: exit %d, want %d: %s", code, exitUsage, out.String())
	}
	if got := mustRead(t, vaultPath(dir)); !bytes.HasPrefix(got, []byte("CSV1")) {
		t.Fatal("a refused init changed the v1 vault's format")
	}
}

// `init` is reachable from the dispatch, with --data-dir and --dry-run, and a stray positional
// argument is refused everywhere in this command group.
func TestInitIsReachableFromTheVaultDispatch(t *testing.T) {
	dir := emptyDataDir(t)
	withHostMachineKey(t)
	t.Setenv(keyEnv, fixturePass)
	var out bytes.Buffer
	code := vaultCmd([]string{"init", "--data-dir", dir, "--dry-run"}, strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("`vault init --dry-run` through the dispatch: exit %d, want 0: %s", code, out.String())
	}
	assertNoVaultFiles(t, dir)
	if !strings.Contains(vaultUsage, "init") {
		t.Fatal("the usage text does not list init")
	}
}
