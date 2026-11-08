package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claude-utilities/internal/vault"
)

// Tests for the four slot mutators as the operator reaches them: the data-dir lock, the vaultop
// journal, the exit codes, and the refusals that must write nothing.
//
// The fixtures are vaultcmd_test.go's: a v2 vault.bin under t.TempDir() with slots this test built
// from the format's own primitives. No real data dir, no credstore, no live host.
//
// Order matters in these tests: the fixture helpers pin every environment input (including an empty
// CLAUDESWAP_KEY), so withPassphraseEnv comes AFTER the helper, never before it.

// mutators is the table every "all four behave the same" test walks.
func mutators() []struct {
	name string
	run  func(dataDir string, in string, out *bytes.Buffer) int
} {
	return []struct {
		name string
		run  func(dataDir string, in string, out *bytes.Buffer) int
	}{
		{"add-slot", func(dir, in string, out *bytes.Buffer) int {
			return vaultAddSlot(dir, "passphrase", false, strings.NewReader(in), out)
		}},
		{"remove-slot", func(dir, in string, out *bytes.Buffer) int {
			return vaultRemoveSlot(dir, fixB64([]byte("slot0002")), strings.NewReader(in), out)
		}},
		{"rotate", func(dir, in string, out *bytes.Buffer) int {
			return vaultRotate(dir, strings.NewReader(in), out)
		}},
		{"change-passphrase", func(dir, in string, out *bytes.Buffer) int {
			return vaultChangePassphrase(dir, strings.NewReader(in), out)
		}},
	}
}

// withPassphraseEnv puts the fixture passphrase where a scripted run keeps it, which is the only
// place but stdin that any of these commands will look.
func withPassphraseEnv(t *testing.T) {
	t.Helper()
	t.Setenv(keyEnv, fixturePass)
}

// twoSlotDir is a data dir whose vault has a passphrase slot and a reachable kek-file slot.
func twoSlotDir(t *testing.T) string {
	t.Helper()
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	withKEKFile(t, fixtureKEK())
	return dir
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func vaultPath(dir string) string { return filepath.Join(dir, "vault.bin") }

// Slot operations require the service stopped. Every mutator takes the data-dir lock, and a held
// lock is exit 2 with the holder's pid - never a write that races the running server's own header.
func TestEveryMutatorTakesTheLockAndExitsTwoWhenHeld(t *testing.T) {
	for _, m := range mutators() {
		t.Run(m.name, func(t *testing.T) {
			dir := twoSlotDir(t)
			withPassphraseEnv(t)
			before := mustRead(t, vaultPath(dir))
			lock, err := vault.AcquireLock(dir, "run")
			if err != nil {
				t.Fatalf("AcquireLock: %v", err)
			}
			defer func() { _ = lock.Release() }()
			var out bytes.Buffer
			if code := m.run(dir, "a-new-passphrase\n", &out); code != 2 {
				t.Fatalf("exit %d while the lock was held, want 2: %s", code, out.String())
			}
			if !strings.Contains(out.String(), "stop it first") {
				t.Fatalf("the refusal does not name the holder: %s", out.String())
			}
			if !bytes.Equal(before, mustRead(t, vaultPath(dir))) {
				t.Fatalf("%s wrote while the lock was held", m.name)
			}
		})
	}
}

// The ordering the journal exists for: it is on disk BEFORE the mutation touches anything, and gone
// afterwards. The probe runs in the mutation's own place in runMutation, so this asserts the order
// rather than the end state.
func TestEveryMutatorWritesAVaultOpJournalFirst(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	var sawJournal vault.VaultOp
	var sawOK bool
	var out bytes.Buffer
	code := runMutation(dir, mutation{
		op:    "rotate",
		files: []string{"vault.bin"},
		apply: func(*vault.Vault, vault.KeySource) (string, error) {
			op, ok, err := vault.ReadVaultOp(dir)
			if err != nil {
				t.Fatalf("ReadVaultOp during the mutation: %v", err)
			}
			sawJournal, sawOK = op, ok
			return "", nil
		},
	}, &out)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !sawOK {
		t.Fatalf("no journal was on disk when the mutation ran")
	}
	if sawJournal.Op != "rotate" || sawJournal.Stage != vault.StageStarted ||
		len(sawJournal.Files) != 1 || sawJournal.Files[0] != "vault.bin" {
		t.Fatalf("the journal does not describe the operation: %+v", sawJournal)
	}
	if _, ok, _ := vault.ReadVaultOp(dir); ok {
		t.Fatalf("the journal outlived a finished mutation")
	}
}

// The recovery copy is dealt with BEFORE the new generation is written, so a write that then fails
// has already re-sealed or DELETED the .bak. The spec's accepted risk for that deletion is that the
// printed line is the notice, so the notice has to survive the failure: a command that reported only
// the error would have deleted an operator's recovery copy silently.
func TestAFailedMutationStillSaysWhatHappenedToTheBak(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	var out bytes.Buffer
	code := runMutation(dir, mutation{
		op:    "remove-slot",
		files: []string{"vault.bin"},
		apply: func(*vault.Vault, vault.KeySource) (string, error) {
			return "bak removed (no available slot opened it)", errors.New("vault: write: disk full")
		},
	}, &out)
	if code == 0 {
		t.Fatalf("exit 0 on a failed mutation: %s", out.String())
	}
	if !strings.Contains(out.String(), "bak removed") {
		t.Fatalf("a failed mutation did not report what it did to the recovery copy: %s", out.String())
	}
	if !strings.Contains(out.String(), "disk full") {
		t.Fatalf("the failure itself is not reported: %s", out.String())
	}
}

// A refusal that wrote nothing clears its own journal: leaving one behind would make the next
// command settle an operation that never started.
func TestARefusedMutatorLeavesNoJournal(t *testing.T) {
	// No CLAUDESWAP_KEK_FILE, so the kek-file slot is present in the header and out of reach:
	// rotate cannot re-wrap it and refuses.
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultRotate(dir, strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
	if _, ok, _ := vault.ReadVaultOp(dir); ok {
		t.Fatalf("a refusal that wrote nothing left a journal behind")
	}
}

// A journal left by a crash is settled before the new command changes anything, and the command
// says what the settle did. This is the spec's settle-or-refuse, from the mutator's side.
func TestAMutatorSettlesALeftoverJournalFirst(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	// ResealsBak is what a real `rotate` writes: it draws a new data key, so it is one of the two
	// operations whose settle may touch the recovery copy. At `started` nothing became visible, so the
	// settle reverts.
	if err := vault.WriteVaultOp(dir, vault.VaultOp{
		Op: "rotate", Files: []string{"vault.bin"}, Stage: vault.StageStarted,
		ResealsBak: true}); err != nil {
		t.Fatalf("WriteVaultOp: %v", err)
	}
	var out bytes.Buffer
	if code := vaultRotate(dir, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "reverted") {
		t.Fatalf("the settle is not reported: %s", out.String())
	}
	if _, ok, _ := vault.ReadVaultOp(dir); ok {
		t.Fatalf("the journal survived the command")
	}
}

// An unreadable journal is never repaired silently and never acted on: a journal says which files
// to delete a .bak from, so believing a crafted one is how a data dir loses files.
func TestAMutatorRefusesAnUnreadableJournal(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	if err := os.WriteFile(vault.VaultOpPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	before := mustRead(t, vaultPath(dir))
	var out bytes.Buffer
	if code := vaultRotate(dir, strings.NewReader(""), &out); code == 0 {
		t.Fatalf("exit 0 on an unreadable journal: %s", out.String())
	}
	if !strings.Contains(out.String(), "verify --all-slots") {
		t.Fatalf("the refusal does not name the verify: %s", out.String())
	}
	if !bytes.Equal(before, mustRead(t, vaultPath(dir))) {
		t.Fatalf("the vault was written despite an unreadable journal")
	}
}

// --- add-slot ---

func TestAddSlotPassphraseAddsASecondIndependentSlot(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultAddSlot(dir, "passphrase", false, strings.NewReader("the-second-passphrase\n"), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	info, err := vault.Inspect(vaultPath(dir))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Slots) != 2 {
		t.Fatalf("%d slots after add-slot, want 2", len(info.Slots))
	}
	if !strings.Contains(out.String(), info.Slots[1].ID) {
		t.Fatalf("add-slot does not print the new slot id: %s", out.String())
	}
	if strings.Contains(out.String(), "the-second-passphrase") {
		t.Fatalf("add-slot printed the passphrase: %s", out.String())
	}
	// Both passphrases open the file afterwards, which is what makes a staged rotation possible.
	for _, pass := range []string{fixturePass, "the-second-passphrase"} {
		t.Setenv(keyEnv, pass)
		var vout bytes.Buffer
		if code := vaultVerify(dir, true, strings.NewReader(""), &vout); code != 0 {
			t.Fatalf("verify with %q: exit %d: %s", pass, code, vout.String())
		}
	}
}

// The passphrase is never an argument: argv is visible to every process on the host.
func TestNoMutatorTakesAPassphraseFromAFlag(t *testing.T) {
	var out bytes.Buffer
	code := vaultCmd([]string{"add-slot", "--type", "passphrase", "--passphrase", "x"},
		strings.NewReader(""), &out, &out)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(out.String(), "not defined") {
		t.Fatalf("a --passphrase flag was not refused: %s", out.String())
	}
}

// A kek-file slot needs host key material. Creating it is `vault init`/`migrate`'s step, so when no
// KEK resolves this refuses by name rather than inventing one.
func TestAddSlotKEKFileRefusesWhenNoKEKResolves(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withPassphraseEnv(t)
	before := mustRead(t, vaultPath(dir))
	var out bytes.Buffer
	if code := vaultAddSlot(dir, "kek-file", false, strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "migrate") && !strings.Contains(out.String(), "init") {
		t.Fatalf("the refusal names no command that creates a KEK: %s", out.String())
	}
	if !bytes.Equal(before, mustRead(t, vaultPath(dir))) {
		t.Fatalf("a refused add-slot wrote to the vault")
	}
}

// With a KEK this host can reach, the machine slot is wrapped under it and the file opens with that
// slot alone afterwards - which is the machine-key recovery procedure, end to end.
func TestAddSlotKEKFileWrapsUnderAReachableKEK(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withKEKFile(t, fixtureKEK())
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultAddSlot(dir, "kek-file", false, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	info, err := vault.Inspect(vaultPath(dir))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Slots) != 2 || info.Slots[1].Type != "kek-file" {
		t.Fatalf("slots after add-slot: %+v", info.Slots)
	}
	// Verify with the machine slot alone, no passphrase in sight.
	t.Setenv(keyEnv, "")
	var vout bytes.Buffer
	if code := vaultVerify(dir, false, strings.NewReader(""), &vout); code != 0 {
		t.Fatalf("verify with the new machine slot: exit %d: %s", code, vout.String())
	}
}

func TestAddSlotRefusesAnUnknownType(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withPassphraseEnv(t)
	before := mustRead(t, vaultPath(dir))
	var out bytes.Buffer
	if code := vaultAddSlot(dir, "cng", false, strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
	if !bytes.Equal(before, mustRead(t, vaultPath(dir))) {
		t.Fatalf("a refused add-slot wrote to the vault")
	}
}

// --- remove-slot, rotate, change-passphrase through the CLI ---

func TestRemoveSlotPrintsTheBakActionAndTheNewGeneration(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultRemoveSlot(dir, fixB64([]byte("slot0002")), strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "no bak") {
		t.Fatalf("remove-slot does not report what it did with the .bak: %s", out.String())
	}
	if !strings.Contains(out.String(), "purge-backups") {
		t.Fatalf("remove-slot does not name the copies it cannot reach: %s", out.String())
	}
	info, err := vault.Inspect(vaultPath(dir))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Slots) != 1 {
		t.Fatalf("%d slots after remove-slot, want 1", len(info.Slots))
	}
}

func TestRemoveSlotRefusesTheLastPassphraseSlotWithExitTwo(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	before := mustRead(t, vaultPath(dir))
	var out bytes.Buffer
	if code := vaultRemoveSlot(dir, fixB64([]byte("slot0001")), strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
	// Exit 2 is not enough: several refusals share it, and the one an operator must see here is
	// "that slot is the recovery key", not "this host cannot reach some other slot".
	if !strings.Contains(out.String(), "last passphrase slot") {
		t.Fatalf("the refusal does not name the last passphrase slot: %s", out.String())
	}
	if !bytes.Equal(before, mustRead(t, vaultPath(dir))) {
		t.Fatalf("a refused remove-slot wrote to the vault")
	}
}

func TestRemoveSlotRefusesAnIdNoSlotCarries(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultRemoveSlot(dir, fixB64([]byte("nosuchid")), strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
}

func TestRotateRefusesAnUnreachableSlotWithExitTwoAndNoDropFlag(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultRotate(dir, strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
	if !strings.Contains(out.String(), fixB64([]byte("slot0002"))) {
		t.Fatalf("the refusal does not name the slot id: %s", out.String())
	}
	// There is deliberately no flag that drops a slot instead: that is remove-slot, by name.
	var usage bytes.Buffer
	vaultCmd([]string{"rotate", "--drop-unreachable"}, strings.NewReader(""), &usage, &usage)
	if !strings.Contains(usage.String(), "not defined") {
		t.Fatalf("--drop-unreachable was accepted: %s", usage.String())
	}
}

func TestRotateReWrapsEveryReachableSlot(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	before, err := vault.Inspect(vaultPath(dir))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	var out bytes.Buffer
	if code := vaultRotate(dir, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	after, err := vault.Inspect(vaultPath(dir))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if after.DEKID == before.DEKID {
		t.Fatalf("rotate kept the dek generation %q", after.DEKID)
	}
	var vout bytes.Buffer
	if code := vaultVerify(dir, true, strings.NewReader(""), &vout); code != 0 {
		t.Fatalf("verify after a rotation: exit %d: %s", code, vout.String())
	}
}

func TestChangePassphraseThroughTheCLIRefusesTheOldOneAfterwards(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultChangePassphrase(dir, strings.NewReader("the-next-passphrase\n"), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if strings.Contains(out.String(), "the-next-passphrase") || strings.Contains(out.String(), fixturePass) {
		t.Fatalf("change-passphrase printed a passphrase: %s", out.String())
	}
	// The old passphrase no longer verifies; the new one does.
	var old bytes.Buffer
	if code := vaultVerify(dir, true, strings.NewReader(""), &old); code != 3 {
		t.Fatalf("verify with the old passphrase: exit %d, want 3: %s", code, old.String())
	}
	t.Setenv(keyEnv, "the-next-passphrase")
	var next bytes.Buffer
	if code := vaultVerify(dir, true, strings.NewReader(""), &next); code != 0 {
		t.Fatalf("verify with the new passphrase: exit %d: %s", code, next.String())
	}
}

// The keyring is migrated and created by `vault init`/`migrate`, so until those land no data dir
// can hold a v2 tunnelkeys.bin. A v1 keyring beside the vault is left byte-identical rather than
// half-changed, and the command says the keyring was not touched.
func TestChangePassphraseLeavesAV1KeyringUntouched(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	withPassphraseEnv(t)
	ring := append([]byte("CSK1"), bytes.Repeat([]byte{0x11}, 16+12+16)...)
	ringPath := filepath.Join(dir, vault.KeyringFileName)
	if err := os.WriteFile(ringPath, ring, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
	var out bytes.Buffer
	if code := vaultChangePassphrase(dir, strings.NewReader("the-next-passphrase\n"), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !bytes.Equal(ring, mustRead(t, ringPath)) {
		t.Fatalf("the v1 keyring was rewritten")
	}
	if !strings.Contains(out.String(), vault.KeyringFileName) {
		t.Fatalf("the command does not say what happened to the keyring: %s", out.String())
	}
}

// A v1 vault has no slots to operate on, and the answer is the format code with the command that
// changes that - never a wrong-key message.
func TestEveryMutatorExitsFourOnAV1Vault(t *testing.T) {
	for _, m := range mutators() {
		t.Run(m.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CREDENTIALS_DIRECTORY", "")
			t.Setenv("CLAUDESWAP_KEK_FILE", "")
			withPassphraseEnv(t)
			v1 := append([]byte("CSV1"), bytes.Repeat([]byte{0x11}, 16+12+16)...)
			if err := os.WriteFile(vaultPath(dir), v1, 0o600); err != nil {
				t.Fatalf("write v1: %v", err)
			}
			var out bytes.Buffer
			if code := m.run(dir, "a-new-passphrase\n", &out); code != 4 {
				t.Fatalf("exit %d, want 4: %s", code, out.String())
			}
			if !strings.Contains(out.String(), "migrate") {
				t.Fatalf("the refusal does not name migrate: %s", out.String())
			}
		})
	}
}

// One structured line per mutator run, in the keys logx already allows: the operation, the slot,
// its type and the exit. Never the KEK, the DEK, a wrap or a path to key material.
func TestAMutatorLogsOneLinePerRun(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	var out bytes.Buffer
	if code := vaultRemoveSlot(dir, fixB64([]byte("slot0002")), strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	var found bool
	for _, line := range bytes.Split(bytes.TrimRight(out.Bytes(), "\n"), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if m["op"] == "remove-slot" {
			found = true
			if m["slot"] != fixB64([]byte("slot0002")) || m["slottype"] != "kek-file" {
				t.Fatalf("the audit line does not name the slot: %v", m)
			}
			if m["exit"] == nil {
				t.Fatalf("the audit line carries no exit: %v", m)
			}
		}
	}
	if !found {
		t.Fatalf("no audit line for the run: %s", out.String())
	}
	if strings.Contains(out.String(), base64.StdEncoding.EncodeToString(fixtureKEK())) {
		t.Fatalf("the output carries the KEK: %s", out.String())
	}
}

// --- the journal stage ladder ---

// The PR 23 review finding, fixed and pinned: runMutation wrote the journal at `started` and never
// advanced it, so the window between the write landing and the journal being removed held a journal
// saying nothing had happened beside a file that had already changed - and the next command's settle
// reported "reverted" for an operation that in fact completed. The journal is now advanced to
// `renamed` after the mutation and before it is cleared.
//
// StageBak has no writer here on purpose: the `.bak` step runs INSIDE internal/vault, between the
// two writes this test brackets, so emitting it would need a progress seam through RemoveSlot and
// Rotate. Nothing is lost by its absence - the package deals with the copy before the rename, so by
// the time the journal reaches `renamed` there is no recovery-copy work left to finish.
func TestEveryMutatorAdvancesTheJournalBeforeClearingIt(t *testing.T) {
	for _, m := range mutators() {
		t.Run(m.name, func(t *testing.T) {
			dir := twoSlotDir(t)
			withPassphraseEnv(t)
			var atClear vault.VaultOp
			var sawClear bool
			restore := watchJournalAtClear(t, &atClear, &sawClear)
			defer restore()

			var out bytes.Buffer
			if code := m.run(dir, "a-new-passphrase\n", &out); code != 0 {
				t.Fatalf("exit %d, want 0: %s", code, out.String())
			}
			if !sawClear {
				t.Fatal("the journal was never cleared, so the ladder cannot be read")
			}
			if atClear.Stage != vault.StageRenamed {
				t.Fatalf("the journal was at stage %q when it was cleared, want %q",
					atClear.Stage, vault.StageRenamed)
			}
			if atClear.Op != m.name {
				t.Fatalf("the journal names op %q, want %q", atClear.Op, m.name)
			}
			if _, ok, err := vault.ReadVaultOp(dir); ok || err != nil {
				t.Fatalf("the journal survived a finished mutation: ok %v err %v", ok, err)
			}
		})
	}
}

// The journal reads `started` while the mutation is in flight, which is the half of the ladder that
// already worked and must keep working: a crash there leaves the file the command started with.
func TestTheJournalReadsStartedWhileTheMutationIsInFlight(t *testing.T) {
	dir := twoSlotDir(t)
	withPassphraseEnv(t)
	var inFlight vault.VaultOp
	var out bytes.Buffer
	code := runMutation(dir, mutation{op: "rotate", files: []string{"vault.bin"}, resealsBak: true,
		reader: newPassphraseReader(strings.NewReader(""), &out),
		apply: func(v *vault.Vault, ks vault.KeySource) (string, error) {
			inFlight, _, _ = vault.ReadVaultOp(dir)
			return "", v.Rotate(ks)
		}}, &out)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if inFlight.Stage != vault.StageStarted {
		t.Fatalf("the journal read %q during the mutation, want %q", inFlight.Stage, vault.StageStarted)
	}
	if !inFlight.ResealsBak {
		t.Fatal("a rotate's journal does not claim the recovery copy")
	}
}

// Only the two operations that invalidate a key claim the recovery copy. add-slot and
// change-passphrase leave every existing key working, so the .bak beside the file still opens under
// keys that are all current, and a settle that re-sealed or DELETED it would destroy a recovery copy
// nobody asked this command to touch. The flag is what the settle reads, so it is asserted on the
// journal the command wrote.
func TestOnlyAKeyInvalidatingMutatorClaimsTheRecoveryCopy(t *testing.T) {
	want := map[string]bool{
		"add-slot": false, "remove-slot": true, "rotate": true, "change-passphrase": false,
	}
	for _, m := range mutators() {
		t.Run(m.name, func(t *testing.T) {
			dir := twoSlotDir(t)
			withPassphraseEnv(t)
			var atClear vault.VaultOp
			var sawClear bool
			restore := watchJournalAtClear(t, &atClear, &sawClear)
			defer restore()

			var out bytes.Buffer
			if code := m.run(dir, "a-new-passphrase\n", &out); code != 0 {
				t.Fatalf("exit %d, want 0: %s", code, out.String())
			}
			if !sawClear {
				t.Fatal("the journal was never cleared, so the flag cannot be read")
			}
			if atClear.ResealsBak != want[m.name] {
				t.Fatalf("%s wrote resealsBak %v, want %v", m.name, atClear.ResealsBak, want[m.name])
			}
		})
	}
}

// And the property the flag exists for, end to end through the command and asserted on the file
// rather than on the journal: a recovery copy beside the vault survives add-slot and
// change-passphrase byte for byte.
func TestAddSlotAndChangePassphraseLeaveTheRecoveryCopyAlone(t *testing.T) {
	for _, m := range mutators() {
		if m.name != "add-slot" && m.name != "change-passphrase" {
			continue
		}
		t.Run(m.name, func(t *testing.T) {
			dir := twoSlotDir(t)
			withPassphraseEnv(t)
			bak := vaultPath(dir) + ".bak"
			if err := os.WriteFile(bak, mustRead(t, vaultPath(dir)), 0o600); err != nil {
				t.Fatal(err)
			}
			before := mustRead(t, bak)
			var out bytes.Buffer
			if code := m.run(dir, "a-new-passphrase\n", &out); code != 0 {
				t.Fatalf("exit %d, want 0: %s", code, out.String())
			}
			if !bytes.Equal(before, mustRead(t, bak)) {
				t.Fatalf("%s changed the recovery copy", m.name)
			}
		})
	}
}

// watchJournalAtClear reads the journal at the moment runMutation removes it, which is the only
// moment the generation written at (iii) is observable: the write and the clear are consecutive
// statements. It then clears it for real, so the command's own behaviour is unchanged.
func watchJournalAtClear(t *testing.T, got *vault.VaultOp, saw *bool) func() {
	t.Helper()
	prev := clearJournalFn
	clearJournalFn = func(dataDir, op string, out io.Writer) {
		if cur, ok, err := vault.ReadVaultOp(dataDir); ok && err == nil {
			*got, *saw = cur, true
		}
		prev(dataDir, op, out)
	}
	return func() { clearJournalFn = prev }
}
