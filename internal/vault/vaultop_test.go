package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fakeDEKID = "AAECAwQFBgcICQoLDA0ODw==" // 16 bytes, the length a dek.id must decode to

func rotateOp(stage string) VaultOp {
	return VaultOp{
		Op:       "rotate",
		Files:    []string{vaultFileName, KeyringFileName},
		NewDEKID: fakeDEKID,
		Stage:    stage,
	}
}

// writeFiles drops a byte string at each name in dir, so a settle has something to act on.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("contents of "+n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v", path, err)
	}
	return err == nil
}

func TestVaultOpRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := ReadVaultOp(dir); ok || err != nil {
		t.Fatalf("ReadVaultOp on a clean data dir = ok %v err %v", ok, err)
	}
	op := rotateOp(StageStarted)
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatalf("WriteVaultOp: %v", err)
	}
	got, ok, err := ReadVaultOp(dir)
	if err != nil || !ok {
		t.Fatalf("ReadVaultOp = ok %v err %v", ok, err)
	}
	if got.Op != op.Op || got.Stage != op.Stage || got.NewDEKID != op.NewDEKID || strings.Join(got.Files, ",") != strings.Join(op.Files, ",") {
		t.Fatalf("round trip = %+v, want %+v", got, op)
	}
	if err := ClearVaultOp(dir); err != nil {
		t.Fatalf("ClearVaultOp: %v", err)
	}
	if _, ok, _ := ReadVaultOp(dir); ok {
		t.Fatal("journal still present after ClearVaultOp")
	}
	// Clearing a journal that is not there is how settle-on-start ends on a clean data dir.
	if err := ClearVaultOp(dir); err != nil {
		t.Fatalf("second ClearVaultOp: %v", err)
	}
}

// The journal names every file the operation spans. That is the hole it closes: a rotate crosses
// vault.bin and tunnelkeys.bin, and a crash between them leaves a pair nothing else can explain.
func TestVaultOpNamesBothFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteVaultOp(dir, rotateOp(StageStarted)); err != nil {
		t.Fatal(err)
	}
	op, _, err := ReadVaultOp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(op.Files) != 2 || op.Files[0] != vaultFileName || op.Files[1] != KeyringFileName {
		t.Fatalf("files = %v, want [%s %s]", op.Files, vaultFileName, KeyringFileName)
	}
}

// The journal must be on disk, whole and fsynced, before anything makes it visible - a rename over
// a journal half-written is a journal that settles to the wrong answer.
func TestVaultOpIsDurableBeforeItBecomesVisible(t *testing.T) {
	dir := t.TempDir()
	var sawAtRename []byte
	restore := renameFn
	renameFn = func(from, to string) error {
		sawAtRename, _ = os.ReadFile(from) //nolint:errcheck // the assertion is on the bytes
		return restore(from, to)
	}
	t.Cleanup(func() { renameFn = restore })

	op := rotateOp(StageStarted)
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"op":"rotate"`, vaultFileName, KeyringFileName, StageStarted} {
		if !strings.Contains(string(sawAtRename), want) {
			t.Fatalf("the temp journal did not already carry %q before the rename: %s", want, sawAtRename)
		}
	}
}

func TestSettleCompletesAnInterruptedBakReseal(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, vaultFileName, vaultFileName+bakSuffix, KeyringFileName, KeyringFileName+bakSuffix)
	op := rotateOp(StageRenamed)
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}

	var resealed []string
	restore := resealBak
	resealBak = func(path string, _ VaultOp, _ KeySource) (string, error) {
		resealed = append(resealed, filepath.Base(path))
		return bakResealed, nil
	}
	t.Cleanup(func() { resealBak = restore })

	result, err := SettleVaultOp(dir, op, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("SettleVaultOp: %v", err)
	}
	if !strings.HasPrefix(result, "completed") || !strings.Contains(result, bakResealed) {
		t.Fatalf("result = %q, want a completed re-seal", result)
	}
	if len(resealed) != 2 || resealed[0] != vaultFileName || resealed[1] != KeyringFileName {
		t.Fatalf("re-sealed %v, want both files", resealed)
	}
	if _, ok, _ := ReadVaultOp(dir); ok {
		t.Fatal("the journal was not cleared after a completed settle")
	}
}

// With no re-seal available the .bak is removed instead: a backup the removed key can still open
// is the hole the ordering change closed, and losing a recovery copy is the lesser harm. The spec
// says so, and the command prints it.
func TestSettleRemovesABakItCannotReseal(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, vaultFileName, vaultFileName+bakSuffix)
	op := VaultOp{Op: "remove-slot", Files: []string{vaultFileName}, NewDEKID: fakeDEKID, Stage: StageRenamed}
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}
	result, err := SettleVaultOp(dir, op, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("SettleVaultOp: %v", err)
	}
	if !strings.HasPrefix(result, "completed") || !strings.Contains(result, bakRemoved) {
		t.Fatalf("result = %q, want a completed removal", result)
	}
	if exists(t, filepath.Join(dir, vaultFileName+bakSuffix)) {
		t.Fatal("the .bak is still there")
	}
	if !exists(t, filepath.Join(dir, vaultFileName)) {
		t.Fatal("settle removed the file it was meant to keep")
	}
}

// Before the new generation is visible there is nothing to complete: the old file is the one the
// command started with, so settle reverts and says so.
func TestSettleRevertsWhenItCannotComplete(t *testing.T) {
	for _, stage := range []string{StageStarted, StageBak} {
		dir := t.TempDir()
		writeFiles(t, dir, vaultFileName, vaultFileName+bakSuffix)
		op := rotateOp(stage)
		if err := WriteVaultOp(dir, op); err != nil {
			t.Fatal(err)
		}
		result, err := SettleVaultOp(dir, op, EnvKey(keyEnv))
		if err != nil {
			t.Fatalf("stage %s: SettleVaultOp: %v", stage, err)
		}
		if result != "reverted" {
			t.Errorf("stage %s: result = %q, want \"reverted\"", stage, result)
		}
		if !exists(t, filepath.Join(dir, vaultFileName)) {
			t.Errorf("stage %s: the old file is gone", stage)
		}
		// A settle that reverts touches no file. Deleting a .bak is step (ii)'s job inside the
		// operation, not a settle's: at StageStarted the operation had not reached it, so the .bak
		// beside the generation on disk is still that generation's recovery copy. The assertion
		// this replaces - "a .bak appeared" - could not fail, because nothing in the setup made one.
		bak := filepath.Join(dir, vaultFileName+bakSuffix)
		got, rerr := os.ReadFile(bak)
		if rerr != nil {
			t.Errorf("stage %s: the .bak did not survive the revert: %v", stage, rerr)
		} else if string(got) != "contents of "+vaultFileName+bakSuffix {
			t.Errorf("stage %s: the .bak's bytes changed: %q", stage, got)
		}
		if _, ok, _ := ReadVaultOp(dir); ok {
			t.Errorf("stage %s: the journal was not cleared", stage)
		}
	}
}

// One Stage for up to maxVaultOpFiles files cannot say that the rename of file 1 of 2 landed and
// the rename of file 2 did not. The pair on disk can, and a settle that read that pair as settled
// would either delete the .bak of the half that never landed - the only copy of it - or clear the
// journal and call the data dir clean. Both stage values refuse instead.
func TestSettleRefusesAMixedPair(t *testing.T) {
	for _, stage := range []string{StageStarted, StageBak, StageRenamed} {
		dir := t.TempDir()
		// A crash between file 1 and file 2 of 2: the vault is the new generation, the keyring is
		// still the old one.
		if err := os.WriteFile(filepath.Join(dir, vaultFileName), []byte(v2VaultMagic+"....."), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, KeyringFileName), []byte(keyringMagic+"....."), 0o600); err != nil {
			t.Fatal(err)
		}
		writeFiles(t, dir, vaultFileName+bakSuffix, KeyringFileName+bakSuffix)
		op := rotateOp(stage)
		if err := WriteVaultOp(dir, op); err != nil {
			t.Fatal(err)
		}

		result, err := SettleVaultOp(dir, op, EnvKey(keyEnv))
		if err == nil {
			t.Fatalf("stage %s: SettleVaultOp reported a mixed pair as %q", stage, result)
		}
		if !errors.Is(err, ErrVaultOpMixedPair) {
			t.Errorf("stage %s: err = %v, want ErrVaultOpMixedPair", stage, err)
		}
		for _, want := range []string{vaultFileName, KeyringFileName, "server vault verify --all-slots"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("stage %s: message %q does not name %q", stage, err.Error(), want)
			}
		}
		// Nothing deleted and nothing cleared: a refused settle leaves the data dir exactly as it
		// found it, so the human the message names still has everything to look at.
		for _, n := range []string{
			vaultFileName, KeyringFileName,
			vaultFileName + bakSuffix, KeyringFileName + bakSuffix,
		} {
			if !exists(t, filepath.Join(dir, n)) {
				t.Errorf("stage %s: a refused settle deleted %s", stage, n)
			}
		}
		if _, ok, _ := ReadVaultOp(dir); !ok {
			t.Errorf("stage %s: a refused settle cleared the journal", stage)
		}
	}
}

// The journal is a file in the data dir, so anyone who can write there decides how large it is, and
// every mutator reads it before it does anything. The read is bounded, and the bound refuses on
// size rather than letting a truncated read fail as a parse error - which would report the wrong
// problem for a file whose only problem is its size.
func TestAnOversizedJournalIsRefused(t *testing.T) {
	head := `{"op":"rotate","files":["` + vaultFileName + `"],"newDekId":"` + fakeDEKID + `","stage":"renamed"`
	// Whitespace before the closing brace is valid JSON, so the only difference between these two
	// is the byte count.
	atBound := head + strings.Repeat(" ", maxVaultOpBytes-len(head)-1) + "}"
	overBound := head + strings.Repeat(" ", maxVaultOpBytes-len(head)) + "}"

	dir := t.TempDir()
	if err := os.WriteFile(VaultOpPath(dir), []byte(atBound), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadVaultOp(dir); !ok || err != nil {
		t.Fatalf("a %d-byte journal (the bound) = ok %v err %v, want it read", len(atBound), ok, err)
	}

	if err := os.WriteFile(VaultOpPath(dir), []byte(overBound), 0o600); err != nil {
		t.Fatal(err)
	}
	op, ok, err := ReadVaultOp(dir)
	if ok || err == nil {
		t.Fatalf("a %d-byte journal = op %+v ok %v err %v, want a refusal", len(overBound), op, ok, err)
	}
	if !errors.Is(err, ErrVaultOpUnreadable) {
		t.Fatalf("err = %v, want ErrVaultOpUnreadable", err)
	}
}

// The window the ordering change trades for is this one, and it is harmless: a crash after the
// .bak step and before the rename leaves the old file, which is the state before the command ran,
// and no .bak.
func TestCrashAfterBakResealBeforeRenameLeavesTheOldVault(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, vaultFileName)
	op := rotateOp(StageBak)
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, vaultFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SettleVaultOp(dir, op, EnvKey(keyEnv)); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, vaultFileName))
	if err != nil {
		t.Fatalf("the old file did not survive the settle: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("the old file's bytes changed")
	}
}

// A settle that cannot finish is reported, never guessed at. The caller refuses rather than
// mutating on top of an unsettled journal.
func TestSettleFailsWhenTheResealFails(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, vaultFileName, vaultFileName+bakSuffix)
	op := VaultOp{Op: "rotate", Files: []string{vaultFileName}, NewDEKID: fakeDEKID, Stage: StageRenamed}
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}
	restore := resealBak
	resealBak = func(string, VaultOp, KeySource) (string, error) { return "", errors.New("disk full") }
	t.Cleanup(func() { resealBak = restore })

	if _, err := SettleVaultOp(dir, op, EnvKey(keyEnv)); err == nil {
		t.Fatal("SettleVaultOp reported success after the re-seal failed")
	}
	if _, ok, _ := ReadVaultOp(dir); !ok {
		t.Fatal("the journal was cleared by a settle that failed")
	}
}

// A torn or hostile journal is refused, not acted on. It is a file in the data dir, so anyone who
// can write there can write it, and settle deletes a .bak from what it says.
func TestATornOrHostileJournalIsRefused(t *testing.T) {
	bad := []string{
		`{"op":"rotate","files":["vault.bin"],"newDekId":"` + fakeDEKID + `","stage":"rena`,
		`{"op":"rotate","files":[],"newDekId":"","stage":"renamed"}`,
		`{"op":"","files":["vault.bin"],"newDekId":"","stage":"renamed"}`,
		`{"op":"rotate","files":["vault.bin"],"newDekId":"","stage":"not-a-stage"}`,
		`{"op":"rotate","files":["../../../etc/passwd"],"newDekId":"","stage":"renamed"}`,
		`{"op":"rotate","files":["sub/vault.bin"],"newDekId":"","stage":"renamed"}`,
		`{"op":"rotate","files":[".."],"newDekId":"","stage":"renamed"}`,
		`{"op":"rotate","files":["vault.bin"],"newDekId":"not-base64","stage":"renamed"}`,
		`{"op":"rotate","files":["vault.bin"],"newDekId":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `","stage":"renamed"}`,
		`{"op":"rot\nate","files":["vault.bin"],"newDekId":"","stage":"renamed"}`,
		"",
		"not json at all",
	}
	for _, body := range bad {
		dir := t.TempDir()
		if err := os.WriteFile(VaultOpPath(dir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		op, ok, err := ReadVaultOp(dir)
		if ok || err == nil {
			t.Errorf("ReadVaultOp accepted %q: op %+v ok %v err %v", body, op, ok, err)
			continue
		}
		if !errors.Is(err, ErrVaultOpUnreadable) {
			t.Errorf("ReadVaultOp(%q) = %v, want ErrVaultOpUnreadable", body, err)
		}
	}
	// And WriteVaultOp refuses to create one of those shapes in the first place.
	dir := t.TempDir()
	for _, op := range []VaultOp{
		{Op: "rotate", Files: []string{"../escape"}, Stage: StageStarted},
		{Op: "rotate", Files: nil, Stage: StageStarted},
		{Op: "rotate", Files: []string{vaultFileName}, Stage: "nonsense"},
	} {
		if err := WriteVaultOp(dir, op); err == nil {
			t.Errorf("WriteVaultOp wrote %+v", op)
		}
	}
}

// A journal naming a path outside the data dir must not make settle touch it.
func TestSettleRefusesAFileOutsideTheDataDir(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim.bin")
	if err := os.WriteFile(outside+bakSuffix, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	op := VaultOp{Op: "rotate", Files: []string{"../" + filepath.Base(filepath.Dir(outside)) + "/victim.bin"}, Stage: StageRenamed}
	if _, err := SettleVaultOp(dir, op, EnvKey(keyEnv)); err == nil {
		t.Fatal("SettleVaultOp acted on a file outside the data dir")
	}
	if !exists(t, outside+bakSuffix) {
		t.Fatal("the file outside the data dir was deleted")
	}
}

// v2 vault beside a v1 keyring, with no journal to explain it, is a state a human has to look at:
// it is named, with the command that inspects it, and never quietly repaired.
func TestMixedPairIsDetectedAndReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, vaultFileName), []byte(v2VaultMagic+"....."), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyringFileName), []byte(keyringMagic+"....."), 0o600); err != nil {
		t.Fatal(err)
	}
	line, mixed := MixedPair(dir)
	if !mixed {
		t.Fatal("MixedPair = false for a v2 vault beside a v1 keyring")
	}
	for _, want := range []string{vaultFileName, KeyringFileName, "v2", "v1", "server vault verify --all-slots"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q does not name %q", line, want)
		}
	}

	// A matching pair, and a pair where one file does not exist yet, are not mixed.
	if err := os.WriteFile(filepath.Join(dir, KeyringFileName), []byte(v2KeyringMagic+"....."), 0o600); err != nil {
		t.Fatal(err)
	}
	if line, mixed := MixedPair(dir); mixed {
		t.Errorf("MixedPair = true for a v2 pair: %q", line)
	}
	if err := os.Remove(filepath.Join(dir, KeyringFileName)); err != nil {
		t.Fatal(err)
	}
	if line, mixed := MixedPair(dir); mixed {
		t.Errorf("MixedPair = true with no keyring at all: %q", line)
	}

	// A file shorter than a magic is not a format this binary knows, so it is not half of a mixed
	// pair either: the opener reports the damage, with the message it already has. formatVersion
	// reads the magic with io.ReadFull for this reason - a short read that came back without an
	// error would compare a part-filled buffer and could name a version off bytes it never read.
	for _, short := range []string{"", "CS", keyringMagic[:len(keyringMagic)-1]} {
		if err := os.WriteFile(filepath.Join(dir, KeyringFileName), []byte(short), 0o600); err != nil {
			t.Fatal(err)
		}
		if line, mixed := MixedPair(dir); mixed {
			t.Errorf("MixedPair = true for a %d-byte keyring: %q", len(short), line)
		}
	}
}

// The journal is a plain file beside the vault, so what it may hold is as important as what it
// does: an operation name, file names, the base64 dek.id and a stage, and nothing else. The dek.id
// is the HKDF salt and part of every slot's AAD, so it is public by construction.
//
// The assertion is on the field set, because that is the thing that can change. The version this
// replaces looked for a DEK and a passphrase that were never handed to WriteVaultOp in the first
// place - two string constants compared against a file they could not reach - so it would have
// passed whatever the writer did. A field added to VaultOp that carried a wrap or a DEK would land
// in this file, and this is what sees it.
func TestVaultOpJournalCarriesOnlyItsFourPublicFields(t *testing.T) {
	dir := t.TempDir()
	if err := WriteVaultOp(dir, rotateOp(StageBak)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(VaultOpPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"op": true, "files": true, "newDekId": true, "stage": true}
	for k := range fields {
		if !want[k] {
			t.Errorf("the journal carries a field this test has not vetted, %q: %s", k, data)
		}
	}
	for k := range want {
		if _, ok := fields[k]; !ok {
			t.Errorf("the journal is missing %q: %s", k, data)
		}
	}
	if !strings.Contains(string(data), fakeDEKID) {
		t.Fatalf("the journal does not carry the dek.id: %s", data)
	}
	// Owner-only, like every other file in the data dir.
	st, err := os.Stat(VaultOpPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %v, want 0600", st.Mode().Perm())
	}
}

// A KeySource is the one way a passphrase reaches this file's code: SettleVaultOp is handed one for
// the re-seal. It must not reach the disk, and the file a failed settle leaves behind is where it
// would show up, so the whole data dir is read back and checked.
func TestSettleWritesNoPassphraseIntoTheDataDir(t *testing.T) {
	const fakePassphrase = "correct-horse-battery-staple"
	t.Setenv(keyEnv, fakePassphrase)

	dir := t.TempDir()
	writeFiles(t, dir, vaultFileName, vaultFileName+bakSuffix)
	op := VaultOp{Op: "rotate", Files: []string{vaultFileName}, NewDEKID: fakeDEKID, Stage: StageRenamed}
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}
	restore := resealBak
	resealBak = func(string, VaultOp, KeySource) (string, error) { return "", errors.New("disk full") }
	t.Cleanup(func() { resealBak = restore })

	if _, err := SettleVaultOp(dir, op, EnvKey(keyEnv)); err == nil {
		t.Fatal("SettleVaultOp reported success after the re-seal failed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the data dir is empty: there is nothing for this test to check")
	}
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), fakePassphrase) {
			t.Errorf("%s carries the passphrase", e.Name())
		}
	}
}
