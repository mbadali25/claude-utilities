package vault

import (
	"encoding/base64"
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
		writeFiles(t, dir, vaultFileName)
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
		if exists(t, filepath.Join(dir, vaultFileName+bakSuffix)) {
			t.Errorf("stage %s: a .bak appeared", stage)
		}
		if _, ok, _ := ReadVaultOp(dir); ok {
			t.Errorf("stage %s: the journal was not cleared", stage)
		}
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
}

// The journal is a plain file beside the vault, so what it may hold is as important as what it
// does. No key, no wrap, no passphrase: the dek.id is an identifier and is not secret.
func TestVaultOpJournalCarriesNoKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	const fakeDEK = "ffffffffffffffffffffffffffffffff"
	const fakePassphrase = "correct-horse-battery-staple"
	t.Setenv(keyEnv, fakePassphrase)

	op := rotateOp(StageBak)
	if err := WriteVaultOp(dir, op); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(VaultOpPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{fakeDEK, fakePassphrase} {
		if strings.Contains(string(data), leak) {
			t.Fatalf("the journal carries %q: %s", leak, data)
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
