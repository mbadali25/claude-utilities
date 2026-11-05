package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// failRenameExceptBackup makes the vault's own write fail while leaving the backup copy's rename
// alone, so a test can reach the save-failure path with a backup already on disk.
func failRenameExceptBackup(t *testing.T) {
	t.Helper()
	renameFn = func(from, to string) error {
		if strings.HasSuffix(to, bakSuffix) {
			return os.Rename(from, to)
		}
		return errors.New("boom")
	}
	t.Cleanup(func() { renameFn = os.Rename })
}

func TestDeleteRemovesOneAccountAndKeepsTheRest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	v.Put(acct("b"))

	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Get("a"); ok {
		t.Fatal("the deleted account is still in the store")
	}
	if _, ok := v.Get("b"); !ok {
		t.Fatal("Delete took another account with it")
	}
}

func TestDeletePersistsAcrossAReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	v.Put(acct("b"))
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}

	v2, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	list := v2.List()
	if len(list) != 1 || list[0].ID != "b" {
		t.Fatalf("after a reload: %+v", list)
	}
}

// The backup is the recovery story for a delete made by mistake, so it must hold the vault as it
// was BEFORE the delete, and the same passphrase must open it.
func TestDeleteLeavesAReadableBackupOfThePreviousVault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	v.Put(acct("b"))
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}

	bak := p + bakSuffix
	got, err := os.ReadFile(bak)
	if err != nil {
		t.Fatalf("no backup beside the vault: %v", err)
	}
	if !bytes.Equal(got, before) {
		t.Fatal("the backup is not the vault's previous bytes")
	}
	v2, err := open(t, bak, "pw")
	if err != nil {
		t.Fatalf("the backup does not open with the same passphrase: %v", err)
	}
	if a, ok := v2.Get("a"); !ok || !bytes.Contains(a.Block, []byte(secret)) {
		t.Fatal("the backup does not hold the deleted account's login")
	}
	// The backup holds the same sealed logins as the vault, so it carries the same owner-only mode.
	// Windows Chmod only toggles the read-only bit, so the owner-only guarantee there is the ACL,
	// asserted for both files in acl_windows_test.go.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(bak)
		if err != nil {
			t.Fatal(err)
		}
		if m := fi.Mode().Perm(); m&0o077 != 0 {
			t.Fatalf("backup mode %v is not owner-only", m)
		}
	}
}

func TestDeletingAnUnknownIDWritesNothingAtAll(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown: %v, want ErrNotFound", err)
	}

	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused delete rewrote the vault")
	}
	if _, err := os.Stat(p + bakSuffix); !os.IsNotExist(err) {
		t.Fatal("a refused delete left a backup behind")
	}
}

// A failed write must leave the vault exactly as it was, on disk as well as in memory: a half
// delete is how a login is lost.
func TestAFailedDeleteWriteChangesNeitherTheStoreNorTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	v.Put(acct("b"))
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	failRenameExceptBackup(t)

	if err := v.Delete("a"); err == nil {
		t.Fatal("expected the failed write to be reported")
	}

	if _, ok := v.Get("a"); !ok {
		t.Fatal("a failed delete dropped the account from the store anyway")
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a failed delete left the vault file changed")
	}
	// The file still has both accounts, so a reload after a failed delete loses nothing.
	v2, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.List()) != 2 {
		t.Fatalf("after a failed delete the file holds %d accounts, want 2", len(v2.List()))
	}
	// No temp file is left in the directory, whichever rename failed.
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("a failed delete left %s behind", e.Name())
		}
	}
}

// A failing backup must stop the delete: deleting without a recovery copy is the one outcome the
// backup exists to prevent.
func TestDeleteIsRefusedWhenTheBackupCannotBeWritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	renameFn = func(string, string) error { return errors.New("boom") }
	t.Cleanup(func() { renameFn = os.Rename })

	if err := v.Delete("a"); err == nil {
		t.Fatal("expected the delete to be refused")
	}
	if _, ok := v.Get("a"); !ok {
		t.Fatal("the account went away without a backup")
	}
}

// A second delete overwrites the one backup rather than stacking copies: it is a regret button,
// not an archive, and a stack of sealed vaults in the data dir is a liability.
func TestASecondDeleteOverwritesTheBackup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	v.Put(acct("b"))
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	mid, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("b"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(p + bakSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mid) {
		t.Fatal("the backup is not the vault as it was before the second delete")
	}
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	var baks int
	for _, e := range ents {
		if strings.Contains(e.Name(), bakSuffix) {
			baks++
		}
	}
	if baks != 1 {
		t.Fatalf("%d backup files, want exactly 1", baks)
	}
}
