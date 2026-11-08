//go:build windows

package vault

import (
	"path/filepath"
	"testing"
)

// The lock file is the one file in the data dir that is not written through replaceFile, so it is
// the one place a missing owner-only grant would not be caught by an existing ACL test. Windows
// Chmod only toggles the read-only bit, so the ACL - not the file mode - is the guarantee, and the
// holder line names a pid and a command in a directory whose files are owner-only as a class.
func TestLockFileOwnerOnlyACL(t *testing.T) {
	dir := t.TempDir()
	acquire(t, dir, "run")
	ownerOnlyACL(t, LockPath(dir))
}

// The data dir itself, when AcquireLock is the thing that created it: `vault init` takes the lock
// before anything in the data dir exists. A directory left with an inherited ACL hands that ACL to
// every file written into it afterwards, so the MkdirAll has to be paired with the grant.
func TestAcquireCreatedDataDirOwnerOnlyACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	acquire(t, dir, "init")
	ownerOnlyACL(t, dir)
}

// And the journal, for the same reason: it is written through replaceFile, but it is new, so the
// grant is asserted where it lands rather than inferred from the writer it shares.
func TestVaultOpJournalOwnerOnlyACL(t *testing.T) {
	dir := t.TempDir()
	if err := WriteVaultOp(dir, rotateOp(StageStarted)); err != nil {
		t.Fatal(err)
	}
	ownerOnlyACL(t, VaultOpPath(dir))
}
