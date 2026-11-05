package vault

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func keyringAt(t *testing.T, dir string) *Keyring {
	t.Helper()
	k, err := OpenKeyring(filepath.Join(dir, KeyringFileName), "CSTESTKEY")
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	return k
}

func newKeyring(t *testing.T) (*Keyring, string) {
	t.Helper()
	t.Setenv("CSTESTKEY", "a-long-test-passphrase")
	dir := t.TempDir()
	return keyringAt(t, dir), dir
}

func TestKeyringGeneratePersistsAndNeverReturnsASeed(t *testing.T) {
	k, dir := newKeyring(t)
	infoOut, err := k.Generate("h-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if infoOut.HostID != "h-1" || infoOut.Created.IsZero() || infoOut.Rotating {
		t.Fatalf("unexpected info: %+v", infoOut)
	}
	seed, ok := k.Seed("h-1")
	if !ok || len(seed) != ed25519.SeedSize {
		t.Fatalf("Seed: %v %d", ok, len(seed))
	}
	// The file on disk must not contain the seed in the clear.
	raw, err := os.ReadFile(filepath.Join(dir, KeyringFileName))
	if err != nil {
		t.Fatalf("read keyring: %v", err)
	}
	if bytes.Contains(raw, seed) {
		t.Fatal("the seed is on disk in the clear")
	}
	// Reopening recovers the same key.
	again := keyringAt(t, dir)
	seed2, ok := again.Seed("h-1")
	if !ok || !bytes.Equal(seed, seed2) {
		t.Fatal("the reopened keyring lost the key")
	}
}

func TestKeyringWrongPassphraseIsRefused(t *testing.T) {
	k, dir := newKeyring(t)
	if _, err := k.Generate("h-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Setenv("CSTESTKEY", "a-different-passphrase")
	if _, err := OpenKeyring(filepath.Join(dir, KeyringFileName), "CSTESTKEY"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}

// A keyring must not open a vault file, nor the other way round: the magic differs.
func TestKeyringAndVaultFilesAreNotInterchangeable(t *testing.T) {
	t.Setenv("CSTESTKEY", "a-long-test-passphrase")
	dir := t.TempDir()
	vpath := filepath.Join(dir, "vault.bin")
	v, err := Open(vpath, "CSTESTKEY")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(Account{ID: "a1", Label: "one"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := OpenKeyring(vpath, "CSTESTKEY"); err == nil {
		t.Fatal("a keyring opened the account vault")
	}
	kpath := filepath.Join(dir, KeyringFileName)
	k := keyringAt(t, dir)
	if _, err := k.Generate("h-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := Open(kpath, "CSTESTKEY"); err == nil {
		t.Fatal("the account vault opened a keyring")
	}
}

func TestKeyringRotationKeepsBothKeysUntilCommitted(t *testing.T) {
	k, _ := newKeyring(t)
	if _, err := k.Generate("h-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	first, _, _ := k.PublicKey("h-1")
	rotated, err := k.Rotate("h-1")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !rotated.Rotating {
		t.Fatal("the key does not report itself as rotating")
	}
	cur, prev, ok := k.PublicKey("h-1")
	if !ok || prev == nil {
		t.Fatal("both public keys must be available during the overlap")
	}
	if cur.Equal(first) {
		t.Fatal("Rotate did not produce a new key")
	}
	if !prev.Equal(first) {
		t.Fatal("the previous key is not the one that was in service")
	}
	// A second rotation on top of an unfinished one is refused.
	if _, err := k.Rotate("h-1"); !errors.Is(err, ErrRotating) {
		t.Fatalf("want ErrRotating, got %v", err)
	}
	if err := k.CommitRotation("h-1"); err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	cur2, prev2, _ := k.PublicKey("h-1")
	if prev2 != nil {
		t.Fatal("the old key survived the commit")
	}
	if !cur2.Equal(cur) {
		t.Fatal("the commit changed the live key")
	}
}

func TestKeyringCancelRotationGoesBackToTheOldKey(t *testing.T) {
	k, _ := newKeyring(t)
	if _, err := k.Generate("h-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	first, _, _ := k.PublicKey("h-1")
	if _, err := k.Rotate("h-1"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := k.CancelRotation("h-1"); err != nil {
		t.Fatalf("CancelRotation: %v", err)
	}
	cur, prev, _ := k.PublicKey("h-1")
	if prev != nil || !cur.Equal(first) {
		t.Fatal("cancelling a rotation must leave the original key alone")
	}
}

func TestKeyringDeleteAndUnknownHost(t *testing.T) {
	k, _ := newKeyring(t)
	if _, err := k.Generate("h-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := k.Delete("h-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := k.Seed("h-1"); ok {
		t.Fatal("the seed survived Delete")
	}
	if err := k.Delete("h-1"); err != nil {
		t.Fatalf("deleting twice must be a no-op: %v", err)
	}
	if _, err := k.Rotate("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, ok := k.Get("nope"); ok {
		t.Fatal("Get invented a key")
	}
	if _, err := k.Generate(""); err == nil {
		t.Fatal("an empty host id must be refused")
	}
}

func TestKeyringListIsOrderedAndSeedFree(t *testing.T) {
	k, _ := newKeyring(t)
	for _, id := range []string{"h-3", "h-1", "h-2"} {
		if _, err := k.Generate(id); err != nil {
			t.Fatalf("Generate %s: %v", id, err)
		}
	}
	list := k.List()
	if len(list) != 3 || list[0].HostID != "h-1" || list[2].HostID != "h-3" {
		t.Fatalf("unexpected list: %+v", list)
	}
}
