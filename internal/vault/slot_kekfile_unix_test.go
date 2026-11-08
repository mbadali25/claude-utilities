//go:build unix

package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The half of the kek-file tests that needs a real kernel: a directory whose mode actually denies
// traversal, a real FIFO, and the real owner lookup. None of it can be expressed through a seam,
// because the bug these cover is precisely that os.Stat's error was read as "the file is absent".
//
// Every test here skips as uid 0 and says so: root traverses a 0000 directory and owns every file
// it creates, so the distinction under test does not exist for root.

// denyTraversal makes dir unreadable and unsearchable, and restores it before t.TempDir's own
// cleanup runs - which would otherwise fail on a directory it cannot descend into.
func denyTraversal(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod 0000 %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as uid 0 (real geteuid, not the seam): root traverses a 0000 directory, so there is no permission error to produce")
	}
}

func TestResolveKEKRefusesACredstoreEntryItCannotStat(t *testing.T) {
	// The finding this test exists for. /etc/credstore and /etc/credstore.encrypted are root:root
	// 0700 on the surveyed host, so a non-root operator CLI stating the entry inside gets EACCES,
	// not ENOENT. Read as "absent", that made the uid-0 refusal unreachable and the open fell
	// quietly through to the passphrase - telling an operator who asked for the machine slot that
	// their passphrase is the only key, which is the one diagnosis the slot must never give.
	skipAsRoot(t)
	kekFixture(t)
	encPath := filepath.Join(credstoreEncryptedDir, kekCredstoreFile)
	if err := os.WriteFile(encPath, []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}
	denyTraversal(t, credstoreEncryptedDir)
	asUID(t, 1000)
	calls := decryptSeam(t, bytes.Repeat([]byte{0x3c}, keyLen), nil)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if err == nil {
		t.Fatal("a credstore entry this process cannot stat was read as absent, so the resolve fell through to the passphrase")
	}
	if kek != nil || route != kekRouteUnreachable {
		t.Fatalf("kek = %d bytes, route = %q", len(kek), route)
	}
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("err = %v, want ErrKEKUnreachable (the exit-2 class)", err)
	}
	if !strings.Contains(err.Error(), encPath) {
		t.Fatalf("error does not name the file the operator has to act on: %v", err)
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("error does not say root is what is missing: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatal("systemd-creds was run as a non-root uid")
	}
}

func TestResolveKEKRefusesACredentialsDirectoryItCannotStat(t *testing.T) {
	// Step 1's stat had the same shape: anything that was not nil fell through in silence. ENOENT
	// must still fall through - a unit may have been handed some other credential and no KEK - but
	// a credential directory this process cannot read is a configured KEK it cannot reach, and the
	// difference is exit 2 against a passphrase prompt.
	skipAsRoot(t)
	kekFixture(t)
	credsDir := filepath.Join(t.TempDir(), "creds")
	if err := os.MkdirAll(credsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(credsDir, "vault-kek")
	writeKEK(t, path, keyLen, 0o600)
	denyTraversal(t, credsDir)
	t.Setenv(credentialsDirEnv, credsDir)
	asUID(t, 1000)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek"})
	if err == nil {
		t.Fatal("an unreadable $CREDENTIALS_DIRECTORY was read as absent")
	}
	if kek != nil || route != kekRouteUnreachable {
		t.Fatalf("kek = %d bytes, route = %q", len(kek), route)
	}
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("err = %v, want ErrKEKUnreachable", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error does not name the credential: %v", err)
	}

	// An absent credential in a readable directory still falls through, which is the case this must
	// not turn into a failure.
	if err := os.Chmod(credsDir, 0o700); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek"}); err != nil || kek != nil || route != kekRouteUnreachable {
		t.Fatalf("an absent credential gave kek = %d bytes, route = %q, err = %v; want a silent fall-through", len(kek), route, err)
	}
}

func TestReadKEKFileDoesNotBlockOnAFifo(t *testing.T) {
	// os.ReadFile on a FIFO with no writer blocks in open(2), forever. A server start that hit one
	// would hang with no error, no log line and no timeout. The regular-file check happens before
	// anything is opened, so the refusal is immediate - and this test is written as a race against
	// a timer because a regression here does not fail, it hangs.
	dir := kekFixture(t)
	fifo := filepath.Join(dir, "fifo.kek")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo is unavailable here: %v", err)
	}
	asUID(t, 1000)

	type result struct {
		route string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		_, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", KEKFile: fifo})
		done <- result{route, err}
	}()
	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("resolveKEK accepted a FIFO as --kek-file")
		}
		if got.route != kekRouteUnreachable {
			t.Fatalf("route = %q, want %q", got.route, kekRouteUnreachable)
		}
		if !errors.Is(got.err, ErrKEKUnreachable) {
			t.Fatalf("err = %v, want ErrKEKUnreachable", got.err)
		}
		if !strings.Contains(got.err.Error(), "regular file") {
			t.Fatalf("error does not say what it refused: %v", got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("resolveKEK blocked on a FIFO with no writer; it must refuse on the mode, before any open")
	}
}

func TestFileOwnerUIDReportsTheRealOwner(t *testing.T) {
	// The seam the other tests drive has to sit on something real. This is the only test that
	// exercises the syscall.Stat_t path, so a build-tag mistake that left the !unix stub compiled
	// in on Linux - which would turn the root-ownership check off everywhere - fails here.
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	uid, known := fileOwnerUID(fi)
	if !known {
		t.Fatal("fileOwnerUID could not report an owner on unix, so the root-ownership check is off")
	}
	if uid != os.Geteuid() {
		t.Fatalf("fileOwnerUID = %d, want this process's uid %d", uid, os.Geteuid())
	}
}
