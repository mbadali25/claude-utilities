//go:build windows

package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// On Windows the file mode says nothing: Chmod only toggles the read-only bit and Stat reports
// 0666 whatever was asked for. The ACL is the real control, and it is what Windows ssh.exe looks
// at when it decides a key is too permissive, so that is what is asserted here.
//
// NOT VERIFIED: that this exact ACL is one ssh.exe accepts. It is the same owner-only ACL the
// credentials file uses and the same shape as the runbook's icacls recipe, which is the best
// available answer without a real run against a real host.
func checkKeyFileRestricted(t *testing.T, path string) {
	t.Helper()
	if err := ownerOnlyACL(path); err != nil {
		t.Errorf("%s: %v", filepath.Base(path), err)
	}
}

// ownerOnlyACL fails unless the ACL grants access to the current user only.
func ownerOnlyACL(path string) error {
	out, err := exec.Command("icacls", path).CombinedOutput() // #nosec G204 -- fixed binary, test-owned path
	if err != nil {
		return fmt.Errorf("icacls: %w", err)
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, ":(") {
			continue
		}
		n++
		if !aceNamesUser(l, u) {
			return fmt.Errorf("non-owner ACE: %s (user %s, uid %s; full icacls: %q)", strings.TrimSpace(l), u.Username, u.Uid, out)
		}
	}
	if n != 1 {
		return fmt.Errorf("want 1 ACE, got %d", n)
	}
	return nil
}

// The key directory itself must be owner-only too, with an inheritable grant, or a file created
// inside it is readable before RestrictFile runs.
func TestKeyDirAndKeyFileAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	kd, err := keyDir(dir)
	if err != nil {
		t.Fatalf("keyDir: %v", err)
	}
	if err := ownerOnlyACL(kd); err != nil {
		t.Fatalf("key dir: %v", err)
	}
	p, err := writeKeyFile(kd, "h-1", bytes.Repeat([]byte{4}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	if err := ownerOnlyACL(p); err != nil {
		t.Fatalf("key file: %v", err)
	}
}

// aceNamesUser reports whether an icacls ACE line names u. icacls prints the account name, which for
// a well-known account (a CI runner under NT AUTHORITY\SYSTEM) need not equal user.Current().Username,
// so the short name after the backslash is matched too.
func aceNamesUser(line string, u *user.User) bool {
	short := u.Username[strings.LastIndex(u.Username, `\`)+1:]
	return strings.Contains(line, u.Username) || strings.Contains(line, u.Uid) || strings.Contains(line, `\`+short+":")
}
