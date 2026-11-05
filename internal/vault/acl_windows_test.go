//go:build windows

package vault

import (
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// ownerOnlyACL fails unless path carries exactly one ACE and it names the current user. Windows
// Chmod only toggles the read-only bit, so this - not the file mode - is the owner-only guarantee.
func ownerOnlyACL(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, ":(") {
			continue
		}
		n++
		if !aceNamesUser(l, u) {
			t.Fatalf("%s: non-owner ACE: %s", path, strings.TrimSpace(l))
		}
	}
	if n != 1 {
		t.Fatalf("%s: want 1 ACE, got %d", path, n)
	}
}

func TestVaultFileOwnerOnlyACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	if err := v.Put(acct("a")); err != nil {
		t.Fatal(err)
	}
	ownerOnlyACL(t, p)
}

// The delete backup is a full copy of the sealed vault, so it needs the vault's own ACL: a
// world-readable vault.bin.bak would undo the file mode the vault is written with.
func TestDeleteBackupOwnerOnlyACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	if err := v.Put(acct("a")); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	ownerOnlyACL(t, p+bakSuffix)
}

// aceNamesUser reports whether an icacls ACE line names u. icacls prints the account name, which for
// a well-known account (a CI runner under NT AUTHORITY\SYSTEM) need not equal user.Current().Username,
// so the short name after the backslash is matched too.
func aceNamesUser(line string, u *user.User) bool {
	short := u.Username[strings.LastIndex(u.Username, `\`)+1:]
	return strings.Contains(line, u.Username) || strings.Contains(line, u.Uid) || strings.Contains(line, `\`+short+":")
}
