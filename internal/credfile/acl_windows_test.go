//go:build windows

package credfile

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// checkOwnerOnly fails unless the ACL grants access to the current user only.
func checkOwnerOnly(path string) error {
	out, err := exec.Command("icacls", path).CombinedOutput()
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
			return fmt.Errorf("non-owner ACE: %s", strings.TrimSpace(l))
		}
	}
	if n != 1 {
		return fmt.Errorf("want 1 ACE, got %d", n)
	}
	return nil
}

func TestOwnerOnlyACL(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(oauth("old", 1)))
	backup, err := Replace(p, json.RawMessage(oauth("n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, backup, filepath.Dir(backup)} {
		if err := checkOwnerOnly(f); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
	}
}

// aceNamesUser reports whether an icacls ACE line names u. icacls prints the account name, which for
// a well-known account (a CI runner under NT AUTHORITY\SYSTEM) need not equal user.Current().Username,
// so the short name after the backslash is matched too.
func aceNamesUser(line string, u *user.User) bool {
	short := u.Username[strings.LastIndex(u.Username, `\`)+1:]
	return strings.Contains(line, u.Username) || strings.Contains(line, u.Uid) || strings.Contains(line, `\`+short+":")
}
