//go:build windows

package vault

import (
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultFileOwnerOnlyACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	if err := v.Put(acct("a")); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("icacls", p).CombinedOutput()
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
		if !strings.Contains(l, u.Username) && !strings.Contains(l, u.Uid) {
			t.Fatalf("non-owner ACE: %s", strings.TrimSpace(l))
		}
	}
	if n != 1 {
		t.Fatalf("want 1 ACE, got %d", n)
	}
}
