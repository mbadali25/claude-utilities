//go:build windows

package credfile

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

func TestDiagACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.json")
	_ = os.WriteFile(p, []byte("x"), 0o600)
	show := func(label string, args ...string) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		t.Logf("DIAG %s err=%v out=%q", label, err, out)
	}
	show("before", "icacls", p)
	u, _ := user.Current()
	show("grant", "icacls", p, "/inheritance:r", "/grant:r", "*"+u.Uid+":F")
	show("after", "icacls", p)
	show("whoami", "whoami", "/all")
	t.Logf("DIAG restrict=%v", restrictACL(p, false))
	show("after2", "icacls", p)
	t.Fatal("diag")
}
