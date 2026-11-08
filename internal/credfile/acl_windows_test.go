//go:build windows

package credfile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// checkOwnerOnly fails unless the ACL grants access to the current user only. It hands the path
// to icacls in the same form restrictACL does, so a path past MAX_PATH can be read back too.
func checkOwnerOnly(path string) error {
	p, err := icaclsPath(path)
	if err != nil {
		return err
	}
	out, err := exec.Command("icacls", p).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w: %s", err, strings.TrimSpace(string(out)))
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

// Review item 1: a failed icacls run has to hand the caller the tool's own output. icacls echoes
// the path it refused, so the error naming it proves the output came through — and unlike the
// message text, the path does not change with the host's language.
func TestRestrictFileErrorCarriesICACLSOutput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "never-created.json")
	err := RestrictFile(p)
	if err == nil {
		t.Fatal("RestrictFile on a path that does not exist: want an error, got nil")
	}
	for _, want := range []string{"credfile: clear ACL failed", filepath.Base(p)} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

// Review Focus 2: icacls takes the path as an argument and a long one has to be handed over in
// extended-length form, so a path over MAX_PATH or with non-ASCII segments must come out restricted
// — never left unrestricted with a nil error, and never readable by anyone but the owner.
func TestRestrictFileAcceptsNonASCIIAndLongPath(t *testing.T) {
	dir := t.TempDir()
	for len(dir) < 280 {
		dir = filepath.Join(dir, "ü日-segment")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %d chars: %v", len(dir), err)
	}
	if err := RestrictDir(dir); err != nil {
		t.Fatalf("RestrictDir on a %d-char path: %v", len(dir), err)
	}
	if err := checkOwnerOnly(dir); err != nil {
		t.Fatalf("ACL of the %d-char dir: %v", len(dir), err)
	}
	p := filepath.Join(dir, "ü日.json")
	if err := os.WriteFile(p, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := RestrictFile(p); err != nil {
		t.Fatalf("RestrictFile on a %d-char path: %v", len(p), err)
	}
	if err := checkOwnerOnly(p); err != nil {
		t.Fatalf("ACL of the %d-char file: %v", len(p), err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != `{"x":1}` {
		t.Fatalf("file no longer opens after RestrictFile: %q, %v", b, err)
	}
}

// serviceTestEnv opts in to the one test that creates a Windows service. Review item 2: gating on
// CI plus an elevated token made it create and delete a real service on every elevated CI run,
// which is not something a test suite should do without being asked.
const serviceTestEnv = "CLAUDESWAP_TEST_SERVICE"

// TestPolicyACLGrantsAdministratorsAndServiceSID proves the one part of the data-dir-ACL decision
// that a pure argument-list test cannot: that icacls accepts a real NT SERVICE\ SID and that a file
// restricted under the policy is reachable by Administrators and by the service as well as the owner.
//
// It creates and deletes a throwaway Windows service, so it runs only on explicit opt-in:
//
//	CLAUDESWAP_TEST_SERVICE=1 go test -race -run TestPolicyACLGrantsAdministratorsAndServiceSID ./internal/credfile
//
// from an elevated shell on a host where creating a service is acceptable. It is not set in CI. The
// service is named uniquely per run so it can never collide with a real service or with a previous
// crashed run, its delete is registered before any assertion so a failing assert still removes it,
// its binary path is a placeholder and it is never started.
func TestPolicyACLGrantsAdministratorsAndServiceSID(t *testing.T) {
	if os.Getenv(serviceTestEnv) != "1" {
		t.Skipf("set %s=1 to opt in: this test creates and deletes a throwaway Windows service to obtain a real NT SERVICE\\ SID", serviceTestEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("not elevated: creating a service needs an elevated token")
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Skipf("service control manager unavailable: %v", err)
	}
	defer func() { _ = m.Disconnect() }()
	name := fmt.Sprintf("ClaudeSwapACLTest-%d-%d", os.Getpid(), time.Now().UnixNano())
	s, err := m.CreateService(name, filepath.Join(t.TempDir(), "never-started.exe"), mgr.Config{
		DisplayName: name,
		Description: "claude-swap ACL test; never started, deleted by the test",
		StartType:   mgr.StartManual,
	})
	if err != nil {
		t.Skipf("create throwaway service %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := s.Delete(); err != nil {
			t.Errorf("delete throwaway service %s: %v", name, err)
		}
		_ = s.Close()
	})
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+name)
	if err != nil {
		t.Fatalf("look up the SID of %s: %v", name, err)
	}
	usePolicy(t, "S-1-5-32-544", sid.String())

	dir := t.TempDir()
	p := write(t, dir, fileWith(oauth("old", 1)))
	if err := RestrictFile(p); err != nil {
		t.Fatalf("RestrictFile under the policy: %v", err)
	}
	out, err := exec.Command("icacls", p).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v: %s", p, err, out)
	}
	var admins, service bool
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, ":(") {
			continue
		}
		low := strings.ToLower(l)
		if strings.Contains(l, "S-1-5-32-544") || strings.Contains(low, `\administrators:`) {
			admins = true
		}
		if strings.Contains(l, sid.String()) || strings.Contains(low, strings.ToLower(name)+":") {
			service = true
		}
		for _, forbidden := range []string{`\users:`, `\everyone:`, `\authenticated users:`, "everyone:"} {
			if strings.Contains(low, forbidden) {
				t.Errorf("policy ACL still grants %s: %s", forbidden, strings.TrimSpace(l))
			}
		}
	}
	if !admins || !service {
		t.Fatalf("want an Administrators ACE (%v) and a service ACE (%v); icacls: %q", admins, service, out)
	}
}

// aceNamesUser reports whether an icacls ACE line names u. icacls prints the account name, which for
// a well-known account (a CI runner under NT AUTHORITY\SYSTEM) need not equal user.Current().Username,
// so the short name after the backslash is matched too.
func aceNamesUser(line string, u *user.User) bool {
	short := u.Username[strings.LastIndex(u.Username, `\`)+1:]
	return strings.Contains(line, u.Username) || strings.Contains(line, u.Uid) || strings.Contains(line, `\`+short+":")
}
