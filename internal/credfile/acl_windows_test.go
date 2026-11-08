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

// TestPolicyACLGrantsAdministratorsAndServiceSID proves the one part of Decision 11 that a pure
// argument-list test cannot: that icacls accepts a real NT SERVICE\ SID and that a file restricted
// under the policy is reachable by Administrators and by the service as well as the owner.
//
// It is CI-only and needs an elevated token, because obtaining a real service SID means creating a
// service. The throwaway service is named uniquely per run so it can never collide with a real
// service or with a previous crashed run, its delete is registered before any assertion so a failing
// assert still removes it, its binary path is a placeholder and it is never started.
func TestPolicyACLGrantsAdministratorsAndServiceSID(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("CI-only: this test creates and deletes a throwaway Windows service to obtain a real NT SERVICE\\ SID")
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
