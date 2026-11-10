//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/install"
	"claude-utilities/internal/service"
)

// standInServiceAccount is a virtual service account that exists on every Windows install, so this
// test can run the real install grant without registering a service. It stands in for
// `NT SERVICE\ClaudeSwapServer`; icacls treats the two identically, and the leaf name is not
// localized the way `BUILTIN\Administrators` is.
const standInServiceAccount = `NT SERVICE\TrustedInstaller`

// standInServiceSID is the SID of standInServiceAccount, in the form credfile.SetACLPolicy takes.
const standInServiceSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// TestInstallGrantReachesAFileWrittenBeforeTheService pins that a file written before the service
// existed ends up with an ACE for the service after the install steps. The icacls /T grant alone does
// not do it (container-only flags land on directories); restrictExistingFiles does.
//
// The sequence is the one the Windows service-smoke leg runs and the one any real host runs:
// `vault init` and `set-password` write into the data dir while no service is registered, so
// credfile's policy is Administrators-only and every file it writes gets an explicit DACL with
// inheritance removed. `service install` then registers the service and re-grants the data dir
// with IcaclsLockdownArgs(dir, serviceAccount, Administrators), which appends /T for two
// principals.
//
// The service then starts as its virtual account and reads admin-password.json first
// (main.go's adminpw.Open). If the /T grant did not reach that file, the read fails with
// "Access is denied" and the server exits 1 with reason=runtime, which is exactly what CI
// reports on windows-latest while a console run by the file's owner succeeds.
func TestInstallGrantReachesAFileWrittenBeforeTheService(t *testing.T) {
	dir := t.TempDir()

	// What the process has before any service is registered: Administrators plus the owner.
	if err := credfile.SetACLPolicy(service.AdministratorsSID); err != nil {
		t.Fatalf("SetACLPolicy: %v", err)
	}
	t.Cleanup(func() { _ = credfile.SetACLPolicy() })

	if err := credfile.RestrictDir(dir); err != nil {
		t.Fatalf("RestrictDir: %v", err)
	}
	// adminpw.Save writes the hash and then restricts the file; the name is the real one so a
	// failure reads the way the CI log does.
	pw := filepath.Join(dir, "admin-password.json")
	if err := os.WriteFile(pw, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatalf("write %s: %v", pw, err)
	}
	if err := credfile.RestrictFile(pw); err != nil {
		t.Fatalf("RestrictFile: %v", err)
	}

	// The exact call serviceInstallCmd makes after the registration.
	args := install.IcaclsLockdownArgs(dir, standInServiceAccount, service.AdministratorsAccount)
	if out, err := platformRunICacls(args); err != nil {
		t.Fatalf("icacls %v: %v: %s", args, err, strings.TrimSpace(string(out)))
	}

	// Control: the /T grant alone must NOT have reached the file, or the assertions below would pass
	// with restrictExistingFiles deleted and prove nothing.
	if daclNames(t, pw, "TrustedInstaller") {
		t.Fatalf("the icacls grant already put %s on the pre-existing file, so this test no longer "+
			"demonstrates what restrictExistingFiles is for: %s", standInServiceAccount, dacl(t, pw))
	}

	// reapplyACLPolicy has run by now: the policy names the service SID. The stand-in is the
	// TrustedInstaller SID, which every Windows install has.
	if err := credfile.SetACLPolicy(service.AdministratorsSID, standInServiceSID); err != nil {
		t.Fatalf("SetACLPolicy with the stand-in: %v", err)
	}
	if n, err := restrictExistingFiles(dir); err != nil || n != 1 {
		t.Fatalf("restrictExistingFiles = %d, %v; want 1 file, nil", n, err)
	}

	// The directory is granted - that half has never been in doubt, and asserting it here keeps a
	// failure from being read as "icacls refused the whole command".
	if !daclNames(t, dir, "TrustedInstaller") {
		t.Fatalf("the data dir itself was not granted to %s; icacls refused the grant outright, so this "+
			"test proves nothing about existing files", standInServiceAccount)
	}

	if !daclNames(t, pw, "TrustedInstaller") {
		t.Fatalf("%s is absent from the DACL of a file that already existed when the grant ran.\n"+
			"icacls visits the file under /T but a grant term carrying the container-only flags (OI)(CI) "+
			"lands on directories only, so every file written before `service install` - "+
			"admin-password.json, vault.bin, tunnelkeys.bin - keeps a DACL with no service ACE.\n"+
			"DACL now: %s", standInServiceAccount, dacl(t, pw))
	}
}

// dacl returns `icacls path` output on one line. icacls is the tool the install itself uses, so
// the test reads the ACL back through the same lens that wrote it.
func dacl(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	return strings.Join(strings.Fields(string(out)), " ")
}

// daclNames reports whether an account's leaf name appears in path's DACL. The leaf name is
// matched, not the whole account string, because the authority half is localized on some hosts.
func daclNames(t *testing.T, path, leafName string) bool {
	t.Helper()
	return strings.Contains(dacl(t, path), leafName)
}

// TestRestrictExistingFilesNarrowedPolicyNeverWidens covers G17: when the service SID would not
// resolve the policy is Administrators-only, and the per-file pass must not add the service, Users
// or Everyone to a file.
func TestRestrictExistingFilesNarrowedPolicyNeverWidens(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "vault.bin")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := credfile.SetACLPolicy(service.AdministratorsSID); err != nil {
		t.Fatalf("SetACLPolicy: %v", err)
	}
	t.Cleanup(func() { _ = credfile.SetACLPolicy() })
	if _, err := restrictExistingFiles(dir); err != nil {
		t.Fatalf("restrictExistingFiles: %v", err)
	}
	d := strings.ReplaceAll(dacl(t, f), f, "") // the temp path itself may contain "Users"
	for _, bad := range []string{"TrustedInstaller", "Everyone", "Users", "Authenticated"} {
		// "BUILTIN\Users" must not appear; "Administrators" legitimately contains no such word.
		if strings.Contains(d, bad) {
			t.Fatalf("narrowed policy widened the file with %q: %s", bad, d)
		}
	}
	if !strings.Contains(d, "Administrators") {
		t.Fatalf("Administrators missing from the DACL: %s", d)
	}
}
