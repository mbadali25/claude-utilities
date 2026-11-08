package credfile

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// A service SID has the S-1-5-80- prefix. These are literals: the argument list is the part
// of the service path that can be proven without creating a service, and it is the part a
// regression would break.
const (
	testOwnerSID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	testAdminSID = "S-1-5-32-544"
	testSvcSID   = "S-1-5-80-4121816810-2498373899-860449367-3390541248-1734453744"
)

// usePolicy sets the process ACL policy for one test and restores the owner-only default
// afterwards. The policy is package-level, and TestOwnerOnlyACL asserts a single ACE, so a
// policy left set would fail a later test instead of this one.
func usePolicy(t *testing.T, sids ...string) {
	t.Helper()
	SetACLPolicy(sids...)
	t.Cleanup(func() { SetACLPolicy() })
}

func TestDefaultPolicyIsOwnerOnly(t *testing.T) {
	if got := aclPolicy(); len(got) != 0 {
		t.Fatalf("default policy: want empty (owner-only), got %v", got)
	}
	want := []string{`C:\d\vault.bin`, "/inheritance:r", "/grant:r", "*" + testOwnerSID + ":F"}
	if got := grantArgs(`C:\d\vault.bin`, testOwnerSID, false, aclPolicy()); !reflect.DeepEqual(got, want) {
		t.Fatalf("grant args under the default policy:\n got %q\nwant %q", got, want)
	}
}

func TestSetACLPolicyIsIdempotentAndCopies(t *testing.T) {
	in := []string{testAdminSID}
	usePolicy(t, in...)
	in[0] = "S-1-1-0" // the caller's slice must not be the policy
	if got := aclPolicy(); len(got) != 1 || got[0] != testAdminSID {
		t.Fatalf("policy after the caller mutated its own slice: %v", got)
	}
	out := aclPolicy()
	out[0] = "S-1-1-0" // the returned slice must be a copy
	if got := aclPolicy(); len(got) != 1 || got[0] != testAdminSID {
		t.Fatalf("policy after mutating a returned copy: %v", got)
	}
	SetACLPolicy(testAdminSID)
	if got := aclPolicy(); len(got) != 1 || got[0] != testAdminSID {
		t.Fatalf("policy after setting the same value twice: %v", got)
	}
	SetACLPolicy()
	if got := aclPolicy(); len(got) != 0 {
		t.Fatalf("policy after SetACLPolicy() with no argument: want empty, got %v", got)
	}
}

func TestGrantArgsIncludeOwnerThenEveryPolicySID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dir    bool
		policy []string
		want   []string
	}{
		{
			name:   "file: owner, then Administrators, then the service SID",
			policy: []string{testAdminSID, testSvcSID},
			want: []string{`C:\d\vault.bin`, "/inheritance:r", "/grant:r",
				"*" + testOwnerSID + ":F", "*" + testAdminSID + ":F", "*" + testSvcSID + ":F"},
		},
		{
			name:   "dir: every principal inheritable",
			dir:    true,
			policy: []string{testAdminSID, testSvcSID},
			want: []string{`C:\d\vault.bin`, "/inheritance:r", "/grant:r",
				"*" + testOwnerSID + ":(OI)(CI)F", "*" + testAdminSID + ":(OI)(CI)F", "*" + testSvcSID + ":(OI)(CI)F"},
		},
		{
			name:   "the owner repeated in the policy is granted once",
			policy: []string{testAdminSID, testOwnerSID},
			want: []string{`C:\d\vault.bin`, "/inheritance:r", "/grant:r",
				"*" + testOwnerSID + ":F", "*" + testAdminSID + ":F"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := grantArgs(`C:\d\vault.bin`, testOwnerSID, tc.dir, tc.policy)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("grant args:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestGrantArgsAlwaysKeepInheritanceR(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dir    bool
		policy []string
	}{
		{name: "file, owner only"},
		{name: "dir, owner only", dir: true},
		{name: "file, with policy", policy: []string{testAdminSID, testSvcSID}},
		{name: "dir, with policy", dir: true, policy: []string{testAdminSID, testSvcSID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := grantArgs(`C:\d`, testOwnerSID, tc.dir, tc.policy)
			if len(args) < 4 || args[1] != "/inheritance:r" {
				t.Fatalf("want /inheritance:r as the first option, got %q", args)
			}
			grants := 0
			for _, a := range args {
				if a == "/grant:r" {
					grants++
				}
			}
			if grants != 1 {
				// One /grant:r with several terms, never one call per SID: each icacls
				// invocation rewrites the DACL, and a failure between two of them would
				// leave a file granting nobody.
				t.Fatalf("want exactly one /grant:r, got %d in %q", grants, args)
			}
		})
	}
}

func TestGrantArgsIncludeAWellFormedServiceSID(t *testing.T) {
	want := "*" + testSvcSID + ":(OI)(CI)F"
	for _, entry := range []string{testSvcSID, "*" + testSvcSID, " " + testSvcSID + " "} {
		args := grantArgs(`C:\d`, testOwnerSID, true, []string{testAdminSID, entry})
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
			if strings.HasPrefix(a, "**") {
				t.Fatalf("policy entry %q produced a doubled SID prefix: %q", entry, a)
			}
		}
		if !found {
			t.Fatalf("policy entry %q: want a %q term, got %q", entry, want, args)
		}
	}
}

// Review Focus 2: icacls takes the path as an argument and a long one has to be handed over
// in extended-length form, so a path over MAX_PATH or with non-ASCII segments must either be
// restricted or report an error — never be left unrestricted with a nil error.
func TestRestrictFileAcceptsNonASCIIAndLongPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("ACLs are a Windows concept; Unix modes are set directly")
	}
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
	p := filepath.Join(dir, "ü日.json")
	if err := os.WriteFile(p, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := RestrictFile(p); err != nil {
		t.Fatalf("RestrictFile on a %d-char path: %v", len(p), err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != `{"x":1}` {
		t.Fatalf("file no longer opens after RestrictFile: %q, %v", b, err)
	}
}
