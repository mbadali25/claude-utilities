package credfile

import (
	"errors"
	"reflect"
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
	if err := SetACLPolicy(sids...); err != nil {
		t.Fatalf("SetACLPolicy(%q): %v", sids, err)
	}
	t.Cleanup(func() { _ = SetACLPolicy() })
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
	if err := SetACLPolicy(testAdminSID); err != nil {
		t.Fatalf("setting the same value twice: %v", err)
	}
	if got := aclPolicy(); len(got) != 1 || got[0] != testAdminSID {
		t.Fatalf("policy after setting the same value twice: %v", got)
	}
	if err := SetACLPolicy(); err != nil {
		t.Fatalf("SetACLPolicy() with no argument: %v", err)
	}
	if got := aclPolicy(); len(got) != 0 {
		t.Fatalf("policy after SetACLPolicy() with no argument: want empty, got %v", got)
	}
}

// A policy entry is a SID. icacls takes each grant term as *<SID>:<rights>, so an account name
// such as NT SERVICE\ClaudeSwap would be handed over as "*NT SERVICE\ClaudeSwap:F" and the whole
// grant would fail, leaving the file with the ACL the removal left behind.
func TestSetACLPolicyRejectsEntriesThatAreNotSIDs(t *testing.T) {
	usePolicy(t, testAdminSID)
	for _, bad := range []string{
		`NT SERVICE\ClaudeSwap`, // the account name, not its SID
		`*NT SERVICE\ClaudeSwap`,
		`BUILTIN\Administrators`,
		"Administrators",
		"S-1-", // a prefix with no sub-authority
		"S-1",
		"S-1-5-32-544:F",        // a whole icacls term, rights included
		"S-1-5-32-544 S-1-5-18", // two entries in one string
		"S-1-5-32-x",
		"1-5-32-544",
		"../S-1-5-32-544",
	} {
		if err := SetACLPolicy(bad); err == nil {
			t.Fatalf("SetACLPolicy(%q): want an error, got nil (policy now %v)", bad, aclPolicy())
		} else if !strings.Contains(err.Error(), bad) {
			t.Errorf("SetACLPolicy(%q): error does not name the entry: %v", bad, err)
		}
		if got := aclPolicy(); len(got) != 1 || got[0] != testAdminSID {
			t.Fatalf("SetACLPolicy(%q) changed the policy: %v", bad, got)
		}
	}
}

func TestSetACLPolicyAcceptsSIDsWithStarsAndSpaces(t *testing.T) {
	t.Cleanup(func() { _ = SetACLPolicy() })
	for _, in := range []string{
		testSvcSID,
		"*" + testSvcSID,
		"**" + testSvcSID,
		" " + testSvcSID + " ",
		strings.ToLower(testSvcSID),
	} {
		if err := SetACLPolicy(testAdminSID, in); err != nil {
			t.Fatalf("SetACLPolicy(%q): %v", in, err)
		}
		want := []string{testAdminSID, strings.TrimLeft(strings.TrimSpace(in), "*")}
		if got := aclPolicy(); !reflect.DeepEqual(got, want) {
			t.Fatalf("policy for entry %q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// Review item 1: a failed icacls run must carry the tool's own output, or a grant that icacls
// refused leaves nothing to diagnose but "set ACL failed".
func TestICACLSErrorNamesTheStepAndTheToolOutput(t *testing.T) {
	run := errors.New("exit status 2")
	err := icaclsError("set", []byte("  vault.bin: The system cannot find the file specified.  \r\n"), run)
	if !errors.Is(err, run) {
		t.Fatalf("want the run error wrapped, got %v", err)
	}
	for _, want := range []string{"credfile: set ACL failed", "exit status 2", "The system cannot find the file specified."} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
	if s := err.Error(); s != strings.TrimSpace(s) {
		t.Fatalf("icacls output was not trimmed: %q", s)
	}
	if got, want := icaclsError("clear", nil, run).Error(), "credfile: clear ACL failed: exit status 2"; got != want {
		t.Fatalf("empty icacls output:\n got %q\nwant %q", got, want)
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
	for _, entry := range []string{testSvcSID, "*" + testSvcSID, "**" + testSvcSID, " " + testSvcSID + " "} {
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
