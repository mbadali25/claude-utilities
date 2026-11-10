package service

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"claude-utilities/internal/credfile"
)

// stubPolicy replaces the two platform seams ACLPolicy reads. Every case below is therefore driven
// from the test and not from whatever the host this runs on happens to have registered: the SCM is
// never opened and `NT SERVICE\ClaudeSwapServer` is never looked up.
func stubPolicy(t *testing.T, registered bool, regErr error, sid string, sidErr error) {
	t.Helper()
	origSup, origReg, origSID := aclSupported, serviceRegistered, lookupServiceSID
	t.Cleanup(func() { aclSupported, serviceRegistered, lookupServiceSID = origSup, origReg, origSID })
	// The rules are the same wherever they run, so the Windows-only platform switch is stubbed too:
	// every case below is driven from the test on every OS the gate builds for.
	aclSupported = true
	serviceRegistered = func() (bool, error) { return registered, regErr }
	lookupServiceSID = func() (string, error) { return sid, sidErr }
}

// The fixture SID stands in for whatever `NT SERVICE\ClaudeSwapServer` resolves to on a host. It is
// in SID form because that is the only form credfile.SetACLPolicy accepts.
const fixtureServiceSID = "S-1-5-80-1234567890-123456789-1234567890-123456789-1234567890"

// TestServiceACLPolicyAlwaysIncludesAdministrators: Decision 11. Administrators is on the list in
// both directions - with a service registered and without one - because losing it is how an
// elevated `vault rotate` stops being able to read the file it just wrote.
func TestServiceACLPolicyAlwaysIncludesAdministrators(t *testing.T) {
	for _, registered := range []bool{true, false} {
		stubPolicy(t, registered, nil, fixtureServiceSID, nil)
		got, err := ACLPolicy()
		if err != nil {
			t.Fatalf("registered=%v: ACLPolicy: %v", registered, err)
		}
		if len(got) == 0 || got[0] != AdministratorsSID {
			t.Fatalf("registered=%v: policy %v does not start with the Administrators SID %s",
				registered, got, AdministratorsSID)
		}
	}
}

// TestServiceACLPolicyAddsTheServiceSIDWhenRegistered: the service's own SID has to be on the list,
// or the first save under the service account leaves a vault only the service can read and an
// elevated save leaves one only an administrator can read.
func TestServiceACLPolicyAddsTheServiceSIDWhenRegistered(t *testing.T) {
	stubPolicy(t, true, nil, fixtureServiceSID, nil)
	got, err := ACLPolicy()
	if err != nil {
		t.Fatalf("ACLPolicy: %v", err)
	}
	want := []string{AdministratorsSID, fixtureServiceSID}
	if len(got) != len(want) {
		t.Fatalf("policy %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("policy %v, want %v", got, want)
		}
	}
	if !ACLPolicyNamesTheService(got) {
		t.Fatal("ACLPolicyNamesTheService is false for a policy that holds the service SID")
	}
}

// TestServiceACLPolicyIsAdministratorsOnlyWhenNotRegistered: an `init` or `migrate` run before
// `service install` is the one case where Administrators-only is the RIGHT answer, and the caller
// has to be able to tell it apart from the registered case so it can print the hint.
func TestServiceACLPolicyIsAdministratorsOnlyWhenNotRegistered(t *testing.T) {
	stubPolicy(t, false, nil, "", errors.New("no such account"))
	got, err := ACLPolicy()
	if err != nil {
		t.Fatalf("ACLPolicy: %v", err)
	}
	if len(got) != 1 || got[0] != AdministratorsSID {
		t.Fatalf("policy %v, want the Administrators SID alone", got)
	}
	if ACLPolicyNamesTheService(got) {
		t.Fatal("ACLPolicyNamesTheService is true for an Administrators-only policy")
	}
	if !strings.Contains(NotRegisteredHint, "server service install") {
		t.Fatalf("the hint %q does not name the command that fixes it", NotRegisteredHint)
	}
}

// TestServiceACLPolicyNarrowsWhenRegisteredButTheSIDWillNotResolve is G17 as decided by Matthew on
// 2026-11-10: NARROW, never refuse. The policy is Administrators alone, returned with an error that
// wraps ErrACLPolicyNarrowed so the caller can log the reason and tell the operator.
func TestServiceACLPolicyNarrowsWhenRegisteredButTheSIDWillNotResolve(t *testing.T) {
	stubPolicy(t, true, nil, "", errors.New("LookupAccountName: mapping between account names and security IDs was not done"))
	got, err := ACLPolicy()
	if !errors.Is(err, ErrACLPolicyNarrowed) {
		t.Fatalf("err %v, want ErrACLPolicyNarrowed", err)
	}
	assertNarrowedToAdministrators(t, got)
	if !strings.Contains(err.Error(), "server service install") {
		t.Fatalf("the error %q does not name the command that fixes it", err)
	}
	if ACLPolicyNarrowedReason != "acl-policy-narrowed" {
		t.Fatalf("the logged reason is %q, want acl-policy-narrowed", ACLPolicyNarrowedReason)
	}
}

// TestServiceACLPolicyNarrowsWhenTheLookupReturnsNoSID: an empty SID with no error is the same
// unresolved case and must not leak an empty principal into the policy.
func TestServiceACLPolicyNarrowsWhenTheLookupReturnsNoSID(t *testing.T) {
	stubPolicy(t, true, nil, "", nil)
	got, err := ACLPolicy()
	if !errors.Is(err, ErrACLPolicyNarrowed) {
		t.Fatalf("err %v, want ErrACLPolicyNarrowed", err)
	}
	assertNarrowedToAdministrators(t, got)
}

// TestServiceACLPolicyNarrowsWhenTheSCMCannotBeReached: a host where the SCM query itself fails
// cannot answer "is a service registered", so it takes the same narrowing as G17.
func TestServiceACLPolicyNarrowsWhenTheSCMCannotBeReached(t *testing.T) {
	stubPolicy(t, false, errors.New("OpenSCManager: access is denied"), fixtureServiceSID, nil)
	got, err := ACLPolicy()
	if !errors.Is(err, ErrACLPolicyNarrowed) {
		t.Fatalf("err %v, want ErrACLPolicyNarrowed", err)
	}
	assertNarrowedToAdministrators(t, got)
}

// assertNarrowedToAdministrators pins that narrowing never widens: the policy is exactly the
// Administrators SID, so it cannot hold Everyone (S-1-1-0), Users (S-1-5-32-545) or the service SID.
func assertNarrowedToAdministrators(t *testing.T, got []string) {
	t.Helper()
	if len(got) != 1 || got[0] != AdministratorsSID {
		t.Fatalf("policy %v, want the Administrators SID alone", got)
	}
	if ACLPolicyNamesTheService(got) {
		t.Fatal("a narrowed policy claims to name the service")
	}
}

// TestServiceACLPolicyIsWhatCredfileAccepts is the mutation check on the representation. icacls
// takes `*<SID>:F` grant terms, so an account name on this list ("NT SERVICE\\ClaudeSwapServer")
// would be handed over as one malformed term and the whole grant would fail, leaving the file with
// whatever the preceding removal left behind. SetACLPolicy is the thing that refuses it, so the
// policy is fed to the real function rather than to a regexp of this test's own.
func TestServiceACLPolicyIsWhatCredfileAccepts(t *testing.T) {
	t.Cleanup(func() { _ = credfile.SetACLPolicy() })
	stubPolicy(t, true, nil, fixtureServiceSID, nil)
	got, err := ACLPolicy()
	if err != nil {
		t.Fatalf("ACLPolicy: %v", err)
	}
	if err := credfile.SetACLPolicy(got...); err != nil {
		t.Fatalf("credfile refused the policy %v: %v", got, err)
	}
	// And the check bites: the account name form is refused, which is why ACLPolicy resolves it.
	if err := credfile.SetACLPolicy(AdministratorsSID, WindowsServiceAccount); err == nil {
		t.Fatalf("credfile accepted the account name %q; the SID resolution would then be optional",
			WindowsServiceAccount)
	}
}

// TestServiceACLPolicyIsEmptyOffWindows exercises the real platform seams, not the stubs: off
// Windows there are no SIDs and no ACLs (credfile's unix restrictACL sets 0600/0700 modes and
// ignores the policy), so the policy is empty and nothing is refused.
func TestServiceACLPolicyIsEmptyOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this is the other build's behaviour")
	}
	got, err := ACLPolicy()
	if err != nil {
		t.Fatalf("ACLPolicy off windows: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("policy %v off windows, want empty", got)
	}
	if ACLPolicyNamesTheService(got) {
		t.Fatal("ACLPolicyNamesTheService is true for an empty policy")
	}
}

// TestWindowsServiceNamesAgree: the virtual account is named NT SERVICE\<SERVICENAME>, so the two
// constants cannot drift apart - a mismatch would register one service and grant another.
func TestWindowsServiceNamesAgree(t *testing.T) {
	if want := `NT SERVICE\` + WindowsServiceName; WindowsServiceAccount != want {
		t.Fatalf("the service account is %q, want %q", WindowsServiceAccount, want)
	}
	if strings.EqualFold(WindowsServiceAccount, `NT AUTHORITY\SYSTEM`) ||
		strings.Contains(strings.ToLower(WindowsServiceAccount), "localsystem") {
		t.Fatalf("the service account is %q: LocalSystem is never the account (Decision 2)", WindowsServiceAccount)
	}
}
