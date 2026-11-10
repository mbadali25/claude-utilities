package service

import (
	"errors"
	"fmt"
)

const (
	// WindowsServiceName is the SCM service name. It is also what makes the virtual account's name:
	// a virtual account is `NT SERVICE\<SERVICENAME>`, so this constant and WindowsServiceAccount
	// below cannot be changed independently.
	WindowsServiceName = "ClaudeSwapServer"

	// WindowsServiceAccount is the account the service runs as (Decision 2): the virtual account,
	// which is automatically managed and has no password to expire. Never LocalSystem. The stated
	// fallback, if the virtual account turns out to have no loadable profile for `--tunnels`'
	// ssh.exe, is `NT AUTHORITY\LocalService`.
	WindowsServiceAccount = `NT SERVICE\` + WindowsServiceName

	// AdministratorsAccount is the icacls form of the second principal on the data dir. icacls grant
	// terms built by install.IcaclsLockdownArgs carry no `*` prefix, so they take account NAMES;
	// credfile.SetACLPolicy takes SIDs. Both representations are deliberate and both are pinned by
	// tests, because crossing them is a silent failure: icacls would read `*NT SERVICE\X:F` as one
	// malformed term and leave the file with whatever the preceding removal left behind.
	AdministratorsAccount = `BUILTIN\Administrators`

	// AdministratorsSID is `BUILTIN\Administrators` in the form credfile.SetACLPolicy accepts. It is
	// well known and identical on every Windows install, so it needs no lookup and cannot fail to
	// resolve - which is why the Administrators half of the policy is never the half that refuses.
	AdministratorsSID = "S-1-5-32-544"

	// EventSourceName is the Application event-log source `service install` registers and
	// `service uninstall` removes.
	EventSourceName = WindowsServiceName
)

// ACLPolicyUnresolvedReason is the `reason` token logged with the G17 refusal. It is a plain token
// so it can go in a marker and in a logx line unchanged.
const ACLPolicyUnresolvedReason = "acl-policy-unresolved"

// NotRegisteredHint is what a command prints when no service is registered: the policy is
// Administrators-only, which is correct for a console install, and the command that makes it the
// full policy is named rather than implied.
const NotRegisteredHint = "service not registered: run `server service install`, which re-grants the data dir"

// ErrACLPolicyUnresolved is the G17 refusal (approved by Matthew, 2026-11-07): when a service IS
// registered and its SID will not resolve, the answer is to write nothing, not to apply a narrower
// policy.
//
// Why refusing is the safe answer and narrowing is not. Administrators-only is right when no
// service is registered (a console install before `service install` has run) and WRONG when one is
// registered and the lookup merely failed: applying it re-ACLs the data dir without the service
// SID, and the service then cannot read vault.bin, admin-password.json or tls/. That is the same
// outcome as the restrictACL bug slice 2 was written to fix, arriving through the fallback instead
// of the default - and it arrives silently, because every write succeeds and only the next service
// start fails.
//
// A host where the SCM query itself fails takes the same refusal: a process that cannot tell
// whether a service is registered cannot tell which SIDs must keep access either.
var ErrACLPolicyUnresolved = errors.New("the data-dir ACL policy is unresolved: a " + WindowsServiceName +
	" service is registered but its SID did not resolve, so nothing was written " +
	"(re-run `server service install`, which re-grants the data dir)")

// The two platform seams ACLPolicy reads. They are variables so the policy's rules are tested
// without an SCM on any OS, and so no test on a developer's machine depends on what that machine
// happens to have registered.
// aclSupported is false on every OS that has no SID-based ACL, where the whole policy is empty.
var (
	aclSupported      = platformACLSupported
	serviceRegistered = platformServiceRegistered
	lookupServiceSID  = platformLookupServiceSID
)

// ACLPolicy is the set of SIDs that keep full control, alongside the owner, on every file and
// directory the server restricts (Decision 11, and the spec's "Data dir ACL under a service").
// Every server entry point hands it to credfile.SetACLPolicy before its first write.
//
// The answers, in full:
//   - Windows, a service registered and its SID resolved: Administrators plus the service SID.
//   - Windows, no service registered: Administrators alone, and the caller prints
//     NotRegisteredHint. ACLPolicyNamesTheService reports which of the two this is.
//   - Windows, registered but unresolvable, or an unreachable SCM: no policy and
//     ErrACLPolicyUnresolved. The caller refuses with exit 2 and writes nothing (G17).
//   - Anything but Windows: empty and no error. ACLs are a Windows concept; credfile's unix
//     restrictACL sets 0600/0700 modes directly and ignores the policy.
//
// Administrators is first in the slice so the order is stable for a golden test and for a log line.
func ACLPolicy() ([]string, error) {
	if !aclSupported {
		return nil, nil
	}
	registered, err := serviceRegistered()
	if err != nil {
		return nil, fmt.Errorf("service: %w: %v", ErrACLPolicyUnresolved, err)
	}
	if !registered {
		return []string{AdministratorsSID}, nil
	}
	sid, err := lookupServiceSID()
	if err != nil {
		return nil, fmt.Errorf("service: %w: %v", ErrACLPolicyUnresolved, err)
	}
	if sid == "" {
		return nil, fmt.Errorf("service: %w: the lookup returned no SID", ErrACLPolicyUnresolved)
	}
	return []string{AdministratorsSID, sid}, nil
}

// ACLPolicyNamesTheService reports whether a policy carries the service's own SID. It is the
// caller's way to tell "Administrators only because no service is registered" (print the hint)
// from "Administrators plus the service" (say nothing) without a second SCM query, and it is false
// for the empty policy every non-Windows build gets.
func ACLPolicyNamesTheService(policy []string) bool {
	for _, s := range policy {
		if s != AdministratorsSID && s != "" {
			return true
		}
	}
	return false
}
