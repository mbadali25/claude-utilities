package credfile

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// The ACL policy and the icacls argument list it produces carry no build constraint, so the
// argument list every restricted file in this process depends on is tested on every platform;
// only the part that resolves the owner and runs icacls needs a Windows host.

var (
	aclPolicyMu   sync.RWMutex
	aclPolicySIDs []string
)

// sidPattern matches a SID in its string form: revision 1, then at least one decimal
// sub-authority. Case is ignored because icacls takes either.
var sidPattern = regexp.MustCompile(`^S-1(-[0-9]+)+$`)

// SetACLPolicy names SIDs that keep full control alongside the owner on every file and
// directory this process restricts. It is set once at process start, before the first write,
// and the default is owner-only.
//
// Entries are SIDs only — `S-1-5-32-544`, with an optional leading `*` and surrounding spaces,
// never an account name. icacls takes each grant term as `*<SID>:<rights>`, so `NT SERVICE\X`
// would be handed over as `*NT SERVICE\X:F` and the whole grant would fail, leaving the file
// with whatever the preceding removal left behind. An entry that is not a SID is therefore
// refused here, with the entry named, and the policy is left as it was: the caller resolves the
// name to a SID (windows.LookupSID) and calls again. Blank entries are dropped.
//
// The server calls it with the Administrators SID, plus the service's own SID once the service
// is registered, because otherwise the first save under the service account strips every
// administrator from the data dir and an elevated save strips the service: either way the next
// reader of vault.bin is denied access to a file it owns the only copy of. The agent never
// calls it — a credentials file stays owner-only. Called with no arguments it restores that
// default.
func SetACLPolicy(extraFullControl ...string) error {
	policy := make([]string, 0, len(extraFullControl))
	for _, entry := range extraFullControl {
		s := normalizeSID(entry)
		if s == "" {
			continue
		}
		if !sidPattern.MatchString(strings.ToUpper(s)) {
			return fmt.Errorf(`credfile: ACL policy entry "%s" is not a SID (want S-1-5-32-544 form, not an account name)`, entry)
		}
		policy = append(policy, s)
	}
	aclPolicyMu.Lock()
	defer aclPolicyMu.Unlock()
	aclPolicySIDs = policy
	return nil
}

// normalizeSID strips the surrounding spaces and every leading icacls `*` prefix, so an entry
// already written as `*S-1-...` is accepted as it is and never grows a doubled prefix.
func normalizeSID(entry string) string {
	return strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(entry), "*"))
}

// icaclsError wraps a failed icacls run. The tool's own output is the only account of what it
// refused — a SID it could not map, a path it could not open — so it travels with the error
// instead of being discarded; it names the path icacls was already given and nothing else.
func icaclsError(step string, out []byte, err error) error {
	if s := strings.TrimSpace(string(out)); s != "" {
		return fmt.Errorf("credfile: %s ACL failed: %w: %s", step, err, s)
	}
	return fmt.Errorf("credfile: %s ACL failed: %w", step, err)
}

// aclPolicy returns a copy of the policy: a caller that mutated the slice in place would
// change what every later restriction grants.
func aclPolicy() []string {
	aclPolicyMu.RLock()
	defer aclPolicyMu.RUnlock()
	return slices.Clone(aclPolicySIDs)
}

// grantArgs builds the single icacls /grant:r call that restrictACL issues after the removal:
// the owner first, then every policy SID, each with full control, and /inheritance:r repeated
// so the grant cannot land on a path that re-acquired inherited access between the two calls.
//
// One /grant:r carrying several terms, never one call per SID: each icacls invocation rewrites
// the DACL, so a failure between two of them would leave a file granting nobody. For a
// directory every grant is inheritable, so files created inside start with the same access.
//
// A policy entry already written with the icacls '*' SID prefix is accepted as it is, and a SID
// repeated as both owner and policy entry is granted once: under the service account the
// service SID is also the owner.
func grantArgs(path, ownerSID string, dir bool, policy []string) []string {
	mode := ":F"
	if dir {
		mode = ":(OI)(CI)F"
	}
	args := []string{path, "/inheritance:r", "/grant:r"}
	seen := make(map[string]bool, len(policy)+1)
	for _, sid := range append([]string{ownerSID}, policy...) {
		s := normalizeSID(sid)
		if s == "" || seen[strings.ToUpper(s)] {
			continue
		}
		seen[strings.ToUpper(s)] = true
		args = append(args, "*"+s+mode)
	}
	return args
}
