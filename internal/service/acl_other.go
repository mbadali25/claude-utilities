//go:build !windows

package service

// The ACL policy's platform half off Windows. There is no SCM to ask and no SID to grant: a unix
// host restricts files with 0600/0700 modes, which credfile does directly, so the policy is empty
// and ACLPolicy never refuses.
//
// "Not registered" is the definitive answer here rather than an error, because an error would take
// the G17 refusal path and stop every server command on Linux from writing anything at all. The
// Linux side of "is a unit registered, and with which data dir" is the systemd half, which lands
// with the unit renderer in slice 4c.

// platformACLSupported is false: there is no SID-based ACL on this OS.
const platformACLSupported = false

// platformServiceRegistered reports that nothing is registered, with no error.
func platformServiceRegistered() (bool, error) { return false, nil }

// platformLookupServiceSID has no answer off Windows and is never reached: ACLPolicy only calls it
// when platformServiceRegistered said yes, which this build never does.
func platformLookupServiceSID() (string, error) { return "", nil }
