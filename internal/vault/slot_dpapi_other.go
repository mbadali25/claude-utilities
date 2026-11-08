//go:build !windows

package vault

import (
	"errors"
	"fmt"
)

// The dpapi slot opener, non-Windows half. DPAPI is a Windows API with no equivalent anywhere else,
// so there is nothing to stub: this file says so, once, in the two ways a caller can find out.
//
// dpapiOpener returns nil, which is the contract HostKeys relies on - it skips a nil opener - so a
// Linux host's try order never contains a dpapi slot and the "no slot could unwrap" error never
// names a type this host could not have satisfied. dpapiWrap and dpapiUnwrap return
// errDPAPIUnsupported, because a caller that reached them off Windows has a bug and must be told
// that rather than handed something that reads like a wrong key.

// errDPAPIUnsupported is what the two functions answer off Windows. Deliberately not ErrBadKey:
// "cannot decrypt (wrong key or tampered file)" on a Linux host would send an operator looking for
// a credential that was never meant to exist there, and the one thing that must not happen is a
// correct key being rotated out of confusion.
var errDPAPIUnsupported = errors.New("vault: dpapi slots need windows")

// dpapiWrap is unreachable off Windows and says so.
func dpapiWrap(_, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: this host cannot create a dpapi slot", errDPAPIUnsupported)
}

// dpapiUnwrap is unreachable off Windows and says so.
func dpapiUnwrap(_, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: this host cannot open a dpapi slot", errDPAPIUnsupported)
}

// dpapiOpener has no opener to offer on this platform, for any scope.
func dpapiOpener(_ string) SlotOpener { return nil }
