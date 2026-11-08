//go:build !windows

package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The non-Windows half of the dpapi slot. It is its own file, and not a `runtime.GOOS` branch
// inside the Windows test, because this is the one assertion in the group that runs on the Linux
// half of the gate: the Windows file is behind `//go:build windows` and never compiles there.

func TestDPAPIOpenerIsNilOnNonWindows(t *testing.T) {
	// nil, not an opener that errors. HostKeys builds its try order by skipping nil, so a non-nil
	// opener here would put a slot type this host can never satisfy into the order, and the open
	// flow would report "dpapi" among the types it tried on a machine with no DPAPI at all.
	for _, scope := range []string{dpapiScopeMachine, "user", "", "made-up"} {
		if op := dpapiOpener(scope); op != nil {
			t.Fatalf("dpapiOpener(%q) = %#v, want nil off Windows", scope, op)
		}
	}
}

func TestDPAPIWrapAndUnwrapAreUnsupportedOffWindows(t *testing.T) {
	// A caller that reaches these off Windows has a bug, and the error has to say so plainly: a
	// generic failure here would read to an operator as "the key is wrong", which on a Linux host
	// would send them looking for a credential that was never meant to exist.
	blob, err := dpapiWrap(bytes.Repeat([]byte{0xd4}, keyLen), []byte("entropy"))
	if !errors.Is(err, errDPAPIUnsupported) {
		t.Fatalf("dpapiWrap err = %v, want errDPAPIUnsupported", err)
	}
	if blob != nil {
		t.Fatalf("dpapiWrap returned %d bytes off Windows", len(blob))
	}
	dek, err := dpapiUnwrap([]byte("blob"), []byte("entropy"))
	if !errors.Is(err, errDPAPIUnsupported) {
		t.Fatalf("dpapiUnwrap err = %v, want errDPAPIUnsupported", err)
	}
	if dek != nil {
		t.Fatalf("dpapiUnwrap returned %d bytes off Windows", len(dek))
	}
	// Not ErrBadKey: the next slot's turn is the answer to a key that does not fit, and this is a
	// platform that has no such key at all.
	if errors.Is(err, ErrBadKey) {
		t.Fatalf("unsupported was reported as a bad key: %v", err)
	}
	if !strings.Contains(err.Error(), "windows") {
		t.Fatalf("error does not say which platform it needs: %v", err)
	}
}
