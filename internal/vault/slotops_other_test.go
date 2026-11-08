//go:build !windows

package vault

import (
	"bytes"
	"errors"
	"testing"
)

// The non-Windows half of the slot mutators, and it exists for one guard: proveSealers' throwaway
// wrap. It is its own file rather than a runtime.GOOS branch for the same reason
// slot_dpapi_other_test.go is - on Windows a dpapi slot wraps perfectly well, so there is nothing
// to refuse there and the assertion would be vacuous.
//
// The guard it covers is the only one in regenerateLocked that sealerFor alone cannot catch. An
// unreachable kek-file slot is refused by sealerFor (the opener carries the reason) and an unknown
// type is refused before that; a dpapi slot off Windows resolves a sealer happily and only FAILS
// when something asks it to wrap. Without the probe that failure lands after the new data key is
// drawn and after the recovery copy has been re-sealed or deleted, which is a file left half-way
// through a generation change - exactly the state the ordering exists to make impossible.

// TestRegenerateRefusesADPAPISlotBeforeTouchingAnythingOffWindows pins the probe: a dpapi slot on a
// host with no DPAPI is a refusal that names the platform, and the vault and its .bak are both
// byte-identical afterwards.
func TestRegenerateRefusesADPAPISlotBeforeTouchingAnythingOffWindows(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(v *Vault, ks KeySource) error
	}{
		{"rotate", func(v *Vault, ks KeySource) error { return v.Rotate(ks) }},
		// Removing a DIFFERENT slot: the dpapi slot survives and so must be re-wrapped, which is what
		// cannot be done here. (Removing the dpapi slot itself is allowed and is the way out.)
		{"remove-slot", func(v *Vault, ks KeySource) error {
			_, err := v.RemoveSlot(b64([]byte("slot0003")), ks)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := v2VaultAt(t, dir, []v2Spec{
				passSpec("slot0001", addSlotPass),
				// A dpapi slot's blob is never opened on this path - the refusal comes from trying to
				// WRAP - so any base64 the parser accepts stands in for one.
				{raw: `{"id":"` + b64([]byte("slot0002")) + `","type":"dpapi","scope":"machine","created":"` +
					fileCreated + `","wrap":{"blob":"AAEC"}}`},
				kekSpec("slot0003", addSlotKEK()),
			}, "a1")
			writeBak(t, path, []byte(fileDEK), []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
			before, bakBefore := bytesOf(t, path), bytesOf(t, path+bakSuffix)

			v := openV2(t, path, addSlotPass)
			ks := &recordingKeySource{pass: addSlotPass,
				openers: []SlotOpener{kekFileOpenerFor(t, addSlotKEK())}}
			err := tc.call(v, ks)
			if !errors.Is(err, errDPAPIUnsupported) {
				t.Fatalf("%s with a dpapi slot off Windows = %v, want errDPAPIUnsupported", tc.name, err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(b64([]byte("slot0002")))) {
				t.Fatalf("the refusal does not name the slot it cannot wrap: %v", err)
			}
			// Nothing was drawn and nothing was touched: the whole point of proving the sealers before
			// the new generation exists.
			if !bytes.Equal(before, bytesOf(t, path)) {
				t.Fatalf("%s wrote to the vault before refusing", tc.name)
			}
			if !bytes.Equal(bakBefore, bytesOf(t, path+bakSuffix)) {
				t.Fatalf("%s touched the recovery copy before refusing", tc.name)
			}
		})
	}
}
