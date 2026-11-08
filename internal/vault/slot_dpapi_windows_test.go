//go:build windows

package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// Tests for the dpapi slot opener. They run on Windows only, in process, on a throwaway 32-byte
// key: CryptProtectData with CRYPTPROTECT_LOCAL_MACHINE derives from the machine key and persists
// nothing, so nothing here adds to, removes from or reads any credential store. The blob never
// leaves the test's memory and is never written to disk.

// dpapiSlot builds a dpapi slot carrying blob, as the header would store it.
func dpapiSlot(blob []byte) Slot {
	return Slot{
		ID:      base64.StdEncoding.EncodeToString(testSlotID(1)),
		Type:    slotTypeDPAPI,
		Scope:   dpapiScopeMachine,
		Created: "2026-11-08T00:00:00Z",
		Wrap:    WrapInfo{Blob: base64.StdEncoding.EncodeToString(blob)},
	}
}

func dpapiAAD() []byte {
	return slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeDPAPI)
}

// otherFileAAD is the same slot's AAD under the keyring's magic: the blob-moving attack, and the
// one failure shape several tests here need.
func otherFileAAD() []byte {
	return slotAAD(v2KeyringMagic, testDEKID(), testSlotID(1), slotTypeDPAPI)
}

func TestDPAPIWrapUnwrapRoundTrip(t *testing.T) {
	dek, entropy := testDEK(), dpapiAAD()

	blob, err := dpapiWrap(dek, entropy)
	if err != nil {
		t.Fatalf("dpapiWrap: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("dpapiWrap returned an empty blob")
	}
	// The blob must not simply be the key with a header round it. DPAPI encrypts, so the plaintext
	// cannot appear in the output; a binding that silently passed the bytes through would round-trip
	// and protect nothing.
	if bytes.Contains(blob, dek) {
		t.Fatal("the DEK appears verbatim in the DPAPI blob")
	}

	got, err := dpapiUnwrap(blob, entropy)
	if err != nil {
		t.Fatalf("dpapiUnwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round trip returned %x, want %x", got, dek)
	}

	// And through the SlotOpener the open flow actually calls.
	op := dpapiOpener(dpapiScopeMachine)
	if op == nil {
		t.Fatal("dpapiOpener returned nil on Windows")
	}
	if op.Type() != slotTypeDPAPI {
		t.Fatalf("Type() = %q, want %q", op.Type(), slotTypeDPAPI)
	}
	viaOpener, err := op.Unwrap(dpapiSlot(blob), entropy)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(viaOpener, dek) {
		t.Fatalf("Unwrap returned %x, want %x", viaOpener, dek)
	}
}

func TestDPAPIUnwrapWithWrongEntropyFails(t *testing.T) {
	// The entropy is the slot's AAD, so this is the slot-moving attack: a blob lifted from another
	// file, another DEK generation, another slot or a retyped slot must not open. Every case is an
	// error wrapping ErrBadKey - the next slot's turn - and never a panic.
	blob, err := dpapiWrap(testDEK(), dpapiAAD())
	if err != nil {
		t.Fatalf("dpapiWrap: %v", err)
	}
	cases := []struct {
		name    string
		entropy []byte
	}{
		{"the other file's magic", otherFileAAD()},
		{"another dek generation", slotAAD(v2VaultMagic, bytes.Repeat([]byte{0x99}, dekIDLen), testSlotID(1), slotTypeDPAPI)},
		{"another slot", slotAAD(v2VaultMagic, testDEKID(), testSlotID(2), slotTypeDPAPI)},
		{"retyped", slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)},
		{"no entropy at all", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := dpapiUnwrap(blob, c.entropy)
			if !errors.Is(err, ErrBadKey) {
				t.Fatalf("err = %v, want ErrBadKey", err)
			}
			if got != nil {
				t.Fatalf("a failed unwrap returned %d bytes", len(got))
			}
		})
	}
}

func TestDPAPIUnwrapRejectsShortOutput(t *testing.T) {
	// A DPAPI blob is MACed, so a 31-byte plaintext means the blob was written by something that is
	// not this format - or by this binary with a bug. Either way those bytes must never be handed
	// back as a DEK: AES would happily take 31 bytes and build a key nobody chose.
	prev := dpapiUnprotect
	dpapiUnprotect = func(_, _ []byte, _ uint32) ([]byte, error) {
		return bytes.Repeat([]byte{0x5c}, keyLen-1), nil
	}
	t.Cleanup(func() { dpapiUnprotect = prev })

	got, err := dpapiUnwrap([]byte("any blob"), dpapiAAD())
	if err == nil {
		t.Fatalf("dpapiUnwrap accepted %d bytes as a DEK", len(got))
	}
	if got != nil {
		t.Fatalf("a failed unwrap returned %d bytes", len(got))
	}
	if !strings.Contains(err.Error(), strconv.Itoa(keyLen-1)) {
		t.Fatalf("error does not name the length it got: %v", err)
	}
	// Not ErrBadKey: the key was right and the content is wrong, so trying the next slot is not the
	// answer and an operator must not be pushed toward rotating a correct key.
	if errors.Is(err, ErrBadKey) {
		t.Fatalf("a short plaintext was reported as a bad key: %v", err)
	}
}

func TestDPAPIWrapErrorIsReturnedNotSwallowed(t *testing.T) {
	sentinel := errors.New("dpapi is having a day")
	prev := dpapiProtect
	dpapiProtect = func(_, _ []byte, _ uint32) ([]byte, error) { return nil, sentinel }
	t.Cleanup(func() { dpapiProtect = prev })

	blob, err := dpapiWrap(testDEK(), dpapiAAD())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the injected error", err)
	}
	if blob != nil {
		t.Fatalf("a failed wrap returned %d bytes", len(blob))
	}
}

func TestDPAPIWrapRefusesADEKOfTheWrongLength(t *testing.T) {
	if _, err := dpapiWrap(bytes.Repeat([]byte{0x01}, keyLen-1), dpapiAAD()); err == nil {
		t.Fatal("dpapiWrap accepted a 31-byte DEK")
	}
}

func TestDPAPIOpenerUsesTheMachineScopeFlag(t *testing.T) {
	// Machine scope is Decision 1: the slot is created by an elevated CLI and consumed by the
	// service account, which are different DPAPI identities under user scope, so the service could
	// not unwrap what the CLI wrapped. The flag is therefore part of the design, not a detail, and
	// UI_FORBIDDEN goes with it because a service has no desktop to prompt on.
	var sawFlags uint32
	prev := dpapiProtect
	dpapiProtect = func(data, _ []byte, flags uint32) ([]byte, error) {
		sawFlags = flags
		return append([]byte("stub:"), data...), nil
	}
	t.Cleanup(func() { dpapiProtect = prev })

	if _, err := dpapiWrap(testDEK(), dpapiAAD()); err != nil {
		t.Fatalf("dpapiWrap: %v", err)
	}
	if sawFlags&cryptProtectLocalMachine == 0 {
		t.Fatalf("flags = %#x, missing CRYPTPROTECT_LOCAL_MACHINE (%#x)", sawFlags, cryptProtectLocalMachine)
	}
	if sawFlags&cryptProtectUIForbidden == 0 {
		t.Fatalf("flags = %#x, missing CRYPTPROTECT_UI_FORBIDDEN (%#x)", sawFlags, cryptProtectUIForbidden)
	}
}

func TestDPAPIOpenerIsNilForAnUnknownScope(t *testing.T) {
	// nil is how this package says "no usable opener on this host", and it is what HostKeys skips.
	// A scope string this binary does not know must take that path rather than guess a flag.
	for _, scope := range []string{"made-up", ""} {
		if op := dpapiOpener(scope); op != nil {
			t.Fatalf("dpapiOpener(%q) = %#v, want nil", scope, op)
		}
	}
}

func TestDPAPIOpenerRefusesASlotItDoesNotOwn(t *testing.T) {
	op := dpapiOpener(dpapiScopeMachine)
	bad := dpapiSlot([]byte("blob"))
	bad.Type = slotTypeKEKFile
	if _, err := op.Unwrap(bad, dpapiAAD()); err == nil {
		t.Fatal("the dpapi opener unwrapped a kek-file slot")
	}
	// A blob that is not base64, or an empty one, is a malformed file rather than a bad key.
	notB64 := dpapiSlot(nil)
	notB64.Wrap.Blob = "not base64 !!"
	if _, err := op.Unwrap(notB64, dpapiAAD()); err == nil {
		t.Fatal("the dpapi opener accepted a blob that is not base64")
	}
	if _, err := op.Unwrap(dpapiSlot(nil), dpapiAAD()); err == nil {
		t.Fatal("the dpapi opener accepted an empty blob")
	}
}

func TestDPAPIBlobIsNeverLogged(t *testing.T) {
	// The structured line an operator sees carries the slot id and the slot type and nothing else;
	// it is written by the mutator, not by this package, and `slot`/`slottype` reach logx's
	// allowlist in Task 3a.9. What this package can be held to today is its own loggable surface:
	// Type() is a closed-set constant, and no error it returns carries the blob, the DEK or the
	// entropy. An error string is what lands in a log line, a ticket and an operator's terminal, so
	// a %x of the blob in an error message would be the leak with or without the allowlist.
	dek, entropy := testDEK(), dpapiAAD()
	blob, err := dpapiWrap(dek, entropy)
	if err != nil {
		t.Fatalf("dpapiWrap: %v", err)
	}

	op := dpapiOpener(dpapiScopeMachine)
	if op.Type() != slotTypeDPAPI {
		t.Fatalf("Type() = %q: the only loggable fact about this opener must be its kind", op.Type())
	}

	var msgs []string
	collect := func(_ []byte, err error) {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	collect(dpapiUnwrap(blob, otherFileAAD()))
	collect(op.Unwrap(dpapiSlot(blob), otherFileAAD()))
	collect(dpapiWrap(dek[:keyLen-1], entropy))
	bad := dpapiSlot(blob)
	bad.Type = slotTypeKEKFile
	collect(op.Unwrap(bad, entropy))
	if len(msgs) < 4 {
		t.Fatalf("only %d of the four failure paths produced an error", len(msgs))
	}

	secrets := map[string][]byte{
		"the DEK":     dek,
		"the blob":    blob,
		"the entropy": entropy,
		"the slot id": testSlotID(1),
		"the dek.id":  testDEKID(),
	}
	for _, msg := range msgs {
		for name, secret := range secrets {
			for enc, s := range map[string]string{
				"raw":    string(secret),
				"hex":    hex.EncodeToString(secret),
				"base64": base64.StdEncoding.EncodeToString(secret),
			} {
				if strings.Contains(msg, s) {
					t.Fatalf("%s (%s) appears in an error message: %q", name, enc, msg)
				}
			}
		}
	}
}
