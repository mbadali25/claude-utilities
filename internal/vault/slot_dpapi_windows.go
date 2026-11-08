//go:build windows

package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The dpapi slot opener, Windows half. The slot stores the CryptProtectData output of the raw
// 32-byte DEK; the entropy is the slot's AAD, so a blob cannot be moved between files, between DEK
// generations, between slots or retyped, exactly as the AAD stops that for a symmetric slot.
//
// Machine scope (CRYPTPROTECT_LOCAL_MACHINE) is Decision 1, and the reason is ergonomic rather than
// cryptographic - worth saying plainly here, because the flag reads like a weakening. The slot is
// created by an elevated CLI and consumed by the service account: under user scope those are two
// DPAPI identities, so the service could not unwrap what the CLI wrapped, and fixing that needs
// either an unlock page in the admin UI or running the CLI as the service account. Machine scope
// needs neither. What it admits is that any local account can unwrap the blob - and against the
// assets this design protects (a stolen vault.bin, a stolen .bak, a stolen data dir) a DPAPI blob
// and an ACL'd 32-byte key file are equally closed, because neither is in the copy. The threat
// model already excludes a local administrator. `"scope":"user"` is in the format for the day that
// changes; this binary creates and accepts machine scope only.
//
// UI_FORBIDDEN goes with it: a service has no desktop, and pPromptStruct is NULL because the prompt
// flow is deprecated and is removed in April 2027.

// dpapiScopeMachine is the only `scope` this binary writes or opens. The constant lives in
// slotwrap.go so both halves of the build and both halves of the test suite can name it.

const (
	cryptProtectUIForbidden  = windows.CRYPTPROTECT_UI_FORBIDDEN
	cryptProtectLocalMachine = windows.CRYPTPROTECT_LOCAL_MACHINE
	// dpapiFlags is the one flag set this binary protects with.
	dpapiFlags = cryptProtectLocalMachine | cryptProtectUIForbidden
)

// dpapiDescription is stored inside the blob by CryptProtectData and is not secret. It is a fixed
// string so a blob is identifiable in a hex dump without carrying anything about the host.
const dpapiDescription = "claude-swap vault v2"

// dpapiProtect and dpapiUnprotect are the syscalls, replaceable so a test can inject a failure or a
// plaintext of the wrong length without a real DPAPI call. They are deliberately separate from
// randRead: nothing about DPAPI draws from this package's random seam.
var (
	dpapiProtect   = winCryptProtect
	dpapiUnprotect = winCryptUnprotect
)

// dpapiWrap protects the DEK under the machine key, with the slot's AAD as the entropy.
func dpapiWrap(dek, entropy []byte) ([]byte, error) {
	if len(dek) != keyLen {
		return nil, fmt.Errorf("vault: dpapi slot: dek is %d bytes, want %d", len(dek), keyLen)
	}
	blob, err := dpapiProtect(dek, entropy, dpapiFlags)
	if err != nil {
		return nil, fmt.Errorf("vault: dpapi slot: protect: %w", err)
	}
	return blob, nil
}

// dpapiUnwrap recovers the DEK from a blob, or returns an error wrapping ErrBadKey when this host
// cannot - a blob from another machine, or one whose entropy does not match this slot - so the open
// flow moves to the next slot.
//
// A plaintext of any length but 32 is not a bad key and is not the next slot's turn: DPAPI MACs the
// blob, so an authenticated plaintext of the wrong size came from something that is not this
// format, and handing those bytes on would build an AES key out of them.
func dpapiUnwrap(blob, entropy []byte) ([]byte, error) {
	dek, err := dpapiUnprotect(blob, entropy, dpapiFlags)
	if err != nil {
		return nil, fmt.Errorf("%w: dpapi slot did not unprotect: %w", ErrBadKey, err)
	}
	if len(dek) != keyLen {
		zero(dek)
		return nil, fmt.Errorf("%w: dpapi slot held %d bytes, want a %d-byte key", errCorrupt, len(dek), keyLen)
	}
	return dek, nil
}

// dpapiSlotOpener is the SlotOpener the open flow calls. It holds no state: the scope is checked
// when the opener is built, and the only scope this binary accepts is the machine one.
type dpapiSlotOpener struct{}

// dpapiOpener returns the opener for a dpapi slot of the given scope, or nil when this binary has
// no opener for it. nil is the contract HostKeys relies on - it skips a nil opener - so a scope this
// binary does not know never reaches the try order and is never named among the types tried.
func dpapiOpener(scope string) SlotOpener {
	if scope != dpapiScopeMachine {
		return nil
	}
	return dpapiSlotOpener{}
}

// Type is the only thing about this opener that may be logged or printed.
func (dpapiSlotOpener) Type() string { return slotTypeDPAPI }

// Unwrap decodes the slot's blob and unprotects it under aad as the entropy. The caller built aad
// from the header; this function never rebuilds it, so there is one definition of what a slot is
// bound to.
func (dpapiSlotOpener) Unwrap(slot Slot, aad []byte) ([]byte, error) {
	if slot.Type != slotTypeDPAPI {
		return nil, fmt.Errorf("%w: the dpapi opener was handed a slot of another type", errCorrupt)
	}
	blob, err := base64.StdEncoding.DecodeString(slot.Wrap.Blob)
	if err != nil || len(blob) == 0 {
		return nil, fmt.Errorf("%w: dpapi slot blob is not base64 of at least one byte", errCorrupt)
	}
	return dpapiUnwrap(blob, aad)
}

// winCryptProtect and winCryptUnprotect are the two syscalls. They share blobOf and copyAndFree so
// the keep-alive and the LocalFree cannot drift apart between them: the output blob is memory
// Windows allocated, and not freeing it leaks on every open of every slot for the life of a service
// that may run for months.
func winCryptProtect(data, entropy []byte, flags uint32) ([]byte, error) {
	desc, err := windows.UTF16PtrFromString(dpapiDescription)
	if err != nil {
		return nil, fmt.Errorf("descriptor: %w", err)
	}
	in, ent, err := inputBlobs(data, entropy)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	err = windows.CryptProtectData(&in, desc, &ent, 0, nil, flags, &out)
	// The blobs hold raw pointers into data and entropy, which the garbage collector cannot see.
	runtime.KeepAlive(data)
	runtime.KeepAlive(entropy)
	if err != nil {
		return nil, err
	}
	return copyAndFree(&out)
}

func winCryptUnprotect(blob, entropy []byte, flags uint32) ([]byte, error) {
	in, ent, err := inputBlobs(blob, entropy)
	if err != nil {
		return nil, err
	}
	// The descriptor comes back in a LocalAlloc'd string when asked for; nil means do not ask. It
	// is a constant this package wrote, so there is nothing to learn from it and one less buffer to
	// free.
	var out windows.DataBlob
	err = windows.CryptUnprotectData(&in, nil, &ent, 0, nil, flags, &out)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(entropy)
	if err != nil {
		return nil, err
	}
	return copyAndFree(&out)
}

// maxDPAPIInput bounds what is handed to DPAPI. Everything this package passes is a 32-byte key, a
// ~41-byte AAD or the blob those produce, so the cap is three orders of magnitude of headroom; it
// is here because DataBlob.Size is a uint32 and a length that did not fit would be truncated into a
// shorter buffer than the pointer describes.
const maxDPAPIInput = 1 << 20

// inputBlobs describes the data and the entropy in one call, so the two syscalls cannot differ on
// which of them is bounds-checked.
func inputBlobs(data, entropy []byte) (in, ent windows.DataBlob, err error) {
	if in, err = blobOf(data); err != nil {
		return windows.DataBlob{}, windows.DataBlob{}, err
	}
	if ent, err = blobOf(entropy); err != nil {
		return windows.DataBlob{}, windows.DataBlob{}, err
	}
	return in, ent, nil
}

// blobOf describes a Go slice to the DPAPI API. An empty slice becomes the zero blob, which is how
// "no entropy" is expressed; a blob sealed with entropy therefore does not open with none.
func blobOf(b []byte) (windows.DataBlob, error) {
	if len(b) == 0 {
		return windows.DataBlob{}, nil
	}
	size, err := blobSize(len(b))
	if err != nil {
		return windows.DataBlob{}, err
	}
	return windows.DataBlob{Size: size, Data: &b[0]}, nil
}

// blobSize narrows a Go length to the uint32 DataBlob.Size is, with the bound checked immediately
// above the conversion. A length that did not fit would describe a shorter buffer than the pointer
// beside it, which is a read of someone else's memory rather than a short key.
func blobSize(n int) (uint32, error) {
	if n < 0 || n > maxDPAPIInput {
		return 0, fmt.Errorf("dpapi input is %d bytes, outside [0, %d]", n, maxDPAPIInput)
	}
	return uint32(n), nil
}

// copyAndFree copies an output blob into Go memory, wipes the buffer Windows allocated and frees
// it. The wipe matters on the unprotect path, where that buffer is holding the DEK in plaintext;
// it is harmless on the protect path, where the blob is already ciphertext.
func copyAndFree(b *windows.DataBlob) ([]byte, error) {
	if b.Data == nil {
		return nil, errors.New("dpapi returned no data")
	}
	//nolint:gosec // G103: the pointer and length come from the API that allocated the buffer.
	raw := unsafe.Slice(b.Data, b.Size)
	defer func() {
		zero(raw)
		//nolint:gosec // G103: freeing exactly the pointer DPAPI handed back.
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	}()
	out := make([]byte, b.Size)
	copy(out, raw)
	return out, nil
}
