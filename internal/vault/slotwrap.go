package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// This file holds the slot wrap: the byte string every slot type binds, the HKDF derivation that
// turns a slot's key-encryption key into that slot's wrap key, and the AES-256-GCM seal of the
// data encryption key under both. It opens no file and reads no key material from the host - the
// three openers that find a KEK are the files beside this one - and nothing here writes a v2 file.
//
// Two rules carry the whole design and are worth stating where they are implemented:
//
//  1. The wrap key is NEVER the KEK. Every symmetric slot derives a 32-byte wrap key with
//     HKDF-SHA256 from the KEK, salted with the generation's dek.id and with the slot's own AAD in
//     the info. So the same KEK added to two slots, or a passphrase reused across two files, still
//     produces distinct wrap keys, and a rotation to a new dek.id produces distinct keys again.
//  2. Every wrap draws a FRESH 96-bit nonce from randRead. No nonce is copied from a previous
//     header, shared between slots or derived from a counter. GCM with a repeated nonce under the
//     same key leaks the key stream and, worse, the authentication key; with 32-byte plaintexts
//     that is the whole DEK.

// slotWrapInfo prefixes the HKDF info. It names the purpose and the format version, so a byte
// string from some other use of the same KEK cannot collide with a slot wrap. It is part of the
// format: changing it makes every existing slot unopenable.
const slotWrapInfo = "claude-swap/slot-wrap/v2"

// dpapiScopeMachine is the only `scope` a dpapi slot may carry in a file this binary writes or
// opens (Decision 1). It is a format constant, which is why it is here rather than in either half
// of the build: both halves name it, and so do both halves of the test suite. `"scope":"user"` is
// reserved by the format for a later version and is refused today.
const dpapiScopeMachine = "machine"

// aadFixedLen is the AAD's length up to and including the slot type's length prefix: the 4-byte
// magic, the dek.id and its prefix, the slot.id and its prefix, then one byte of type length. The
// type itself follows and is at least one byte.
const aadFixedLen = 4 + 1 + dekIDLen + 1 + slotIDLen + 1

// slotAAD builds the byte string that binds a slot to its file, its DEK generation, its slot id and
// its type. Both symmetric slot types use it as the GCM additional data, and the dpapi slot uses
// the same bytes as the CryptProtectData entropy, so there is one definition and one layout:
//
//	magic(4) || uint8(len(dekID)) || dekID || uint8(len(slotID)) || slotID || uint8(len(type)) || type
//
// For the format's lengths that is the spec's `magic(4) || 0x10 || dek.id(16) || 0x08 || slot.id(8)`.
// The ids are the DECODED bytes, never their base64 spelling: the encoding is a property of the
// file, and binding the text would make a slot's AAD depend on which decoder wrote it.
//
// Every variable field carries a one-byte length prefix in front of it, which is what makes the
// byte string unambiguous. Without them a header could move a byte from the end of dek.id to the
// start of slot.id and produce the same AAD, which is exactly the slot-moving attack the AAD exists
// to stop.
//
// It panics on a field it cannot length-prefix. That is unreachable from any parsed header -
// parseHeader decodes both ids to their exact lengths and parseSlot bounds the type at 255 printable
// ASCII bytes - and the alternative is worse: an error return would be ignored at some call site, and
// a silent truncation of a length prefix would be a format change that still round-trips inside one
// binary while binding something other than what the format says.
func slotAAD(magicStr string, dekID, slotID []byte, slotType string) []byte {
	if len(magicStr) > 255 {
		panic("vault: slotAAD: the magic is longer than one length prefix can carry")
	}
	out := make([]byte, 0, len(magicStr)+3+len(dekID)+len(slotID)+len(slotType))
	out = append(out, magicStr...)
	out = append(out, lenPrefix(len(dekID)))
	out = append(out, dekID...)
	out = append(out, lenPrefix(len(slotID)))
	out = append(out, slotID...)
	out = append(out, lenPrefix(len(slotType)))
	return append(out, slotType...)
}

// lenPrefix is one variable field's one-byte length prefix. The bound is checked here, immediately
// above the conversion, so there is one place the AAD's "every field fits in a byte" invariant
// lives. See slotAAD on why this is a panic rather than an error.
func lenPrefix(n int) byte {
	if n < 0 || n > 255 {
		panic("vault: slotAAD: a field is longer than one length prefix can carry")
	}
	return byte(n)
}

// dekIDFromAAD returns the dek.id carried in an AAD built by slotAAD, which is the HKDF salt.
//
// The seal and the open take the salt out of the AAD rather than as a second parameter on purpose:
// two parameters that must agree are two parameters that can disagree, and a wrap derived under one
// generation's salt while binding another's AAD would be a slot that opens and binds nothing. One
// input, so there is nothing to keep in step.
//
// The shape is checked strictly - the prefixes must be the format's 16 and 8, the type must be
// present and must run to the end - because this is reachable from a fuzz target with no parse in
// front of it, and because an AAD of any other shape did not come from slotAAD.
func dekIDFromAAD(aad []byte) ([]byte, error) {
	if len(aad) < aadFixedLen+1 {
		return nil, fmt.Errorf("%w: slot aad is %d bytes, want at least %d", errCorrupt, len(aad), aadFixedLen+1)
	}
	if aad[4] != dekIDLen {
		return nil, fmt.Errorf("%w: slot aad dek.id prefix is %d, want %d", errCorrupt, aad[4], dekIDLen)
	}
	if aad[5+dekIDLen] != slotIDLen {
		return nil, fmt.Errorf("%w: slot aad slot.id prefix is %d, want %d", errCorrupt, aad[5+dekIDLen], slotIDLen)
	}
	// The type's length prefix must account for exactly the rest of the byte string. A prefix that
	// claimed less would leave trailing bytes nothing binds; one that claimed more would describe
	// bytes that are not there.
	if int(aad[aadFixedLen-1]) != len(aad)-aadFixedLen {
		return nil, fmt.Errorf("%w: slot aad type prefix is %d, want %d", errCorrupt, aad[aadFixedLen-1], len(aad)-aadFixedLen)
	}
	return aad[5 : 5+dekIDLen], nil
}

// wrapKey derives one slot's 32-byte wrap key: HKDF-SHA256 with the KEK as the input keying
// material, the generation's dek.id as the salt and slotWrapInfo followed by the slot's AAD as the
// info. L is 32, the AES-256 key length.
//
// The info carries the magic, the dek.id, the slot.id and the type with their length prefixes, so
// the derivation is domain-separated by every one of them. The conversion to string is a byte copy
// and not a text operation: the info holds 0x10, 0x08 and a length byte, and anything that treated
// it as text would corrupt it.
func wrapKey(kek, dekID, aad []byte) ([]byte, error) {
	if len(kek) != keyLen {
		return nil, fmt.Errorf("vault: slot wrap: kek is %d bytes, want %d", len(kek), keyLen)
	}
	if len(dekID) != dekIDLen {
		return nil, fmt.Errorf("%w: dek.id is %d bytes, want %d", errCorrupt, len(dekID), dekIDLen)
	}
	info := make([]byte, 0, len(slotWrapInfo)+len(aad))
	info = append(info, slotWrapInfo...)
	info = append(info, aad...)
	wk, err := hkdf.Key(sha256.New, kek, dekID, string(info), keyLen)
	if err != nil {
		return nil, fmt.Errorf("vault: slot wrap: hkdf: %w", err)
	}
	return wk, nil
}

// sealedWrap is one slot's wrap: its nonce and its ciphertext, the two fields a symmetric slot
// stores. Kept as a type so sealWith has one return value to zero its inputs around.
type sealedWrap struct {
	nonce []byte
	ct    []byte
}

// sealWith seals plain under an already-derived wrap key and a fresh nonce. It exists as its own
// function because sealSlot derives the key and this does the AEAD, and because a test needs a way
// to produce a wrap whose plaintext is not 32 bytes - something sealSlot refuses to build and
// openSlot must still refuse to believe.
func sealWith(wk, plain, aad []byte) (sealedWrap, error) {
	aead, err := wrapAEAD(wk)
	if err != nil {
		return sealedWrap{}, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := randRead(nonce); err != nil {
		return sealedWrap{}, fmt.Errorf("vault: slot nonce: %w", err)
	}
	return sealedWrap{nonce: nonce, ct: aead.Seal(nil, nonce, plain, aad)}, nil
}

// sealSlot wraps the DEK for one slot: derive the slot's wrap key from its KEK, draw a fresh 96-bit
// nonce, and seal the DEK under the slot's AAD. It returns the two fields the slot stores.
//
// The derived wrap key is zeroed before returning. The KEK and the DEK belong to the caller and are
// left alone; the copy this function made is the one it is responsible for.
func sealSlot(kek []byte, dek []byte, aad []byte) (nonce, ct []byte, err error) {
	if len(dek) != keyLen {
		return nil, nil, fmt.Errorf("vault: slot wrap: dek is %d bytes, want %d", len(dek), keyLen)
	}
	dekID, err := dekIDFromAAD(aad)
	if err != nil {
		return nil, nil, err
	}
	wk, err := wrapKey(kek, dekID, aad)
	if err != nil {
		return nil, nil, err
	}
	defer zero(wk)
	sealed, err := sealWith(wk, dek, aad)
	if err != nil {
		return nil, nil, err
	}
	return sealed.nonce, sealed.ct, nil
}

// openSlot recovers the DEK from one slot's nonce and ciphertext, or returns an error wrapping
// ErrBadKey when this KEK cannot open it and the next slot is the caller's next move.
//
// ErrBadKey and not errCorrupt for a failed GCM open: a slot that does not open under the key this
// host holds is the normal case on a file with several slots, and reporting it as a malformed file
// would send an operator looking for a corrupt disk. A malformed AAD or a key of the wrong length
// is a different thing and keeps its own error.
func openSlot(kek, nonce, ct, aad []byte) ([]byte, error) {
	dekID, err := dekIDFromAAD(aad)
	if err != nil {
		return nil, err
	}
	wk, err := wrapKey(kek, dekID, aad)
	if err != nil {
		return nil, err
	}
	defer zero(wk)
	aead, err := wrapAEAD(wk)
	if err != nil {
		return nil, err
	}
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("%w: slot nonce is %d bytes, want %d", errCorrupt, len(nonce), nonceLen)
	}
	dek, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: slot wrap did not open", ErrBadKey)
	}
	// A wrap that authenticates but carries something other than 32 bytes was written by something
	// that is not this format. Handing those bytes on would build an AES key out of them, so they
	// are zeroed and refused instead.
	if len(dek) != keyLen {
		zero(dek)
		return nil, fmt.Errorf("%w: slot wrap held %d bytes, want a %d-byte key", errCorrupt, len(dek), keyLen)
	}
	return dek, nil
}

// wrapAEAD builds the AES-256-GCM AEAD for one wrap key.
func wrapAEAD(wk []byte) (cipher.AEAD, error) {
	if len(wk) != keyLen {
		return nil, fmt.Errorf("vault: slot wrap: wrap key is %d bytes, want %d", len(wk), keyLen)
	}
	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, fmt.Errorf("vault: slot wrap: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: slot wrap: gcm: %w", err)
	}
	return aead, nil
}

// zero overwrites key material this package is done with. It is not a guarantee - Go may have
// copied the slice during a growth, and nothing stops the OS paging it - which is why it is used
// where it is cheap and honest (a derived key this function allocated) and is not claimed as a
// security control for anything a caller owns.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
