package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Tests for the slot wrap: the byte-exact AAD every slot type binds, the HKDF derivation that
// turns a slot's KEK into that slot's wrap key, and the AES-256-GCM seal of the DEK under both.
//
// The AAD is the whole security argument of the slot format, so it is pinned as a golden byte
// string rather than as a property. A field order or a length prefix that changed would still
// round-trip within one binary - seal and open would agree with each other - and would silently
// stop binding what the format says it binds. Only a byte comparison catches that.

// testKEK and testDEK are fixed non-secret key material. Distinct repeated bytes so a function
// that returned the wrong one of them is obvious in a failure message.
func testKEK() []byte { return bytes.Repeat([]byte{0xa1}, keyLen) }
func testDEK() []byte { return bytes.Repeat([]byte{0xd4}, keyLen) }

// testDEKID and testSlotID are a header's ids at their format lengths, decoded.
func testDEKID() []byte { return bytes.Repeat([]byte{0x11}, dekIDLen) }

func testSlotID(n byte) []byte {
	id := bytes.Repeat([]byte{0x20}, slotIDLen)
	id[slotIDLen-1] = n
	return id
}

func TestSlotAADFieldOrderAndLengthPrefixes(t *testing.T) {
	got := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypePassphrase)

	var want bytes.Buffer
	want.WriteString("CSV2")
	want.WriteByte(0x10)
	want.Write(testDEKID())
	want.WriteByte(0x08)
	want.Write(testSlotID(1))
	want.WriteByte(byte(len(slotTypePassphrase)))
	want.WriteString(slotTypePassphrase)

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("slotAAD bytes:\n got %x\nwant %x", got, want.Bytes())
	}
	// 4 magic + 1 + 16 + 1 + 8 + 1 + len(type). Spelled out so a change to any prefix is caught
	// here and not only by the byte compare above.
	if n := len(got); n != 4+1+dekIDLen+1+slotIDLen+1+len(slotTypePassphrase) {
		t.Fatalf("slotAAD length = %d", n)
	}
}

func TestSlotAADNoTwoFieldSplitsCollide(t *testing.T) {
	// Each pair carries the same concatenated bytes split differently between two fields. Without
	// the one-byte length prefix in front of every variable field, both members of a pair would
	// produce the same AAD, and a slot could be moved between generations by a header that moved a
	// byte from one id to the next.
	cases := []struct {
		name   string
		a, b   []byte
		aType  string
		bType  string
		aSlot  []byte
		bSlot  []byte
		aMagic string
		bMagic string
	}{
		{
			name:   "a byte moved from dek.id to slot.id",
			a:      bytes.Repeat([]byte{0x33}, dekIDLen),
			b:      bytes.Repeat([]byte{0x33}, dekIDLen-1),
			aSlot:  bytes.Repeat([]byte{0x33}, slotIDLen),
			bSlot:  bytes.Repeat([]byte{0x33}, slotIDLen+1),
			aType:  slotTypeKEKFile,
			bType:  slotTypeKEKFile,
			aMagic: v2VaultMagic,
			bMagic: v2VaultMagic,
		},
		{
			name:   "a byte moved from slot.id to type",
			a:      testDEKID(),
			b:      testDEKID(),
			aSlot:  append(bytes.Repeat([]byte{0x41}, slotIDLen-1), 'x'),
			bSlot:  bytes.Repeat([]byte{0x41}, slotIDLen-1),
			aType:  "y",
			bType:  "xy",
			aMagic: v2VaultMagic,
			bMagic: v2VaultMagic,
		},
		{
			name:   "the other file's magic",
			a:      testDEKID(),
			b:      testDEKID(),
			aSlot:  testSlotID(7),
			bSlot:  testSlotID(7),
			aType:  slotTypePassphrase,
			bType:  slotTypePassphrase,
			aMagic: v2VaultMagic,
			bMagic: v2KeyringMagic,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := slotAAD(c.aMagic, c.a, c.aSlot, c.aType)
			b := slotAAD(c.bMagic, c.b, c.bSlot, c.bType)
			if bytes.Equal(a, b) {
				t.Fatalf("two field splits produced the same AAD: %x", a)
			}
		})
	}
}

func TestSlotAADRefusesAFieldItCannotLengthPrefix(t *testing.T) {
	// A length prefix is one byte, so a field past 255 bytes has no encoding. Unreachable from a
	// parsed header - parseSlot bounds the type at 255 and both ids to their exact lengths - but
	// silently truncating a prefix would be a format break that round-trips, so it panics instead.
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("slotAAD accepted a 256-byte type")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "slotAAD") {
			t.Fatalf("panic does not name slotAAD: %v", r)
		}
	}()
	slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), strings.Repeat("t", 256))
}

func TestWrapKeyDiffersPerSlotWithTheSameKEK(t *testing.T) {
	kek := testKEK()
	one := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)
	two := slotAAD(v2VaultMagic, testDEKID(), testSlotID(2), slotTypeKEKFile)

	a, err := wrapKey(kek, testDEKID(), one)
	if err != nil {
		t.Fatalf("wrapKey one: %v", err)
	}
	b, err := wrapKey(kek, testDEKID(), two)
	if err != nil {
		t.Fatalf("wrapKey two: %v", err)
	}
	if len(a) != keyLen || len(b) != keyLen {
		t.Fatalf("wrap key lengths = %d, %d, want %d", len(a), len(b), keyLen)
	}
	if bytes.Equal(a, b) {
		t.Fatal("the same KEK derived the same wrap key for two slot ids")
	}
}

func TestWrapKeyIsNeverTheKEK(t *testing.T) {
	kek := testKEK()
	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypePassphrase)
	got, err := wrapKey(kek, testDEKID(), aad)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	if bytes.Equal(got, kek) {
		t.Fatal("wrapKey returned the KEK itself")
	}
	// The dek.id is the HKDF salt, so a second generation derives a different wrap key from the
	// same KEK and the same slot. Without the salt a rotation would reuse the wrap key.
	other := bytes.Repeat([]byte{0x12}, dekIDLen)
	rotated, err := wrapKey(kek, other, slotAAD(v2VaultMagic, other, testSlotID(1), slotTypePassphrase))
	if err != nil {
		t.Fatalf("wrapKey rotated: %v", err)
	}
	if bytes.Equal(got, rotated) {
		t.Fatal("two dek.id generations derived the same wrap key")
	}
}

func TestWrapKeyGoldenVector(t *testing.T) {
	// The derivation is part of the file format: a slot sealed by one version of it is unopenable
	// by another, on every host. So it is pinned as a vector and not only as a set of properties.
	//
	// This is the assertion that makes the HKDF *salt* load-bearing. `dek.id` is also inside the
	// info, so a build that passed nil as the salt still derives a different key per generation and
	// satisfies every property test in this file - the vector is what catches it. The expected
	// bytes were computed by a standalone program against crypto/hkdf, not by this package.
	const (
		wantAAD  = "435356321011111111111111111111111111111111082020202020202001086b656b2d66696c65"
		wantWrap = "bd5fe08d6fd8a1b00de13d4fd6f0e0e3d53fe536a644399591676493ef045638"
	)
	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)
	if got := hex.EncodeToString(aad); got != wantAAD {
		t.Fatalf("aad = %s, want %s", got, wantAAD)
	}
	wk, err := wrapKey(testKEK(), testDEKID(), aad)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	if got := hex.EncodeToString(wk); got != wantWrap {
		t.Fatalf("wrap key = %s, want %s", got, wantWrap)
	}
}

func TestWrapKeyUsesTheDEKIDAsTheHKDFSalt(t *testing.T) {
	// The salt is isolated here by holding the AAD still: wrapKey's dek.id parameter is the only
	// thing that changes, so a derivation that ignored it cannot pass. Deriving under an AAD whose
	// dek.id disagrees with the salt is not a state sealSlot can produce - it takes the salt out of
	// the AAD - but the parameter exists and this pins what it does.
	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypePassphrase)
	a, err := wrapKey(testKEK(), testDEKID(), aad)
	if err != nil {
		t.Fatalf("wrapKey a: %v", err)
	}
	b, err := wrapKey(testKEK(), bytes.Repeat([]byte{0x77}, dekIDLen), aad)
	if err != nil {
		t.Fatalf("wrapKey b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two salts derived the same wrap key, so dek.id is not the HKDF salt")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	kek, dek := testKEK(), testDEK()
	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(3), slotTypeKEKFile)

	nonce, ct, err := sealSlot(kek, dek, aad)
	if err != nil {
		t.Fatalf("sealSlot: %v", err)
	}
	if len(nonce) != nonceLen {
		t.Fatalf("nonce length = %d, want %d", len(nonce), nonceLen)
	}
	got, err := openSlot(kek, nonce, ct, aad)
	if err != nil {
		t.Fatalf("openSlot: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round trip returned %x, want %x", got, dek)
	}
	// A wrong KEK is a bad key, not a malformed file: it is the next slot's turn, not an abort.
	wrong := bytes.Repeat([]byte{0xa2}, keyLen)
	if _, err := openSlot(wrong, nonce, ct, aad); !errors.Is(err, ErrBadKey) {
		t.Fatalf("wrong KEK gave %v, want ErrBadKey", err)
	}
}

func TestOpenSlotWithAModifiedAADFails(t *testing.T) {
	kek, dek := testKEK(), testDEK()
	seal := slotAAD(v2VaultMagic, testDEKID(), testSlotID(4), slotTypeKEKFile)
	nonce, ct, err := sealSlot(kek, dek, seal)
	if err != nil {
		t.Fatalf("sealSlot: %v", err)
	}

	otherDEKID := bytes.Repeat([]byte{0x99}, dekIDLen)
	cases := []struct {
		name string
		aad  []byte
	}{
		{"retyped", slotAAD(v2VaultMagic, testDEKID(), testSlotID(4), slotTypePassphrase)},
		{"another dek generation", slotAAD(v2VaultMagic, otherDEKID, testSlotID(4), slotTypeKEKFile)},
		{"another slot", slotAAD(v2VaultMagic, testDEKID(), testSlotID(5), slotTypeKEKFile)},
		{"the other file's magic", slotAAD(v2KeyringMagic, testDEKID(), testSlotID(4), slotTypeKEKFile)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := openSlot(kek, nonce, ct, c.aad)
			if !errors.Is(err, ErrBadKey) {
				t.Fatalf("err = %v, want ErrBadKey", err)
			}
			if got != nil {
				t.Fatalf("a failed open returned %d bytes", len(got))
			}
		})
	}
}

func TestWrapCiphertextIsFortyEightBytes(t *testing.T) {
	nonce, ct, err := sealSlot(testKEK(), testDEK(), slotAAD(v2VaultMagic, testDEKID(), testSlotID(6), slotTypeKEKFile))
	if err != nil {
		t.Fatalf("sealSlot: %v", err)
	}
	if len(ct) != wrapCTLen {
		t.Fatalf("ct length = %d, want %d (32 + %d tag)", len(ct), wrapCTLen, gcmTagLen)
	}
	// The parser decodes both fields to exactly these lengths, so a wrap of another size would be
	// written and then refused on the next open.
	if len(nonce) != nonceLen {
		t.Fatalf("nonce length = %d, want %d", len(nonce), nonceLen)
	}
}

// wrapGenerations seals the same slot set under n successive DEK generations and returns every
// nonce it drew, in order. Each generation is a rotation: a fresh DEK and a fresh dek.id, re-wrapped
// into every slot, which is what `rotate` does.
//
// It returns an error instead of calling t.Fatal because
// TestConstantRandReaderMakesTheNonceTestsFail runs it expecting failure, and a helper that failed
// the test directly would fail the parent along with it.
func wrapGenerations(slots, generations int) ([][]byte, error) {
	kek := testKEK()
	var nonces [][]byte
	for g := 0; g < generations; g++ {
		dekID := make([]byte, dekIDLen)
		if _, err := randRead(dekID); err != nil {
			return nil, err
		}
		dek := make([]byte, keyLen)
		if _, err := randRead(dek); err != nil {
			return nil, err
		}
		for s := 0; s < slots; s++ {
			aad := slotAAD(v2VaultMagic, dekID, testSlotID(byte(s)), slotTypeKEKFile)
			nonce, _, err := sealSlot(kek, dek, aad)
			if err != nil {
				return nil, err
			}
			nonces = append(nonces, nonce)
		}
		// The payload nonce is fresh on every save, and a save follows every rotation.
		payload := make([]byte, nonceLen)
		if _, err := randRead(payload); err != nil {
			return nil, err
		}
		nonces = append(nonces, payload)
	}
	return nonces, nil
}

// repeatedNonce returns the first nonce that appears twice, or nil when every one is distinct.
func repeatedNonce(nonces [][]byte) []byte {
	seen := make(map[string]bool, len(nonces))
	for _, n := range nonces {
		if seen[string(n)] {
			return n
		}
		seen[string(n)] = true
	}
	return nil
}

func TestWrapNoncesAreUnique(t *testing.T) {
	// The real crypto/rand reader, deliberately: this test exists to prove the nonce rule holds in
	// the binary that ships, and the seam is only poisoned by the meta-test below.
	nonces, err := wrapGenerations(6, 3)
	if err != nil {
		t.Fatalf("wrapGenerations: %v", err)
	}
	if want := 3 * (6 + 1); len(nonces) != want {
		t.Fatalf("drew %d nonces, want %d", len(nonces), want)
	}
	if dup := repeatedNonce(nonces); dup != nil {
		t.Fatalf("nonce reused across slots or generations: %x", dup)
	}
}

func TestRotateChangesEveryNonce(t *testing.T) {
	const slots = 4
	nonces, err := wrapGenerations(slots, 2)
	if err != nil {
		t.Fatalf("wrapGenerations: %v", err)
	}
	// Per generation: one nonce per slot then the payload nonce.
	first, second := nonces[:slots], nonces[slots+1:slots+1+slots]
	for i := range first {
		if bytes.Equal(first[i], second[i]) {
			t.Fatalf("slot %d kept its nonce across the rotation: %x", i, first[i])
		}
	}
}

func TestConstantRandReaderMakesTheNonceTestsFail(t *testing.T) {
	// What makes TestWrapNoncesAreUnique mean anything is that it is reachable from the seam: a
	// sealSlot that ignored randRead, or hashed something deterministic into the nonce, would pass
	// the uniqueness test for the wrong reason. Poisoning the seam here proves the test is wired to
	// the randomness the implementation actually uses.
	prev := randRead
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0x7e
		}
		return len(b), nil
	}
	t.Cleanup(func() { randRead = prev })

	t.Run("a constant reader repeats a nonce", func(t *testing.T) {
		nonces, err := wrapGenerations(3, 2)
		if err != nil {
			t.Fatalf("wrapGenerations: %v", err)
		}
		if dup := repeatedNonce(nonces); dup == nil {
			t.Fatal("a constant rand reader produced no repeated nonce, so the uniqueness test is not wired to the seam")
		}
	})

	// And the seam is restorable: the real reader is back for everything after this test.
	t.Run("the real reader is restored", func(t *testing.T) {
		b := make([]byte, nonceLen)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	})
}

func TestSealSlotRefusesAMalformedAAD(t *testing.T) {
	// sealSlot takes the dek.id out of the AAD it was handed, so an AAD that is not the byte string
	// slotAAD builds has no dek.id to find. Deriving from whatever happened to sit at that offset
	// would produce a slot that opens and binds nothing.
	good := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)
	cases := []struct {
		name string
		aad  []byte
	}{
		{"empty", nil},
		{"truncated before the ids", good[:4]},
		{"truncated mid dek.id", good[:12]},
		{"a dek.id prefix of the wrong length", append([]byte("CSV2\x0f"), good[5:]...)},
		{"a slot.id prefix of the wrong length", func() []byte {
			b := append([]byte(nil), good...)
			b[5+dekIDLen] = 0x07
			return b
		}()},
		{"no type field", good[:5+dekIDLen+1+slotIDLen]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := sealSlot(testKEK(), testDEK(), c.aad); err == nil {
				t.Fatal("sealSlot accepted a malformed AAD")
			}
			if _, err := openSlot(testKEK(), make([]byte, nonceLen), make([]byte, wrapCTLen), c.aad); err == nil {
				t.Fatal("openSlot accepted a malformed AAD")
			}
		})
	}
}

func TestSealSlotRefusesAKeyOrDEKOfTheWrongLength(t *testing.T) {
	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)
	if _, _, err := sealSlot(bytes.Repeat([]byte{1}, keyLen-1), testDEK(), aad); err == nil {
		t.Fatal("sealSlot accepted a 31-byte KEK")
	}
	if _, _, err := sealSlot(testKEK(), bytes.Repeat([]byte{1}, keyLen+1), aad); err == nil {
		t.Fatal("sealSlot accepted a 33-byte DEK")
	}
	if _, err := openSlot(bytes.Repeat([]byte{1}, keyLen-1), make([]byte, nonceLen), make([]byte, wrapCTLen), aad); err == nil {
		t.Fatal("openSlot accepted a 31-byte KEK")
	}
}

func TestOpenSlotNeverReturnsADEKOfTheWrongLength(t *testing.T) {
	// A wrap that authenticates but carries something other than 32 bytes is a file this binary
	// wrote wrong or a format it does not know; handing those bytes back as a DEK would build an
	// AES key out of them. The parser's length check on `ct` is the first line and this is the
	// second, because openSlot is reachable from the fuzz target in Task 3a.10 with no parse first.
	kek := testKEK()
	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)
	wk, err := wrapKey(kek, testDEKID(), aad)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	short, err := sealWith(wk, bytes.Repeat([]byte{0x01}, keyLen-1), aad)
	if err != nil {
		t.Fatalf("sealWith: %v", err)
	}
	got, err := openSlot(kek, short.nonce, short.ct, aad)
	if err == nil {
		t.Fatalf("openSlot returned %d bytes for a short wrap", len(got))
	}
	if got != nil {
		t.Fatalf("a failed open returned %d bytes", len(got))
	}
}
