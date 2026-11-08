package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the v2 open flow and the v2 writer: the slot walk that recovers the data key, the
// payload open under the bytes of the header as they were read from disk, and the re-seal that
// carries that header forward with a fresh nonce.
//
// Every file here is built by buildV2 out of this package's own primitives (sealSlot, encodeSlot,
// encodeCompact, payloadAEAD), so a test fixture cannot drift from the format the writer emits -
// and none of it goes anywhere near a real data dir: every path is under t.TempDir().

// The fixed inputs. A 16-byte dek.id and a 32-byte data key, both literal, so a failure is
// reproducible and nothing here depends on the host's randomness except the nonces, which are the
// one thing that must be fresh.
const (
	fileDEKID   = "0123456789abcdef"
	fileDEK     = "0123456789abcdef0123456789abcdef"
	fileCreated = "2026-11-07T12:00:00Z"
	fileKEK     = "0000000000000000000000000000kek1"
	// Distinct from fileDEKID, and both sixteen bytes: a fixture in which two fields share a spelling
	// would make a tamper case that names one of them ambiguous.
	fileSalt = "abcdefghijklmnop"
)

// cheapArgon is the argon2id cost every passphrase slot in this file is written at: the floor of
// each bound (t=1, m=8 KiB, p=1), which the parser accepts and which costs microseconds. The real
// derivation therefore runs in these tests rather than a stub - that is the point, since the
// passphrase slot is the one slot type whose key-encryption key this package derives itself - and a
// test binary still finishes in the time the rest of the suite takes.
func cheapArgon() *Argon2Params {
	return &Argon2Params{T: minArgonTime, M: minArgonMem, P: minArgonPar,
		Salt: base64.StdEncoding.EncodeToString([]byte(fileSalt))}
}

// v2Spec is one slot buildV2 should write. Exactly one of raw, pass or kek says what kind it is:
// raw is a slot of a type this binary does not know, emitted verbatim; pass seals the data key
// under an argon2id-derived key; kek seals it under a 32-byte key-encryption key.
type v2Spec struct {
	id   string // slotIDLen raw bytes
	typ  string
	name string
	pass string
	kek  []byte
	raw  string
}

func passSpec(id, pass string) v2Spec {
	return v2Spec{id: id, typ: slotTypePassphrase, pass: pass}
}

func kekSpec(id string, kek []byte) v2Spec {
	return v2Spec{id: id, typ: slotTypeKEKFile, name: "vault-kek", kek: kek}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// buildV2 writes a complete v2 file: the header JSON through this package's own encoder, then the
// payload sealed under the data key with the first 8+hdrLen bytes as additional data.
func buildV2(t *testing.T, magicStr string, dek []byte, specs []v2Spec, plain []byte) []byte {
	t.Helper()
	return v2FileFrom(t, magicStr, dek, buildV2Header(t, magicStr, dek, specs), plain)
}

// buildV2Header is buildV2's header half, so a tamper test can alter the bytes between the encode
// and the seal and get a file whose payload is still sealed under the header that was written.
func buildV2Header(t *testing.T, magicStr string, dek []byte, specs []v2Spec) []byte {
	t.Helper()
	v2 := v2Magic(magicStr)
	if v2 == "" {
		t.Fatalf("buildV2: no v2 magic for %q", magicStr)
	}
	dekID := []byte(fileDEKID)
	elems := make([]json.RawMessage, 0, len(specs))
	for _, sp := range specs {
		if sp.raw != "" {
			elems = append(elems, json.RawMessage(sp.raw))
			continue
		}
		if len(sp.id) != slotIDLen {
			t.Fatalf("buildV2: slot id %q is %d bytes, want %d", sp.id, len(sp.id), slotIDLen)
		}
		slot := Slot{ID: b64([]byte(sp.id)), Type: sp.typ, Name: sp.name, Created: fileCreated}
		var kek []byte
		switch sp.typ {
		case slotTypePassphrase:
			slot.Argon2id = cheapArgon()
			k, err := passphraseKEK(sp.pass, *slot.Argon2id)
			if err != nil {
				t.Fatalf("buildV2: passphraseKEK: %v", err)
			}
			kek = k
		case slotTypeKEKFile:
			kek = sp.kek
		default:
			t.Fatalf("buildV2 cannot seal a %q slot; give it raw JSON instead", sp.typ)
		}
		nonce, ct, err := sealSlot(kek, dek, slotAAD(v2, dekID, []byte(sp.id), sp.typ))
		if err != nil {
			t.Fatalf("buildV2: sealSlot: %v", err)
		}
		slot.Wrap = WrapInfo{Nonce: b64(nonce), CT: b64(ct)}
		enc, err := encodeSlot(slot)
		if err != nil {
			t.Fatalf("buildV2: encodeSlot: %v", err)
		}
		elems = append(elems, enc)
	}
	hdr, err := encodeCompact(Header{V: headerVersion,
		DEK:   DEKInfo{ID: b64(dekID), Created: fileCreated},
		Slots: elems})
	if err != nil {
		t.Fatalf("buildV2: encodeCompact: %v", err)
	}
	return hdr
}

// v2FileFrom assembles magic || hdrLen || header || nonce || sealed payload. The additional data is
// the prefix as it will sit on disk, which is the whole AAD rule in one line.
func v2FileFrom(t *testing.T, magicStr string, dek, hdr, plain []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	raw.WriteString(v2Magic(magicStr))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(hdr)))
	raw.Write(n[:])
	raw.Write(hdr)
	aead, err := payloadAEAD(dek)
	if err != nil {
		t.Fatalf("payloadAEAD: %v", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	out := append([]byte(nil), raw.Bytes()...)
	out = append(out, nonce...)
	return append(out, aead.Seal(nil, nonce, plain, raw.Bytes())...)
}

// accountsPayload is a v2 vault's plaintext: the same JSON array the v1 payload is.
func accountsPayload(t *testing.T, ids ...string) []byte {
	t.Helper()
	list := make([]Account, 0, len(ids))
	for _, id := range ids {
		list = append(list, acct(id))
	}
	b, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return b
}

// kekSource returns a KeySource offering this host's kek-file opener over a key file holding kek,
// plus whatever passphrase the caller wants behind it. CREDENTIALS_DIRECTORY is cleared so a test
// cannot be decided by the environment of the machine it runs on.
func kekSource(t *testing.T, kek []byte, pass string, passErr error) *recordingKeySource {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(p, kek, 0o600); err != nil {
		t.Fatalf("write kek file: %v", err)
	}
	t.Setenv(credentialsDirEnv, "")
	t.Setenv(kekFileEnv, "")
	op := kekFileOpener(HostKeyOptions{KEKFile: p})
	if op == nil {
		t.Fatalf("kekFileOpener returned nil for a %d-byte key file", len(kek))
	}
	return &recordingKeySource{pass: pass, passErr: passErr, openers: []SlotOpener{op}}
}

// fileMagic is the first four bytes on disk, which is how every test here asks "what did the writer
// actually write".
func fileMagic(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if len(data) < 4 {
		t.Fatalf("%s is %d bytes", filepath.Base(path), len(data))
	}
	return string(data[:4])
}

// --- the passphrase slot: a full round trip through the writer ---

// The baseline. A v2 vault with one passphrase slot opens, the payload comes back, a write re-seals
// it as v2 and a reopen reads what was written. Nothing in this package could do any of that before:
// openSealedV2 answered ErrBadKey for every file it could parse.
func TestV2PassphraseSlotOpensAndWritesBackAsV2(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			accountsPayload(t, "a")))

	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got, ok := v.Get("a"); !ok || got.Label != "La" {
		t.Fatalf("the passphrase slot opened the file but lost the account: %+v ok=%v", got, ok)
	}
	if err := v.Put(acct("b")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := fileMagic(t, p); got != v2VaultMagic {
		t.Fatalf("a save on a v2 vault wrote magic %q; it must stay %q, or the file never opens again",
			got, v2VaultMagic)
	}
	again, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("reopen after a v2 write: %v", err)
	}
	for _, id := range []string{"a", "b"} {
		if _, ok := again.Get(id); !ok {
			t.Fatalf("account %q did not survive the v2 write", id)
		}
	}
	// The mutation check for the whole round trip: the same file under another passphrase must not
	// open, so the open above was the key doing the work and not a path that ignores it.
	if _, err := open(t, p, "wrong"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("a wrong passphrase gave %v, want ErrBadKey", err)
	}
}

// The keyring is the same envelope under its own magic, and the magic is bound into every slot's
// AAD. A save must keep CSK2 for the same reason a vault's must keep CSV2.
func TestV2KeyringOpensAndWritesBackAsCSK2(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, KeyringFileName,
		buildV2(t, keyringMagic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			[]byte(`{"keys":null}`)))

	t.Setenv(keyEnv, "pw")
	k, err := OpenKeyring(p, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if _, err := k.Generate("h1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got := fileMagic(t, p); got != v2KeyringMagic {
		t.Fatalf("a save on a v2 keyring wrote magic %q, want %q", got, v2KeyringMagic)
	}
	again, err := OpenKeyring(p, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := again.Get("h1"); !ok {
		t.Fatal("the key did not survive the v2 keyring write")
	}
}

// A vault's magic is in every slot's AAD, so a CSK2 file opened as a vault must not unwrap even
// though the passphrase is right: that is the cross-magic rule the v1 path already has.
func TestV2CrossMagicDoesNotUnwrap(t *testing.T) {
	dir := t.TempDir()
	p := writeFixture(t, dir, "vault.bin",
		buildV2(t, keyringMagic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			accountsPayload(t, "a")))
	if _, err := open(t, p, "pw"); !errors.Is(err, errCorrupt) {
		t.Fatalf("a CSK2 file opened as a vault gave %v, want errCorrupt", err)
	}
}

// --- the open order ---

// The order the spec fixes: machine slots first, the passphrase last and only if a machine slot did
// not produce the key. A service has no passphrase, so a passphrase slot tried first would produce
// a prompt it cannot answer; an operator at a console has one, and spending it on a slot that was
// going to work anyway is a prompt nobody needed.
func TestV2MachineSlotOpensWithoutAskingForThePassphrase(t *testing.T) {
	kek := []byte(fileKEK)
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{
			passSpec("slot0001", "pw"),
			kekSpec("slot0002", kek),
		}, accountsPayload(t, "a")))

	ks := kekSource(t, kek, "pw", nil)
	v, err := Open(p, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := v.Get("a"); !ok {
		t.Fatal("the machine slot opened the file but lost the account")
	}
	if ks.passCalls != 0 {
		t.Fatalf("Passphrase called %d times when a machine slot opened the file, want 0", ks.passCalls)
	}
	if ks.machineCall == 0 {
		t.Fatal("Machine was never called, so the file did not open through a machine slot")
	}

	// The positive control, without which "passCalls == 0" is a claim about a stub nothing calls:
	// the same KeySource type, on a file whose only slot is a passphrase, is asked exactly once.
	t.Run("the same KeySource is asked when only a passphrase slot is there", func(t *testing.T) {
		pp := writeFixture(t, t.TempDir(), "vault.bin",
			buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
				accountsPayload(t, "a")))
		ks := kekSource(t, kek, "pw", nil)
		if _, err := Open(pp, ks); err != nil {
			t.Fatalf("Open: %v", err)
		}
		if ks.passCalls != 1 {
			t.Fatalf("Passphrase called %d times, want exactly 1", ks.passCalls)
		}
	})
}

// An opener is chosen by the slot's type and never by its position in the list. HostKeys omits the
// openers a host does not have, so the indices mean nothing; and an opener handed a slot of another
// type answers errCorrupt, which would turn "this host has no opener for this kind, skip the slot"
// into a refusal of a file that opens perfectly well through its next slot.
func TestV2AnOpenerIsNeverHandedASlotOfAnotherType(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{
			kekSpec("slot0002", []byte(fileKEK)),
			passSpec("slot0001", "pw"),
		}, accountsPayload(t, "a")))
	// An opener for a kind this file has no slot of. stubOpener fails the test if it is ever asked
	// to unwrap, which is the assertion.
	ks := &recordingKeySource{pass: "pw",
		openers: []SlotOpener{stubOpener{t: t, kind: slotTypeDPAPI}}}
	v, err := Open(p, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := v.Get("a"); !ok {
		t.Fatal("the passphrase slot opened the file but lost the account")
	}
	if ks.passCalls != 1 {
		t.Fatalf("Passphrase called %d times, want 1: the kek-file slot has no opener here, so the "+
			"passphrase slot is the one that can open this file", ks.passCalls)
	}
}

// Eight passphrase slots are allowed and argon2id is deliberately expensive, so the passphrase is
// asked for once per open however many slots want it.
func TestV2PassphraseIsAskedForAtMostOncePerOpen(t *testing.T) {
	specs := []v2Spec{
		// Two slots the passphrase cannot open, then one it can: the walk must not re-ask.
		passSpec("slot0001", "other-1"),
		passSpec("slot0002", "other-2"),
		passSpec("slot0003", "pw"),
	}
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), specs, accountsPayload(t, "a")))
	ks := &recordingKeySource{pass: "pw"}
	if _, err := Open(p, ks); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ks.passCalls != 1 {
		t.Fatalf("Passphrase called %d times across three passphrase slots, want 1", ks.passCalls)
	}
}

// A header this binary cannot read is answered from the bytes, and no key is asked for on the way:
// telling an operator to set CLAUDESWAP_KEY for a file whose header is unreadable is how a correct
// passphrase gets rotated out of confusion. The malformed case is pinned in keysource_test.go; this
// is the other half, a header that parses and names a version this binary does not write.
func TestV2NewerVersionAsksForNoKeyAtAll(t *testing.T) {
	hdr := buildV2Header(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")})
	newer := bytes.Replace(hdr, []byte(`{"v":2,`), []byte(`{"v":3,`), 1)
	if bytes.Equal(hdr, newer) {
		t.Fatal("the version was not replaced")
	}
	p := writeFixture(t, t.TempDir(), "vault.bin",
		v2FileFrom(t, magic, []byte(fileDEK), newer, accountsPayload(t, "a")))

	ks := &recordingKeySource{pass: "pw"}
	if _, err := Open(p, ks); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("Open: want ErrNewerFormat, got %v", err)
	}
	if ks.passCalls != 0 || ks.machineCall != 0 {
		t.Fatalf("a newer header asked for keys: passphrase %d, machine %d", ks.passCalls, ks.machineCall)
	}
}

// --- what cannot open ---

// Every field of the header is covered, one way or the other: a field in a slot's AAD stops the
// wrap opening, and a field that is not stops the payload opening, because the payload's additional
// data is the header's bytes as read from disk. Either way the answer is a refusal and never a
// silent success, and never ErrNewerFormat, which would send an operator to a downgrade they do not
// need.
//
// Each case rewrites one field to a value of the SAME length, so hdrLen and every offset after it
// are untouched: what is under test is the binding, not the bounds.
func TestV2TamperedHeaderFieldIsRefused(t *testing.T) {
	dek := []byte(fileDEK)
	specs := []v2Spec{passSpec("slot0001", "pw"), kekSpec("slot0002", []byte(fileKEK))}
	hdr := buildV2Header(t, magic, dek, specs)
	payload := accountsPayload(t, "a")

	// The file is assembled ONCE, from the untouched header, and each case then edits the header
	// bytes where they sit in that file. Re-sealing the payload under the edited header would be
	// forging a new file rather than tampering with this one, and every case that only the payload's
	// AAD covers would pass for the wrong reason.
	file := v2FileFrom(t, magic, dek, hdr, payload)

	// The control: untouched, the file opens. Without it every case below could pass because the
	// fixture never opened at all.
	p := writeFixture(t, t.TempDir(), "vault.bin", file)
	if _, err := open(t, p, "pw"); err != nil {
		t.Fatalf("the untouched fixture does not open, so the tamper cases prove nothing: %v", err)
	}

	for _, tc := range []struct {
		field string
		from  string
		to    string
	}{
		{"dek.id", b64([]byte(fileDEKID)), b64([]byte("fedcba9876543210"))},
		{"dek.created", `"created":"2026-11-07T12:00:00Z"},"slots"`, `"created":"2026-11-07T12:00:01Z"},"slots"`},
		{"slot.id", b64([]byte("slot0001")), b64([]byte("slot9999"))},
		{"slot.type", `"type":"kek-file"`, `"type":"kek-fiIe"`},
		{"slot.name", `"name":"vault-kek"`, `"name":"vault-keK"`},
		{"slot.created", `"created":"2026-11-07T12:00:00Z","argon2id"`, `"created":"2026-11-07T12:00:01Z","argon2id"`},
		{"argon2id.t", `"t":1`, `"t":2`},
		{"argon2id.m", `"m":8`, `"m":9`},
		{"argon2id.salt", b64([]byte(fileSalt)), b64([]byte("fedcba9876543210"))},
	} {
		t.Run(tc.field, func(t *testing.T) {
			if bytes.Count(file, []byte(tc.from)) != 1 {
				t.Fatalf("the file holds %d occurrences of %q; a tamper case must name exactly one",
					bytes.Count(file, []byte(tc.from)), tc.from)
			}
			if len(tc.from) != len(tc.to) {
				t.Fatalf("the replacement changes the header's length (%d to %d)", len(tc.from), len(tc.to))
			}
			bad := bytes.Replace(file, []byte(tc.from), []byte(tc.to), 1)
			p := writeFixture(t, t.TempDir(), "vault.bin", bad)
			_, err := open(t, p, "pw")
			if err == nil {
				t.Fatal("the tampered header opened")
			}
			if !errors.Is(err, ErrBadKey) && !errors.Is(err, errCorrupt) {
				t.Fatalf("err = %v, want ErrBadKey or errCorrupt", err)
			}
			if errors.Is(err, ErrNewerFormat) {
				t.Fatalf("a tampered header reports as a newer format: %v", err)
			}
		})
	}
	// The wrap's own bytes, which are not the same length game: a ct that still decodes to 48 bytes
	// but holds something else must be ErrBadKey, not a malformed file.
	t.Run("wrap.ct", func(t *testing.T) {
		_, slots, err := parseHeader(hdr)
		if err != nil {
			t.Fatalf("parseHeader: %v", err)
		}
		ct, err := base64.StdEncoding.DecodeString(slots[0].Wrap.CT)
		if err != nil {
			t.Fatalf("decode ct: %v", err)
		}
		ct[0] ^= 0x01
		bad := bytes.Replace(file, []byte(slots[0].Wrap.CT), []byte(b64(ct)), 1)
		p := writeFixture(t, t.TempDir(), "vault.bin", bad)
		if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
			t.Fatalf("a flipped bit in the wrap gave %v, want ErrBadKey", err)
		}
	})
}

// The payload's additional data is the header's bytes AS WRITTEN, never a re-marshal of the parse.
// The fixture here is a header this binary would not have emitted - its top-level members are in
// another order and one slot carries whitespace - and that is deliberately the case a newer server
// produces. It parses (the top level is read as a map, and json.RawMessage keeps a slot's bytes), so
// a reader that rebuilt the AAD by re-encoding the parsed header would open every slot and then fail
// on the payload, for a file that is not damaged in any way.
//
// It is also the reason retention is not enough on its own: marshalHeader canonicalises, so the
// bytes it emits for this header are NOT the bytes it was given, and only reading the AAD off the
// file keeps the two apart.
func TestV2PayloadOpensUnderTheHeaderBytesAsWrittenNotAReMarshal(t *testing.T) {
	dek := []byte(fileDEK)
	canonical := buildV2Header(t, magic, dek, []v2Spec{passSpec("slot0001", "pw")})
	_, slots, err := parseHeader(canonical)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	slot, err := json.MarshalIndent(slots[0], "", "  ")
	if err != nil {
		t.Fatalf("indent the slot: %v", err)
	}
	// dek, then slots, then v: every member present and well-formed, none of them in the writer's
	// order. The pretty-printed slot adds the whitespace a round trip through the encoder removes.
	hdr := []byte(`{"dek":{"id":"` + b64([]byte(fileDEKID)) + `","created":"` + fileCreated + `"},` +
		`"slots":[` + string(slot) + `],"v":2}`)
	if _, _, err := parseHeader(hdr); err != nil {
		t.Fatalf("the non-canonical header must parse, or this test proves nothing: %v", err)
	}
	// The control for the whole test: if a re-marshal gave these same bytes back, both AADs would
	// agree and nothing here would be under test.
	if again, merr := marshalHeader(mustHeader(t, hdr), nil); merr != nil {
		t.Fatalf("marshalHeader: %v", merr)
	} else if bytes.Equal(again, hdr) {
		t.Fatal("the fixture survives a re-marshal unchanged, so it cannot tell the two AADs apart")
	}

	p := writeFixture(t, t.TempDir(), "vault.bin",
		v2FileFrom(t, magic, dek, hdr, accountsPayload(t, "a")))
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("a header this binary did not write does not open: %v", err)
	}
	if _, ok := v.Get("a"); !ok {
		t.Fatal("the file opened but lost the account")
	}
	// And a save canonicalises it, which is fine precisely because the payload is resealed under the
	// bytes that save wrote.
	if err := v.Put(acct("b")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := open(t, p, "pw"); err != nil {
		t.Fatalf("reopen after the save that canonicalised the header: %v", err)
	}
}

func mustHeader(t *testing.T, raw []byte) Header {
	t.Helper()
	h, _, err := parseHeader(raw)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	return h
}

// A payload byte flipped under an untouched header is the other side of the same binding: the slot
// still opens, so the data key is right, and the payload's GCM tag is what refuses.
func TestV2TamperedPayloadIsErrBadKey(t *testing.T) {
	dek := []byte(fileDEK)
	file := buildV2(t, magic, dek, []v2Spec{passSpec("slot0001", "pw")}, accountsPayload(t, "a"))
	file[len(file)-1] ^= 0x01
	p := writeFixture(t, t.TempDir(), "vault.bin", file)
	if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("a flipped payload byte gave %v, want ErrBadKey", err)
	}
}

// Truncation at every boundary of the layout. Nothing may panic and nothing may open; a file that
// no longer carries 8 + hdrLen + 12 + 16 bytes is malformed.
func TestV2TruncatedFileIsErrCorrupt(t *testing.T) {
	dek := []byte(fileDEK)
	file := buildV2(t, magic, dek, []v2Spec{passSpec("slot0001", "pw")}, accountsPayload(t, "a"))
	hdrEnd := v2PrefixLen + int(binary.BigEndian.Uint32(file[4:v2PrefixLen]))
	// Every boundary of the layout up to the shortest file that still satisfies
	// 8 + hdrLen + 12 + 16. Past that the bytes are a complete envelope with a short ciphertext,
	// which is the tag's business and not the parser's - the subtest below is that case.
	for _, n := range []int{0, 1, 4, 7, v2PrefixLen, hdrEnd - 1, hdrEnd, hdrEnd + nonceLen,
		hdrEnd + nonceLen + gcmTagLen - 1} {
		if n >= len(file) {
			t.Fatalf("the truncation at %d is not shorter than the %d-byte file", n, len(file))
		}
		p := writeFixture(t, t.TempDir(), "vault.bin", file[:n])
		_, err := open(t, p, "pw")
		// A zero-byte file is the create-on-open case and is not an error at all: it is an empty v1
		// vault in memory, which is what it was before v2 existed.
		if n == 0 {
			if err != nil {
				t.Fatalf("an empty file gave %v, want the create-on-open path", err)
			}
			continue
		}
		if !errors.Is(err, errCorrupt) {
			t.Fatalf("truncated to %d bytes: want errCorrupt, got %v", n, err)
		}
	}
	// A byte off the end of a well-formed envelope: the header parses, the slot opens, and the
	// payload's own tag refuses. ErrBadKey, not errCorrupt - the file is not malformed, its
	// ciphertext is short - and never a success.
	p := writeFixture(t, t.TempDir(), "vault.bin", file[:len(file)-1])
	if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("one byte off the payload: want ErrBadKey, got %v", err)
	}
}

// --- the nonce rule ---

// Every save draws a fresh payload nonce. A repeat under the same data key leaks the key stream and
// the GCM authentication key, and the payload is the whole vault.
func TestV2PayloadNonceIsFreshOnEveryWrite(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			accountsPayload(t, "a")))
	seen := map[string]bool{payloadNonce(t, p): true}
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 8 {
		if err := v.Put(acct(string(rune('b' + i)))); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		n := payloadNonce(t, p)
		if seen[n] {
			t.Fatalf("write %d reused a payload nonce", i)
		}
		seen[n] = true
	}
	if len(seen) != 9 {
		t.Fatalf("got %d distinct nonces across 9 writes", len(seen))
	}
	// The mutation check: with the random seam returning a constant the property above must fail.
	// Without this, a writer that copied the previous nonce would pass whenever the test happened
	// not to look.
	t.Run("a constant random reader makes this test fail", func(t *testing.T) {
		prev := randRead
		randRead = func(b []byte) (int, error) {
			for i := range b {
				b[i] = 0x11
			}
			return len(b), nil
		}
		t.Cleanup(func() { randRead = prev })
		p := writeFixture(t, t.TempDir(), "vault.bin",
			buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
				accountsPayload(t, "a")))
		v, err := open(t, p, "pw")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := v.Put(acct("b")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		first := payloadNonce(t, p)
		if err := v.Put(acct("c")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if payloadNonce(t, p) != first {
			t.Fatal("the constant seam still produced two different nonces, so the seam is not the " +
				"writer's only source of randomness and the test above proves nothing")
		}
	})
}

// payloadNonce returns the twelve bytes after the header, base64 so a map key reads in a failure.
func payloadNonce(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) < v2PrefixLen {
		t.Fatalf("the file is %d bytes", len(data))
	}
	end := v2PrefixLen + int(binary.BigEndian.Uint32(data[4:v2PrefixLen]))
	if len(data) < end+nonceLen {
		t.Fatalf("the file is %d bytes, shorter than its header and nonce", len(data))
	}
	return b64(data[end : end+nonceLen])
}

// --- retention and the write refusals ---

// A slot of a type this binary does not know is skipped on open and its bytes are re-emitted
// unchanged by the writer. The header round trip is pinned in slots_test.go against marshalHeader;
// this pins it against the writer that actually puts a file on disk.
func TestV2WriteRetainsAnUnknownSlotByteForByte(t *testing.T) {
	const unknown = `{"id":"QUJDREVGR0g=","type":"tpm-v9","created":"2026-11-07T12:00:00Z",` +
		`"wrap":{"handle":"AAEC","sealed":"AAEC"}}`
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{
			{raw: unknown},
			passSpec("slot0001", "pw"),
		}, accountsPayload(t, "a")))

	buf := captureLog(t)
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// One warning, naming the slot and its type and nothing else - the slot was skipped, not refused.
	lines := logLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want one per skipped slot: %q", len(lines), buf.String())
	}
	if got := lines[0]["slottype"]; got != "tpm-v9" {
		t.Fatalf("slottype = %v, want tpm-v9", got)
	}
	if err := v.Put(acct("b")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(data, []byte(unknown)) {
		t.Fatalf("the unknown slot's bytes did not survive the write")
	}
	if _, err := open(t, p, "pw"); err != nil {
		t.Fatalf("reopen after a write that retained an unknown slot: %v", err)
	}
}

// A v2 file with no passphrase slot can be opened - a hand-damaged header has to be readable to be
// repairable - and cannot be saved: a machine slot is tied to one host, and losing the host would
// take the vault with it. The refusal has to come from the writer, because that is where the file
// on disk is decided.
func TestV2WriteWithNoPassphraseSlotIsRefusedAndChangesNothing(t *testing.T) {
	kek := []byte(fileKEK)
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{kekSpec("slot0002", kek)},
			accountsPayload(t, "a")))
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	v, err := Open(p, kekSource(t, kek, "", ErrNoKey))
	if err != nil {
		t.Fatalf("a header with no passphrase slot must still open so it can be repaired: %v", err)
	}
	if _, ok := v.Get("a"); !ok {
		t.Fatal("the machine slot opened the file but lost the account")
	}
	if err := v.Put(acct("b")); !errors.Is(err, ErrNoRecoverySlot) {
		t.Fatalf("Put: want ErrNoRecoverySlot, got %v", err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused write changed the file")
	}
}

// The writer's other refusal, which belongs to the caller rather than the file: a `changed` entry
// whose map key and whose Slot's own id disagree. The key decides which slot is touched and the id
// is what gets encoded, so an unchecked pair rewrites an id that is length-prefixed into every
// wrap's AAD - every wrap bound to the old id stops opening while the file still parses.
func TestV2WriteRefusesAChangedSlotWhoseIDDoesNotMatchItsKey(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			accountsPayload(t, "a")))
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, slots, err := parseHeader(v.file.rawHeader[v2PrefixLen:])
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	wrong := slots[0]
	wrong.ID = b64([]byte("slot9999"))
	err = v.file.writeV2(magic, accountsPayload(t, "a"), map[string]Slot{slots[0].ID: wrong})
	if !errors.Is(err, errSlotIDMismatch) {
		t.Fatalf("writeV2: want errSlotIDMismatch, got %v", err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused write changed the file")
	}
}

// A change to a slot has to land in the rawHeader the next payload is sealed under, or the file
// opens once and never again. The salt rotation below is what `change-passphrase` does.
func TestV2ChangedSlotUpdatesTheRawHeaderAndTheFileStillOpens(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			accountsPayload(t, "a")))
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, slots, err := parseHeader(v.file.rawHeader[v2PrefixLen:])
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	next := slots[0]
	params := *next.Argon2id
	params.Salt = b64(bytes.Repeat([]byte{0x7f}, saltLen))
	next.Argon2id = &params
	// The new salt means a new key-encryption key, so the wrap has to be resealed under it or the
	// slot stops opening. That is what `change-passphrase` does and what Task 3b.2 will call.
	kek, err := passphraseKEK("pw2", params)
	if err != nil {
		t.Fatalf("passphraseKEK: %v", err)
	}
	aad := slotAAD(v2VaultMagic, []byte(fileDEKID), []byte("slot0001"), slotTypePassphrase)
	nonce, ct, err := sealSlot(kek, v.file.dek, aad)
	if err != nil {
		t.Fatalf("sealSlot: %v", err)
	}
	next.Wrap = WrapInfo{Nonce: b64(nonce), CT: b64(ct)}

	oldRaw := append([]byte(nil), v.file.rawHeader...)
	if err := v.file.writeV2(magic, accountsPayload(t, "a"), map[string]Slot{next.ID: next}); err != nil {
		t.Fatalf("writeV2: %v", err)
	}
	if bytes.Equal(oldRaw, v.file.rawHeader) {
		t.Fatal("the rawHeader was not updated, so the next payload would be sealed under stale bytes")
	}
	if _, err := open(t, p, "pw2"); err != nil {
		t.Fatalf("the file does not open under the new passphrase: %v", err)
	}
	if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("the old passphrase still opens the file: %v", err)
	}
	// And a save through the ordinary path must seal under the header that is now on disk.
	again, err := open(t, p, "pw2")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := again.Put(acct("b")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := open(t, p, "pw2"); err != nil {
		t.Fatalf("reopen after a save on the changed header: %v", err)
	}
}

// --- ErrKEKUnreachable is not ErrBadKey ---

// A kek-file slot whose key this process cannot reach is the exit-2 class, and it must not be
// reported as a bad key: "try another key" on a machine slot means rotating something that is very
// probably correct, and pushing an operator towards that is an Anti-goal. The error has to survive
// the walk, because the opener is consulted in the middle of it.
func TestV2UnreachableKEKIsReportedRatherThanABadKey(t *testing.T) {
	kek := []byte(fileKEK)
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{kekSpec("slot0002", kek)},
			accountsPayload(t, "a")))
	// Thirty-one bytes: configured, present, and not a key. readKEKFile refuses it, so the opener
	// carries the refusal rather than being absent.
	ks := kekSource(t, kek[:len(kek)-1], "", ErrNoKey)
	_, err := Open(p, ks)
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("Open: want ErrKEKUnreachable, got %v", err)
	}
	if errors.Is(err, ErrBadKey) {
		t.Fatalf("an unreachable KEK is reported as a bad key: %v", err)
	}

	// Masked by a success, and only by a success: the recovery rung is the passphrase, so a file
	// that has one still opens with the unreachable slot in it.
	t.Run("a later slot that opens wins", func(t *testing.T) {
		p := writeFixture(t, t.TempDir(), "vault.bin",
			buildV2(t, magic, []byte(fileDEK), []v2Spec{
				kekSpec("slot0002", kek),
				passSpec("slot0001", "pw"),
			}, accountsPayload(t, "a")))
		ks := kekSource(t, kek[:len(kek)-1], "pw", nil)
		v, err := Open(p, ks)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, ok := v.Get("a"); !ok {
			t.Fatal("the passphrase slot opened the file but lost the account")
		}
	})

	// A wrong-but-readable KEK is the other diagnosis and keeps ErrBadKey: the key is reachable and
	// does not fit, which is exactly "try the next slot" and then "no slot could unwrap".
	t.Run("a readable KEK that does not fit stays ErrBadKey", func(t *testing.T) {
		p := writeFixture(t, t.TempDir(), "vault.bin",
			buildV2(t, magic, []byte(fileDEK), []v2Spec{kekSpec("slot0002", kek)},
				accountsPayload(t, "a")))
		wrong := append([]byte(nil), kek...)
		wrong[0] ^= 0xff
		_, err := Open(p, kekSource(t, wrong, "", ErrNoKey))
		if !errors.Is(err, ErrBadKey) {
			t.Fatalf("want ErrBadKey, got %v", err)
		}
		if errors.Is(err, ErrKEKUnreachable) {
			t.Fatalf("a reachable KEK that does not fit is reported as unreachable: %v", err)
		}
	})
}

// A v2 file whose only slot is a passphrase one, opened by a process that has no passphrase, is
// ErrNoKey and not ErrBadKey: nothing was tried, so there is no key to call bad, and the actionable
// answer names the variable that was not set.
func TestV2WithNoKeyAtAllIsErrNoKey(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", "pw")},
			accountsPayload(t, "a")))
	_, err := Open(p, &recordingKeySource{passErr: ErrNoKey})
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("Open: want ErrNoKey, got %v", err)
	}
	if errors.Is(err, ErrBadKey) {
		t.Fatalf("a missing key is reported as a bad key: %v", err)
	}
}

// The error an operator sees when nothing opened names the kinds that were tried and no value from
// any of them: not an id, not a salt, not a nonce, not a wrapped key.
func TestV2NoSlotOpenedNamesKindsAndNoValues(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin",
		buildV2(t, magic, []byte(fileDEK), []v2Spec{
			passSpec("slot0001", "pw"),
			kekSpec("slot0002", []byte(fileKEK)),
		}, accountsPayload(t, "a")))
	_, err := open(t, p, "wrong")
	if !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "kek-file, passphrase") {
		t.Fatalf("the error does not name the kinds in try order: %q", msg)
	}
	for _, leak := range []string{b64([]byte(fileDEKID)), b64([]byte("slot0001")), b64([]byte(fileSalt))} {
		if strings.Contains(msg, leak) {
			t.Fatalf("the error carries a value from the header: %q", msg)
		}
	}
}

// --- nothing a default `server run` reaches may write v2 ---

// The create-on-open path is v1 and stays v1 (TestCreateOnOpenStillWritesV1), and this is the
// structural half of the same claim: a sealed file that came from the v1 path carries no data key
// and no rawHeader, so write cannot take the v2 branch at all. There is no input to Open that makes
// a v1 or an absent file produce v2 state.
func TestAV1OpenCarriesNoV2StateSoTheV2WriterIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		path func() string
	}{
		{"an absent file, the create-on-open path", func() string { return filepath.Join(dir, "fresh.bin") }},
		{"an existing v1 file", func() string { return writeV1Vault(t, "pw") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.path()
			v, err := open(t, p, "pw")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if v.file.dek != nil || v.file.rawHeader != nil {
				t.Fatalf("a v1 open left v2 state on the sealed file: dek %d bytes, rawHeader %d bytes",
					len(v.file.dek), len(v.file.rawHeader))
			}
			if err := v.Put(acct("a")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if got := fileMagic(t, p); got != magic {
				t.Fatalf("the write produced magic %q, want %q", got, magic)
			}
		})
	}
}
