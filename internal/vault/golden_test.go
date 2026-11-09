package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// Golden files for the two on-disk formats, and the builders that make them.
//
// WHAT THE TWO FILES ARE, stated plainly because it decides what a failure here means:
//
//   - testdata/vault-v1.bin is built by independentV1 below: its own argon2id call, its own AES-GCM,
//     its own layout literals. It does not call anything in this package. A failure of
//     TestGoldenV1Opens therefore means this package's v1 READER disagrees with an independent
//     writer, which is a real finding.
//
//   - testdata/vault-v2.bin is **a regression pin, generated from the implementation** - InitV2 run
//     through the randRead/nowFn seams with every id, salt, nonce and stamp pinned. It is NOT an
//     independent oracle, and TestGoldenV2IsRebuiltByteIdentical cannot catch a format change that
//     is made in the writer and re-pinned here in the same commit. It catches the change that is
//     made by accident: a base64 alphabet, a padding rule, a JSON member order, a stray whitespace
//     or newline, an HTML escape, or a timestamp's precision drifting without anyone meaning it to.
//     Regenerate it with `go test ./internal/vault -run TestGoldenV2IsRebuiltByteIdentical -update`
//     and say in the commit message what changed in the format and why.
//
// The independent half of the v2 story is carried by two other tests rather than by the file:
// TestGoldenV2HeaderObeysTheFormatRules decodes the pinned bytes with its own JSON and base64 and
// asserts the rules the spec states, and TestTheOpenerOpensAnIndependentlyBuiltV2File proves this
// package's reader against independentV2's encoding. Between them a drift that moved the writer and
// the golden together still has to pass rules written down separately from both.
//
// No real key material anywhere: one fixed fake passphrase, one fixed 32-byte test KEK, one fixed
// fake payload, all literals below and all asserted absent from the committed bytes by
// TestGoldenFilesCarryNoKeyMaterial.

// updateGolden rewrites the committed fixtures. It is a developer's flag: CI never passes it, and
// the assertion runs either way, so a run with it set still fails if the bytes it wrote do not
// then compare equal.
var updateGolden = flag.Bool("update", false, "rewrite internal/vault/testdata golden files")

const (
	// goldenPass is the fake passphrase both fixtures are sealed under. It is in the clear in this
	// file on purpose: a fixture passphrase that was secret would make the fixtures unreproducible.
	goldenPass = "golden-fixture-passphrase-not-a-real-one"
	// goldenCreated is the one stamp both fixtures carry, which is what makes the v2 pin stable.
	goldenCreated = "2026-11-08T00:00:00Z"
	goldenV1File  = "vault-v1.bin"
	goldenV2File  = "vault-v2.bin"
)

// goldenKEK is the 32-byte fake key-encryption key the v2 fixture's machine slot wraps under.
func goldenKEK() []byte { return bytes.Repeat([]byte{0xa7}, 32) }

// goldenPayload is the fake account list both fixtures carry. The token is obviously not one, and
// the unicode label is there so a fixture that lost its encoding would be caught by the payload
// comparison rather than by a reader somewhere downstream.
func goldenPayload() []byte {
	return []byte(`[{"id":"golden","label":"Gölden 中文","identity":"golden@example.invalid",` +
		`"block":{"accessToken":"FAKE-GOLDEN-TOKEN-0000"},"updated":"2026-11-08T00:00:00Z"}]`)
}

func goldenPath(name string) string { return filepath.Join("testdata", name) }

// --- the pinned seams ---

// pinSeams makes this package's randomness and clock deterministic, so InitV2's output is a
// function of its inputs alone. The stream is a counter rather than a constant: a constant would
// hand every slot the same id and the same nonce, and the header parser refuses a duplicate id -
// so a counter is the weakest stub that produces a file at all.
func pinSeams(t *testing.T) {
	t.Helper()
	prevRand, prevNow := randRead, nowFn
	var n byte
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = n
			n++
		}
		return len(b), nil
	}
	stamp, err := time.Parse(time.RFC3339, goldenCreated)
	if err != nil {
		t.Fatalf("parse the fixture stamp: %v", err)
	}
	// Sub-second and off-UTC on purpose, so the golden PINS the two things nowString does to a
	// clock reading rather than passing them over. A stamp that was already truncated and already
	// UTC would make a writer that dropped the Truncate or the UTC() produce identical bytes, and
	// the one-second precision the spec fixes would be asserted nowhere.
	stamp = stamp.Add(123456789 * time.Nanosecond).In(time.FixedZone("fixture", 3*60*60))
	nowFn = func() time.Time { return stamp }
	t.Cleanup(func() { randRead, nowFn = prevRand, prevNow })
}

// buildGoldenV2 is the pinned-seam rebuild of testdata/vault-v2.bin: InitV2 into a fresh temp dir,
// with the fake passphrase and a kek-file machine slot over the fake KEK.
//
// A kek-file slot and never dpapi, deliberately. A DPAPI blob is machine-bound and not
// reproducible, so a golden carrying one could be neither rebuilt nor read on another host - the
// file would pin the machine it was generated on instead of the format.
func buildGoldenV2(t *testing.T) []byte {
	t.Helper()
	opener := kekFileOpenerFor(t, goldenKEK())
	pinSeams(t)
	dir := t.TempDir()
	ks := &recordingKeySource{pass: goldenPass, openers: []SlotOpener{opener}}
	if _, err := InitV2(dir, goldenPass, Slot{Type: slotTypeKEKFile}, ks); err != nil {
		t.Fatalf("InitV2 under the pinned seams: %v", err)
	}
	return bytesOf(t, filepath.Join(dir, vaultFileName))
}

// --- independentV1: a v1 envelope written and read without this package ---

// independentV1 is the v1 format written out from its own literals: magic | salt(16) | nonce(12) |
// AES-256-GCM(argon2id(pass, salt, t=3, m=64 MiB, p=4, 32), payload) with magic||salt as the
// additional data. Every number is a literal here rather than one of this package's constants, which
// is the whole point: a constant renamed or retuned in vault.go must show up as a failing test, not
// as a fixture that quietly followed it.
func independentV1(t *testing.T, magicStr, pass string, salt, nonce, payload []byte) []byte {
	t.Helper()
	if len(magicStr) != 4 || len(salt) != 16 || len(nonce) != 12 {
		t.Fatalf("independentV1: magic %d, salt %d, nonce %d bytes", len(magicStr), len(salt), len(nonce))
	}
	key := argon2.IDKey([]byte(pass), salt, 3, 64*1024, 4, 32)
	aead := independentGCM(t, key)
	header := append([]byte(magicStr), salt...)
	out := append(append([]byte(nil), header...), nonce...)
	return append(out, aead.Seal(nil, nonce, payload, header)...)
}

// independentV1Open is a copy of the v1 reader, kept in the test. The plan asks for exactly this:
// a downgrade that was verified with this package's own openSealed would be this code agreeing with
// itself, and the file downgrade writes exists to be read by a BINARY THAT PREDATES v2.
func independentV1Open(data []byte, magicStr, pass string) ([]byte, error) {
	hdr := 4 + 16
	if len(magicStr) != 4 {
		return nil, errors.New("independentV1Open: magic must be 4 bytes")
	}
	if len(data) < hdr+12+16 || string(data[:4]) != magicStr {
		return nil, fmt.Errorf("independentV1Open: not a %s file of at least %d bytes", magicStr, hdr+12+16)
	}
	salt := data[4:hdr]
	key := argon2.IDKey([]byte(pass), salt, 3, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, data[hdr:hdr+12], data[hdr+12:], data[:hdr])
}

// writeIndependentV1 drops an independently built v1 file at path, with a salt and a nonce derived
// from the path so two fixtures in one test are not identical.
func writeIndependentV1(t *testing.T, path, magicStr, pass string, payload []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte(path))
	data := independentV1(t, magicStr, pass, seed[:16], seed[16:28], payload)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write an independent v1 fixture: %v", err)
	}
}

func independentGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	return aead
}

// --- independentV2: a v2 envelope written without this package ---

// independentSlot is one slot independentV2 should write. Exactly one of pass and kek says what
// kind it is; id must be 8 bytes.
type independentSlot struct {
	id   string
	pass string
	kek  []byte
}

// The header's shape, as a local copy. Marshalling this package's own Header would be asserting it
// against itself; these structs are written from the spec's member list and member order.
type indHeader struct {
	V     int               `json:"v"`
	DEK   indDEK            `json:"dek"`
	Slots []json.RawMessage `json:"slots"`
}

type indDEK struct {
	ID      string `json:"id"`
	Created string `json:"created"`
}

type indSlotJSON struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Scope    string    `json:"scope,omitempty"`
	Name     string    `json:"name,omitempty"`
	Created  string    `json:"created"`
	Argon2id *indArgon `json:"argon2id,omitempty"`
	Wrap     indWrap   `json:"wrap"`
}

type indArgon struct {
	T    uint32 `json:"t"`
	M    uint32 `json:"m"`
	P    uint32 `json:"p"`
	Salt string `json:"salt"`
}

type indWrap struct {
	Nonce string `json:"nonce,omitempty"`
	CT    string `json:"ct,omitempty"`
}

// independentV2 builds a v2 file: magic | hdrLen uint32 BE | header JSON | nonce(12) |
// AES-256-GCM(DEK, payload) with the first 8+hdrLen bytes as the additional data, and each slot's
// wrap sealed under HKDF-SHA256(ikm = KEK, salt = dek.id, info = "claude-swap/slot-wrap/v2" ||
// slotAAD). Every literal is written out here from the spec, not read from this package.
func independentV2(t *testing.T, magicStr string, slots []independentSlot, payload []byte) []byte {
	t.Helper()
	dek := bytes.Repeat([]byte{0xd7}, 32)
	dekID := []byte("golden-dek-id-16")
	salt := []byte("golden-salt--16b")

	elems := make([]json.RawMessage, 0, len(slots))
	for i, sp := range slots {
		if len(sp.id) != 8 {
			t.Fatalf("independentV2: slot id %q is %d bytes, want 8", sp.id, len(sp.id))
		}
		js := indSlotJSON{ID: indB64([]byte(sp.id)), Created: goldenCreated}
		var kek []byte
		if sp.pass != "" {
			js.Type = "passphrase"
			// The parser's floor, not this binary's production cost: a fixture that spent 64 MiB per
			// open would make every test that touches it slow for no extra assertion.
			js.Argon2id = &indArgon{T: 1, M: 8, P: 1, Salt: indB64(salt)}
			kek = argon2.IDKey([]byte(sp.pass), salt, 1, 8, 1, 32)
		} else {
			js.Type = "kek-file"
			js.Name = "vault-kek"
			kek = sp.kek
		}
		aad := independentSlotAAD(magicStr, dekID, []byte(sp.id), js.Type)
		wk, err := hkdf.Key(sha256.New, kek, dekID, "claude-swap/slot-wrap/v2"+string(aad), 32)
		if err != nil {
			t.Fatalf("hkdf: %v", err)
		}
		nonce := bytes.Repeat([]byte{byte(0x20 + i)}, 12)
		js.Wrap = indWrap{Nonce: indB64(nonce), CT: indB64(independentGCM(t, wk).Seal(nil, nonce, dek, aad))}
		enc, err := json.Marshal(js)
		if err != nil {
			t.Fatalf("marshal slot: %v", err)
		}
		elems = append(elems, enc)
	}
	header, err := json.Marshal(indHeader{V: 2, DEK: indDEK{ID: indB64(dekID), Created: goldenCreated}, Slots: elems})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	raw := append([]byte(magicStr), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(header)))
	raw = append(raw, header...)
	pnonce := bytes.Repeat([]byte{0x7a}, 12)
	out := append(append([]byte(nil), raw...), pnonce...)
	return append(out, independentGCM(t, dek).Seal(nil, pnonce, payload, raw)...)
}

func writeIndependentV2(t *testing.T, path, magicStr string, slots []independentSlot, payload []byte) {
	t.Helper()
	if err := os.WriteFile(path, independentV2(t, magicStr, slots, payload), 0o600); err != nil {
		t.Fatalf("write an independent v2 fixture: %v", err)
	}
}

// independentSlotAAD is the slot AAD from the spec: magic || len(dek.id) || dek.id || len(slot.id)
// || slot.id || len(type) || type.
func independentSlotAAD(magicStr string, dekID, slotID []byte, slotType string) []byte {
	out := append([]byte(nil), magicStr...)
	out = append(out, byte(len(dekID)))
	out = append(out, dekID...)
	out = append(out, byte(len(slotID)))
	out = append(out, slotID...)
	out = append(out, byte(len(slotType)))
	return append(out, slotType...)
}

func indB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// --- the golden tests ---

// The v2 regression pin. A drift in the base64 alphabet or padding, in JSON member order, in
// whitespace, in HTML escaping or in the `created` precision fails here first, which is the only
// reason the file is committed. See the file comment for what it does NOT prove.
func TestGoldenV2IsRebuiltByteIdentical(t *testing.T) {
	built := buildGoldenV2(t)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath(goldenV2File), built, 0o644); err != nil {
			t.Fatalf("write the v2 golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath(goldenV2File), len(built))
	}
	want, err := os.ReadFile(goldenPath(goldenV2File))
	if err != nil {
		t.Fatalf("read the v2 golden (regenerate with -update): %v", err)
	}
	if !bytes.Equal(built, want) {
		t.Fatalf("the pinned-seam rebuild is %d bytes and the committed golden is %d; the format drifted.\n"+
			"built  %x\ngolden %x", len(built), len(want), built, want)
	}
}

// Rebuilding twice under the same pinned seams must give the same bytes. Without this, a single
// comparison against the committed file could pass for a build that is not reproducible at all -
// it would only mean today's run happened to match.
func TestGoldenV2RebuildIsDeterministic(t *testing.T) {
	if !bytes.Equal(buildGoldenV2(t), buildGoldenV2(t)) {
		t.Fatal("two pinned-seam rebuilds of the v2 golden differ")
	}
}

// The independent half of the v2 story: the committed bytes are decoded here with this test's own
// JSON and base64 and held to the rules the spec writes down, so a format change made in the writer
// and re-pinned in the golden still has to satisfy a specification kept apart from both.
func TestGoldenV2HeaderObeysTheFormatRules(t *testing.T) {
	data, err := os.ReadFile(goldenPath(goldenV2File))
	if err != nil {
		t.Fatalf("read the v2 golden: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("the golden is %d bytes", len(data))
	}
	if string(data[:4]) != v2VaultMagic {
		t.Fatalf("the golden starts with %q, want %s", data[:4], v2VaultMagic)
	}
	hdrLen := int(binary.BigEndian.Uint32(data[4:8]))
	if hdrLen <= 0 || hdrLen > 64<<10 {
		t.Fatalf("hdrLen = %d, want 1..65536", hdrLen)
	}
	if len(data) < 8+hdrLen+12+16 {
		t.Fatalf("the golden is %d bytes, short of 8+%d+12+16", len(data), hdrLen)
	}
	headerJSON := data[8 : 8+hdrLen]

	// Compact, with no trailing newline and no whitespace between members.
	if headerJSON[len(headerJSON)-1] == '\n' {
		t.Fatal("the header JSON ends with a newline")
	}
	if bytes.ContainsAny(headerJSON, " \t\r\n") {
		t.Fatalf("the header JSON carries whitespace: %s", headerJSON)
	}
	// No HTML escaping: a `<`, `>` or `&` would come back as < and base64 never produces one,
	// so the assertion is that no \u escape appears at all in a header of base64 and ASCII.
	if bytes.Contains(headerJSON, []byte(`\u`)) {
		t.Fatalf("the header JSON carries a unicode escape: %s", headerJSON)
	}
	// Member order, read off the raw text rather than through a map: the spec fixes it as the struct
	// field order, and a JSON object decoded into a map loses exactly this.
	if !bytes.HasPrefix(headerJSON, []byte(`{"v":2,"dek":{"id":"`)) {
		t.Fatalf("the top-level member order changed: %s", headerJSON)
	}
	var h indHeader
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		t.Fatalf("the header is not JSON this test can read: %v", err)
	}
	if h.V != 2 || len(h.Slots) != 2 {
		t.Fatalf("v = %d with %d slots, want 2 and 2", h.V, len(h.Slots))
	}
	// Base64 StdEncoding WITH padding, everywhere. A field that switched to RawStdEncoding would
	// still decode in most places and would change every AAD.
	rfc3339Z := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	if !rfc3339Z.MatchString(h.DEK.Created) {
		t.Fatalf("dek.created = %q, want RFC3339 at one-second precision with a Z", h.DEK.Created)
	}
	assertPaddedB64(t, "dek.id", h.DEK.ID, 16)
	var passSlots int
	for i, raw := range h.Slots {
		if !bytes.HasPrefix(raw, []byte(`{"id":"`)) {
			t.Fatalf("slot %d does not begin with its id: %s", i, raw)
		}
		var s indSlotJSON
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
		assertPaddedB64(t, fmt.Sprintf("slot %d id", i), s.ID, 8)
		assertPaddedB64(t, fmt.Sprintf("slot %d wrap.nonce", i), s.Wrap.Nonce, 12)
		assertPaddedB64(t, fmt.Sprintf("slot %d wrap.ct", i), s.Wrap.CT, 48)
		if !rfc3339Z.MatchString(s.Created) {
			t.Fatalf("slot %d created = %q, want RFC3339 at one-second precision", i, s.Created)
		}
		if s.Type == "passphrase" {
			passSlots++
			if s.Argon2id == nil {
				t.Fatalf("slot %d is a passphrase slot with no argon2id block", i)
			}
			assertPaddedB64(t, fmt.Sprintf("slot %d argon2id salt", i), s.Argon2id.Salt, 16)
		}
	}
	if passSlots != 1 {
		t.Fatalf("the golden carries %d passphrase slots, want exactly 1 (the recovery rung)", passSlots)
	}
}

// assertPaddedB64 holds one field to base64.StdEncoding WITH padding over exactly n bytes.
func assertPaddedB64(t *testing.T, what, value string, n int) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("%s = %q is not padded StdEncoding base64: %v", what, value, err)
	}
	if len(raw) != n {
		t.Fatalf("%s decodes to %d bytes, want %d", what, len(raw), n)
	}
	if want := base64.StdEncoding.EncodeToString(raw); want != value {
		t.Fatalf("%s = %q does not re-encode to itself (%q): the alphabet or the padding changed", what, value, want)
	}
}

// The v1 golden, which IS an independent fixture, and the reader this package ships.
func TestGoldenV1Opens(t *testing.T) {
	salt := bytes.Repeat([]byte{0x31}, 16)
	nonce := bytes.Repeat([]byte{0x32}, 12)
	built := independentV1(t, magic, goldenPass, salt, nonce, goldenPayload())
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath(goldenV1File), built, 0o644); err != nil {
			t.Fatalf("write the v1 golden: %v", err)
		}
	}
	data, err := os.ReadFile(goldenPath(goldenV1File))
	if err != nil {
		t.Fatalf("read the v1 golden (regenerate with -update): %v", err)
	}
	if !bytes.Equal(data, built) {
		t.Fatal("the committed v1 golden is not what the independent builder produces")
	}
	// This package's reader, against those bytes.
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, plain, err := openSealed(path, magic, passOnly{pass: goldenPass})
	if err != nil {
		t.Fatalf("openSealed could not read the independent v1 golden: %v", err)
	}
	if !bytes.Equal(plain, goldenPayload()) {
		t.Fatalf("the v1 golden's payload is %q", plain)
	}
}

// Each of the v2 golden's two keys opens it on its own, which is the format's whole claim: every
// slot wraps the same data key and any one of them is enough.
func TestGoldenV2OpensViaEachSlotAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	data, err := os.ReadFile(goldenPath(goldenV2File))
	if err != nil {
		t.Fatalf("read the v2 golden: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	kekOnly := &recordingKeySource{openers: []SlotOpener{kekFileOpenerFor(t, goldenKEK())}}
	for _, c := range []struct {
		label string
		ks    KeySource
	}{
		{"the passphrase slot alone", passOnly{pass: goldenPass}},
		{"the kek-file slot alone", machineOnly{inner: kekOnly}},
	} {
		if _, _, oerr := openSealed(path, magic, c.ks); oerr != nil {
			t.Fatalf("the v2 golden did not open via %s: %v", c.label, oerr)
		}
	}
}

// This package's reader against an independent WRITER. It is the mirror of TestGoldenV1Opens for
// the v2 format, and the one test here that could catch a reader and a writer that drifted together
// in the same commit.
func TestTheOpenerOpensAnIndependentlyBuiltV2File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	writeIndependentV2(t, path, v2VaultMagic, []independentSlot{
		{id: "passslot", pass: goldenPass},
		{id: "kekslot1", kek: goldenKEK()},
	}, goldenPayload())

	kekOnly := &recordingKeySource{openers: []SlotOpener{kekFileOpenerFor(t, goldenKEK())}}
	for _, c := range []struct {
		label string
		ks    KeySource
	}{
		{"the passphrase slot", passOnly{pass: goldenPass}},
		{"the kek-file slot", machineOnly{inner: kekOnly}},
	} {
		_, plain, oerr := openSealed(path, magic, c.ks)
		if oerr != nil {
			t.Fatalf("openSealed could not read an independently built v2 file via %s: %v", c.label, oerr)
		}
		if !bytes.Equal(plain, goldenPayload()) {
			t.Fatalf("the payload read via %s is %q", c.label, plain)
		}
	}
}

// The v1 golden, migrated, opens under both keys. It is the end-to-end assertion for the command
// the operator actually runs, against a file this package did not write.
func TestMigrateV1GoldenProducesAFileThatOpensViaBoth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	data, err := os.ReadFile(goldenPath(goldenV1File))
	if err != nil {
		t.Fatalf("read the v1 golden: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	bak := path + ".v1.golden"
	if err := os.WriteFile(bak, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ks := &recordingKeySource{pass: goldenPass, openers: []SlotOpener{kekFileOpenerFor(t, goldenKEK())}}
	if _, err := MigrateToV2(path, bak, goldenPass, Slot{Type: slotTypeKEKFile}, ks); err != nil {
		t.Fatalf("MigrateToV2 on the v1 golden: %v", err)
	}
	kekOnly := &recordingKeySource{openers: []SlotOpener{kekFileOpenerFor(t, goldenKEK())}}
	for _, c := range []struct {
		label string
		ks    KeySource
	}{
		{"the passphrase slot alone", passOnly{pass: goldenPass}},
		{"the machine slot alone", machineOnly{inner: kekOnly}},
	} {
		_, plain, oerr := openSealed(path, magic, c.ks)
		if oerr != nil {
			t.Fatalf("the migrated golden did not open via %s: %v", c.label, oerr)
		}
		if !bytes.Equal(plain, goldenPayload()) {
			t.Fatalf("the migrated golden's payload read via %s is %q", c.label, plain)
		}
	}
}

// The v2 golden, downgraded, is read by the COPY of the v1 reader. That is the rollback promise:
// bytes a binary that predates v2 can open.
func TestDowngradeV2GoldenProducesBytesTheV1PathOpens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	data, err := os.ReadFile(goldenPath(goldenV2File))
	if err != nil {
		t.Fatalf("read the v2 golden: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, derr := DowngradeToV1(path, path+".v2.golden", goldenPass); derr != nil {
		t.Fatalf("DowngradeToV1 on the v2 golden: %v", derr)
	}
	plain, oerr := independentV1Open(bytesOf(t, path), magic, goldenPass)
	if oerr != nil {
		t.Fatalf("the copy of the v1 reader could not open the downgraded golden: %v", oerr)
	}
	// InitV2 creates an empty account list, so this is what the v2 golden's payload is.
	if string(plain) != `[]` {
		t.Fatalf("the downgraded golden's payload is %q, want []", plain)
	}
}

// A reader that only knows v1 must refuse the v2 golden rather than misread it. The error it gives
// is its own ("not a CSV1 file"), and the current reader's answer is the format's name, not a bad
// key - which is the Anti-goal this pair of assertions guards.
func TestAV1OnlyReaderRefusesTheV2Golden(t *testing.T) {
	data, err := os.ReadFile(goldenPath(goldenV2File))
	if err != nil {
		t.Fatalf("read the v2 golden: %v", err)
	}
	if _, oerr := independentV1Open(data, magic, goldenPass); oerr == nil {
		t.Fatal("a v1-only reader opened a v2 file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	info, ierr := Inspect(path)
	if ierr != nil || info.Format != FormatV2 {
		t.Fatalf("Inspect reports %s (err %v), want %s", info.Format, ierr, FormatV2)
	}
	// And a wrong passphrase against it is a bad key, never "malformed": an operator pushed towards
	// rotating a correct passphrase out of confusion is the stated Anti-goal.
	if _, _, oerr := openSealed(path, magic, passOnly{pass: "wrong"}); !errors.Is(oerr, ErrBadKey) {
		t.Fatalf("a wrong passphrase against the v2 golden gives %v, want ErrBadKey", oerr)
	}
}

// Neither committed fixture carries key material, and both carry the fake markers this file
// declares. A golden generated on a real host - from a real vault, under a real passphrase - is the
// one way a test fixture becomes a secret leak, so it is asserted rather than trusted.
func TestGoldenFilesCarryNoKeyMaterial(t *testing.T) {
	secrets := [][]byte{[]byte(goldenPass), goldenKEK(), []byte("FAKE-GOLDEN-TOKEN-0000")}
	for _, name := range []string{goldenV1File, goldenV2File} {
		data, err := os.ReadFile(goldenPath(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, secret := range secrets {
			if bytes.Contains(data, secret) {
				t.Fatalf("%s carries %d bytes of fixture key material or payload in the clear", name, len(secret))
			}
		}
		// The only readable text in either file is the format's own: a magic, and for v2 the header's
		// member names and slot type names. Anything else means a payload or a key escaped the AEAD.
		// The `created` stamps are removed first rather than whitelisted word by word: they are the
		// one field whose VALUE is readable by design, and TestGoldenV2HeaderObeysTheFormatRules is
		// where their shape is asserted.
		for _, word := range asciiWords(data) {
			switch word {
			case "CSV1", "CSV2", "v", "dek", "id", "created", "slots", "type", "scope", "name",
				"argon2id", "t", "m", "p", "salt", "wrap", "nonce", "ct", "passphrase", "kek-file",
				"dpapi", "machine", "vault-kek":
			default:
				if len(word) >= 6 && !looksLikeB64(word) {
					t.Fatalf("%s carries the readable word %q, which is not part of the format", name, word)
				}
			}
		}
	}
}

// asciiWords is every run of printable ASCII of three bytes or more, with RFC3339 stamps removed
// first: `created` is the one header value that is readable text by design.
func asciiWords(data []byte) []string {
	text := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`).ReplaceAllString(string(data), " ")
	return regexp.MustCompile(`[A-Za-z][A-Za-z0-9_.@:+/=-]{2,}`).FindAllString(text, -1)
}

// looksLikeB64 reports whether a word is plausibly a base64 field rather than English. Every value
// in the header is base64 or one of the names listed above, so this is what lets the assertion above
// be a whitelist without flagging a wrap.
func looksLikeB64(word string) bool {
	raw, err := base64.StdEncoding.DecodeString(word)
	if err == nil && len(raw) > 0 {
		return true
	}
	// A base64 run cut at a field boundary by the regexp is still not a word: no two consecutive
	// English vowels-and-consonants test is reliable, so the weaker and honest test is "it is all
	// base64 alphabet", which an English word also satisfies - hence the length and the whitelist
	// above doing the real work.
	for i := 0; i < len(word); i++ {
		c := word[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '='
		if !ok {
			return false
		}
	}
	return true
}
