package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the v2 header: its byte-exact encoding, and the bounds that are checked on every
// attacker-controlled integer in it before a single allocation. The header is not authenticated
// until the payload opens, and a `passphrase` slot's argon2id cost is read before any key exists
// to authenticate it with, so every number in here is hostile input by construction.

// goldenHeader is the committed byte-exact v2 header. One optional trailing newline is trimmed on
// load: nothing this package writes has one (TestHeaderBytesHaveNoTrailingNewline pins that), but a
// checkout filter or an editor that appends one must not turn the round-trip test red for a reason
// that has nothing to do with the encoder.
func goldenHeader(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "header-golden.json"))
	if err != nil {
		t.Fatalf("golden: %v", err)
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) == 0 || data[0] != '{' || data[len(data)-1] != '}' {
		t.Fatalf("golden is not a bare JSON object: %d bytes", len(data))
	}
	return data
}

// v2File assembles a complete v2 file around a header: the magic, the big-endian header length,
// the header bytes as given, then a nonce and a tag-sized payload. The payload is zeros and opens
// for nobody, which is the point: every test here is about the header, and a parse that reaches
// the payload has already told us what we wanted to know.
func v2File(magicStr string, header []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(magicStr)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(header)))
	buf.Write(n[:])
	buf.Write(header)
	buf.Write(make([]byte, nonceLen+gcmTagLen))
	return buf.Bytes()
}

// writeV2 drops a v2 file in dir and returns its path.
func writeV2(t *testing.T, dir, name, magicStr string, header []byte) string {
	t.Helper()
	return writeFixture(t, dir, name, v2File(magicStr, header))
}

// noArgon2 replaces the argon2id seam with one that fails the test if it is ever entered, and
// restores it afterwards. A header claiming m = 1 TiB must be refused on the parsed integer, not
// by the allocator inside the derivation.
func noArgon2(t *testing.T) {
	t.Helper()
	prev := argon2IDKey
	argon2IDKey = func(_, _ []byte, _, _ uint32, _ uint8, _ uint32) []byte {
		t.Fatal("argon2id was entered: the header's parameters reached the derivation")
		return nil
	}
	t.Cleanup(func() { argon2IDKey = prev })
}

// --- encoding ---

func TestHeaderRoundTripIsByteIdentical(t *testing.T) {
	golden := goldenHeader(t)
	h, slots, err := parseHeader(golden)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if len(slots) != 3 {
		t.Fatalf("got %d slots, want 3", len(slots))
	}
	out, err := marshalHeader(h, nil)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if !bytes.Equal(golden, out) {
		t.Fatalf("round trip changed the bytes:\n golden %s\n got    %s", golden, out)
	}
}

func TestHeaderBytesHaveNoTrailingNewline(t *testing.T) {
	h, _, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	out, err := marshalHeader(h, nil)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if out[len(out)-1] != '}' {
		t.Fatalf("last byte is %q, want '}': json.Encoder's newline was not trimmed", out[len(out)-1])
	}
	if bytes.Contains(out, []byte("\n")) {
		t.Fatalf("the header carries a newline: %s", out)
	}
}

func TestHeaderMemberOrderIsFixed(t *testing.T) {
	h, _, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	out, err := marshalHeader(h, nil)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	s := string(out)
	// Top level, then the dek's two members, then one slot of each type in the order the spec's
	// example shows. Index comparisons, not a substring of the whole header: a member in the wrong
	// place has to move the ordering, not merely appear somewhere.
	for _, seq := range [][]string{
		{`{"v":2,`, `"dek":{`, `"slots":[`},
		{`"dek":{"id":"`, `","created":"`},
		{`{"id":"EBESExQVFhc=","type":"passphrase","created":"`, `","argon2id":{"t":`, `"m":`, `"p":`, `"salt":"`, `"wrap":{"nonce":"`, `","ct":"`},
		{`"type":"dpapi","scope":"machine","created":"`, `"wrap":{"blob":"`},
		{`"type":"kek-file","name":"vault-kek","created":"`},
	} {
		at := -1
		for _, want := range seq {
			i := strings.Index(s[at+1:], want)
			if i < 0 {
				t.Fatalf("header does not contain %q in order: %s", want, s)
			}
			at += 1 + i
		}
	}
}

func TestHeaderBase64IsStdEncodingWithPadding(t *testing.T) {
	golden := goldenHeader(t)
	h, slots, err := parseHeader(golden)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	// StdEncoding with padding, not RawStdEncoding: a 16-byte id is 24 characters ending in "==".
	if !strings.HasSuffix(h.DEK.ID, "==") || len(h.DEK.ID) != 24 {
		t.Fatalf("dek.id %q is not padded StdEncoding of 16 bytes", h.DEK.ID)
	}
	if got, err := base64.StdEncoding.DecodeString(slots[0].Argon2id.Salt); err != nil || len(got) != saltLen {
		t.Fatalf("salt decode: %v len=%d", err, len(got))
	}
	// The same 16 bytes in RawStdEncoding must not be accepted: one decoder, one alphabet.
	raw := base64.RawStdEncoding.EncodeToString(make([]byte, dekIDLen))
	hdr := bytes.Replace(golden, []byte(h.DEK.ID), []byte(raw), 1)
	if _, _, err := parseHeader(hdr); !errors.Is(err, errCorrupt) {
		t.Fatalf("RawStdEncoding dek.id accepted: want errCorrupt, got %v", err)
	}
}

func TestHeaderEscapesNoHTML(t *testing.T) {
	h, slots, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	s := slots[2]
	s.Name = "a<&>b"
	out, err := marshalHeader(h, map[string]Slot{s.ID: s})
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if !bytes.Contains(out, []byte(`"name":"a<&>b"`)) {
		t.Fatalf("SetEscapeHTML(false) is not in force: %s", out)
	}
	if bytes.Contains(out, []byte(`\u00`)) {
		t.Fatalf("the header carries an escaped character: %s", out)
	}
}

func TestHeaderCreatedIsRFC3339SecondsUTC(t *testing.T) {
	prev := nowFn
	nowFn = func() time.Time {
		// A non-UTC instant with a fraction, so a writer that forgot either conversion shows up.
		return time.Date(2026, 11, 7, 7, 0, 0, 500_000_000, time.FixedZone("EST", -5*60*60))
	}
	t.Cleanup(func() { nowFn = prev })
	got := nowString()
	if got != "2026-11-07T12:00:00Z" {
		t.Fatalf("nowString = %q, want 2026-11-07T12:00:00Z", got)
	}
	if strings.ContainsAny(got, ".+") {
		t.Fatalf("created %q carries a fraction or an offset", got)
	}
}

// --- the payload AAD is the bytes on disk, never a re-marshal ---

func TestRawHeaderIsTheFirstEightPlusHdrLenBytesOfTheFile(t *testing.T) {
	golden := goldenHeader(t)
	file := v2File(v2VaultMagic, golden)
	aad, headerJSON, err := rawHeaderOf(file)
	if err != nil {
		t.Fatalf("rawHeaderOf: %v", err)
	}
	if len(aad) != v2PrefixLen+len(golden) {
		t.Fatalf("aad is %d bytes, want %d", len(aad), v2PrefixLen+len(golden))
	}
	if !bytes.Equal(aad, file[:v2PrefixLen+len(golden)]) {
		t.Fatalf("aad is not the file's first 8 + hdrLen bytes")
	}
	if !bytes.Equal(headerJSON, golden) {
		t.Fatalf("header JSON is not the committed golden:\n got %s", headerJSON)
	}
	// The magic and the length are inside the AAD, so a slot or a payload cannot be moved between
	// a vault and a keyring, or have its header silently truncated.
	if string(aad[:4]) != v2VaultMagic {
		t.Fatalf("the magic is not in the AAD: %q", aad[:4])
	}
	if got := binary.BigEndian.Uint32(aad[4:8]); got != uint32(len(golden)) {
		t.Fatalf("hdrLen in the AAD is %d, want %d", got, len(golden))
	}
	// A header that a lossless parse-then-marshal would reproduce is still not where the AAD comes
	// from: the bytes are a slice of the file, so a one-byte edit anywhere in the header moves it.
	edited := append([]byte(nil), file...)
	edited[v2PrefixLen+1] = 'V'
	again, _, err := rawHeaderOf(edited)
	if err != nil {
		t.Fatalf("rawHeaderOf on the edited file: %v", err)
	}
	if bytes.Equal(aad, again) {
		t.Fatal("editing the header did not change the AAD")
	}
}

// --- bounds, all of them before an allocation ---

func TestHeaderParamBoundsRejectedBeforeAllocation(t *testing.T) {
	golden := string(goldenHeader(t))
	// The passphrase slot's text, lifted from the golden so the repeated-slot cases encode exactly
	// what the single-slot case does.
	const oneSlot = `{"id":"EBESExQVFhc=","type":"passphrase","created":"2026-11-07T12:00:00Z",` +
		`"argon2id":{"t":3,"m":65536,"p":4,"salt":"QEFCQ0RFRkdISUpLTE1OTw=="},` +
		`"wrap":{"nonce":"UFFSU1RVVldYWVpb","ct":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"}}`
	if !strings.Contains(golden, oneSlot) {
		t.Fatalf("the golden no longer contains the slot this table repeats")
	}
	repeat := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = oneSlot
		}
		return strings.Replace(golden, `"slots":[`+oneSlot, `"slots":[`+strings.Join(parts, ","), 1)
	}
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"t below the floor", strings.Replace(golden, `"t":3`, `"t":0`, 1)},
		{"t above the ceiling", strings.Replace(golden, `"t":3`, `"t":11`, 1)},
		{"p below the floor", strings.Replace(golden, `"p":4`, `"p":0`, 1)},
		{"p above the ceiling", strings.Replace(golden, `"p":4`, `"p":17`, 1)},
		{"m below the floor", strings.Replace(golden, `"m":65536`, `"m":7`, 1)},
		{"m above the ceiling", strings.Replace(golden, `"m":65536`, `"m":1048577`, 1)},
		{"m claiming four terabytes", strings.Replace(golden, `"m":65536`, `"m":4294967295`, 1)},
		{"seventeen slots", repeat(17)},
		{"nine passphrase slots", repeat(9)},
		{"salt of fifteen bytes", strings.Replace(golden,
			`"salt":"QEFCQ0RFRkdISUpLTE1OTw=="`,
			`"salt":"`+base64.StdEncoding.EncodeToString(make([]byte, 15))+`"`, 1)},
		{"salt of seventeen bytes", strings.Replace(golden,
			`"salt":"QEFCQ0RFRkdISUpLTE1OTw=="`,
			`"salt":"`+base64.StdEncoding.EncodeToString(make([]byte, 17))+`"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.header == golden {
				t.Fatalf("the case did not change the golden header")
			}
			noArgon2(t)
			if _, _, err := parseHeader([]byte(tc.header)); !errors.Is(err, errCorrupt) {
				t.Fatalf("parseHeader: want errCorrupt, got %v", err)
			}
			// The same answer through the reader an operator actually reaches, and never
			// ErrBadKey: a crafted header must not push anyone towards rotating a correct
			// passphrase. ErrMalformed is the exported face of errCorrupt and is what
			// cmd/server maps to exit 4.
			p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, []byte(tc.header))
			_, err := open(t, p, "pw")
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Open: want ErrMalformed, got %v", err)
			}
			if errors.Is(err, ErrBadKey) {
				t.Fatalf("Open also reports a bad key: %v", err)
			}
		})
	}
}

func TestHdrLenOver64KiBIsErrCorruptWithNoAllocation(t *testing.T) {
	noArgon2(t)
	// The 40-byte file says its header is a megabyte long. Nothing may be sized from that number.
	data := append([]byte(nil), v2Fixture(t)...)
	binary.BigEndian.PutUint32(data[4:8], 1<<20)
	p := writeFixture(t, t.TempDir(), "vault.bin", data)
	if _, err := open(t, p, "pw"); !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
	// Exactly one past the cap is still refused, so the comparison is not off by one.
	ok := v2File(v2VaultMagic, bytes.Repeat([]byte("x"), 1))
	binary.BigEndian.PutUint32(ok[4:8], maxHdrLen+1)
	p2 := writeFixture(t, t.TempDir(), "vault.bin", ok)
	if _, err := open(t, p2, "pw"); !errors.Is(err, errCorrupt) {
		t.Fatalf("hdrLen = maxHdrLen+1: want errCorrupt, got %v", err)
	}
}

func TestFileShorterThanMinimumIsErrCorrupt(t *testing.T) {
	noArgon2(t)
	golden := goldenHeader(t)
	full := v2File(v2VaultMagic, golden)
	if want := 8 + len(golden) + nonceLen + gcmTagLen; len(full) != want {
		t.Fatalf("the assembled file is %d bytes, want %d", len(full), want)
	}
	// One byte short of 8 + hdrLen + 12 + 16 is refused; the full length gets past the header.
	short := full[:len(full)-1]
	p := writeFixture(t, t.TempDir(), "vault.bin", short)
	if _, err := open(t, p, "pw"); !errors.Is(err, errCorrupt) {
		t.Fatalf("one byte short: want errCorrupt, got %v", err)
	}
	p2 := writeFixture(t, t.TempDir(), "vault.bin", full)
	if _, err := open(t, p2, "pw"); errors.Is(err, errCorrupt) {
		t.Fatalf("a well-formed v2 header reports as malformed: %v", err)
	}
}

// --- the closed top level ---

func TestClosedTopLevelHeader(t *testing.T) {
	golden := string(goldenHeader(t))
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"a newer version", strings.Replace(golden, `{"v":2,`, `{"v":3,`, 1)},
		{"an extra member", strings.Replace(golden, `{"v":2,`, `{"v":2,"x":1,`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noArgon2(t)
			if _, _, err := parseHeader([]byte(tc.header)); !errors.Is(err, ErrNewerFormat) {
				t.Fatalf("parseHeader: want ErrNewerFormat, got %v", err)
			}
			// Never also malformed: "malformed vault file" sends an operator looking for a corrupt
			// disk or a wrong passphrase, and this file is neither.
			p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, []byte(tc.header))
			err := func() error { _, e := open(t, p, "pw"); return e }()
			if !errors.Is(err, ErrNewerFormat) {
				t.Fatalf("Open: want ErrNewerFormat, got %v", err)
			}
			if errors.Is(err, errCorrupt) {
				t.Fatalf("also reports as malformed: %v", err)
			}
		})
	}
	// A `v` that is not a number at all is malformed, not newer: this binary cannot say which
	// version wrote a header whose version field is a string.
	bad := strings.Replace(golden, `{"v":2,`, `{"v":"two",`, 1)
	if _, _, err := parseHeader([]byte(bad)); !errors.Is(err, errCorrupt) {
		t.Fatalf(`"v":"two": want errCorrupt, got %v`, err)
	}
}

// --- decoded lengths and the created stamp ---

func TestDecodedLengthMismatchIsErrCorrupt(t *testing.T) {
	golden := string(goldenHeader(t))
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"dek.id of fifteen bytes", strings.Replace(golden,
			`"id":"AAECAwQFBgcICQoLDA0ODw=="`,
			`"id":"`+base64.StdEncoding.EncodeToString(make([]byte, 15))+`"`, 1)},
		{"dek.id of seventeen bytes", strings.Replace(golden,
			`"id":"AAECAwQFBgcICQoLDA0ODw=="`,
			`"id":"`+base64.StdEncoding.EncodeToString(make([]byte, 17))+`"`, 1)},
		{"slot.id of nine bytes", strings.Replace(golden,
			`"id":"EBESExQVFhc="`,
			`"id":"`+base64.StdEncoding.EncodeToString(make([]byte, 9))+`"`, 1)},
		{"wrap.nonce of eleven bytes", strings.Replace(golden,
			`"nonce":"UFFSU1RVVldYWVpb"`,
			`"nonce":"`+base64.StdEncoding.EncodeToString(make([]byte, 11))+`"`, 1)},
		{"wrap.ct of forty-seven bytes", strings.Replace(golden,
			`"ct":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"`,
			`"ct":"`+base64.StdEncoding.EncodeToString(make([]byte, 47))+`"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noArgon2(t)
			if tc.header == golden {
				t.Fatalf("the case did not change the golden header")
			}
			if _, _, err := parseHeader([]byte(tc.header)); !errors.Is(err, errCorrupt) {
				t.Fatalf("want errCorrupt, got %v", err)
			}
		})
	}
}

func TestUnparseableCreatedIsRejectedNotTrusted(t *testing.T) {
	noArgon2(t)
	golden := string(goldenHeader(t))
	for _, tc := range []struct{ name, header string }{
		{"the dek's stamp", strings.Replace(golden,
			`"dek":{"id":"AAECAwQFBgcICQoLDA0ODw==","created":"2026-11-07T12:00:00Z"}`,
			`"dek":{"id":"AAECAwQFBgcICQoLDA0ODw==","created":"not a date"}`, 1)},
		{"a slot's stamp", strings.Replace(golden,
			`"type":"passphrase","created":"2026-11-07T12:00:00Z"`,
			`"type":"passphrase","created":"not a date"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.header == golden {
				t.Fatalf("the case did not change the golden header")
			}
			if _, _, err := parseHeader([]byte(tc.header)); !errors.Is(err, errCorrupt) {
				t.Fatalf("want errCorrupt, got %v", err)
			}
		})
	}
}

func TestFutureCreatedOpensButIsNeverUsedForOrdering(t *testing.T) {
	golden := string(goldenHeader(t))
	// The passphrase slot claims it was made a century from now. A reader that sorted slots by
	// their stamp would try it first; the try order is fixed by slot kind, so nothing moves.
	future := time.Now().UTC().AddDate(100, 0, 0).Truncate(time.Second).Format(time.RFC3339)
	hdr := strings.Replace(golden,
		`"type":"passphrase","created":"2026-11-07T12:00:00Z"`,
		`"type":"passphrase","created":"`+future+`"`, 1)
	if hdr == golden {
		t.Fatal("the future stamp did not change the golden header")
	}
	_, slots, err := parseHeader([]byte(hdr))
	if err != nil {
		t.Fatalf("a future stamp must still open: %v", err)
	}
	var got []string
	for _, s := range tryOrder(slots) {
		got = append(got, s.Type)
	}
	// Machine slots first, passphrase last: the service has no passphrase and must succeed on a
	// machine slot, and an operator's passphrase must not be spent on a slot that was going to work.
	want := []string{"dpapi", "kek-file", "passphrase"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("try order %v, want %v", got, want)
	}
}

// --- the write path is untouched by this change ---

// A v1 vault still writes v1 through every mutator. Nothing in this binary may write a v2 file:
// `vault init` is the only v2 creator (Task 3b.3), and until it lands a data dir that was v1 stays
// v1 byte for byte at the magic. This is a permanent assertion, not a temporary one.
func TestV1VaultStillWritesV1AfterEveryMutator(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	magicOnDisk := func(t *testing.T, what string) {
		t.Helper()
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: read: %v", what, err)
		}
		if got := string(data[:len(magic)]); got != magic {
			t.Fatalf("%s wrote magic %q, want %q", what, got, magic)
		}
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	magicOnDisk(t, "Put")
	if err := v.Put(acct("b")); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	if err := v.ReplaceBlock("a", json.RawMessage(`{"accessToken":"x"}`), time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("ReplaceBlock: %v", err)
	}
	magicOnDisk(t, "ReplaceBlock")
	if err := v.Delete("b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	magicOnDisk(t, "Delete")
	// The .bak Delete left behind is the same v1 envelope, so the same passphrase opens it.
	bak, err := os.ReadFile(p + bakSuffix)
	if err != nil {
		t.Fatalf("bak: %v", err)
	}
	if got := string(bak[:len(magic)]); got != magic {
		t.Fatalf("the backup is magic %q, want %q", got, magic)
	}
	if _, err := open(t, p, "pw"); err != nil {
		t.Fatalf("reopen after the mutators: %v", err)
	}
}

func TestV1KeyringStillWritesCSK1AfterThisChange(t *testing.T) {
	t.Setenv(keyEnv, "pw")
	p := filepath.Join(t.TempDir(), KeyringFileName)
	k, err := OpenKeyring(p, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if _, err := k.Generate("h1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(data[:len(keyringMagic)]); got != keyringMagic {
		t.Fatalf("keyring magic %q, want %q", got, keyringMagic)
	}
}
