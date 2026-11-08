package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/logx"
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

// argon2Seam replaces the derivation with one that counts its calls and returns a fixed key
// without doing any work, and hands back the counter. A stub that *panicked* would be no stronger:
// what makes a count of zero mean anything is that the same seam, in the same test binary, is
// provably entered by the v1 path - TestTheArgon2idSeamIsEnteredByTheV1Path asserts exactly that.
// Without it, "the derivation was never entered" is a claim about a function nothing ever calls.
//
// The stub does not call the real argon2id: a header claiming m = 1 TiB must be refused on the
// parsed integer, and a stub that delegated would allocate the machine to prove it.
func argon2Seam(t *testing.T) *int {
	t.Helper()
	calls := 0
	prev := argon2IDKey
	argon2IDKey = func(_, _ []byte, _, _ uint32, _ uint8, _ uint32) []byte {
		calls++
		return bytes.Repeat([]byte{0x5a}, keyLen)
	}
	t.Cleanup(func() { argon2IDKey = prev })
	return &calls
}

// noArgon2 installs the seam and asserts, at cleanup, that it was never entered. The assertion is
// explicit and runs before the restore (t.Cleanup is LIFO), so it reads the counter this test set.
func noArgon2(t *testing.T) {
	t.Helper()
	calls := argon2Seam(t)
	t.Cleanup(func() {
		if *calls != 0 {
			t.Fatalf("argon2id was entered %d times: the header's parameters reached the derivation", *calls)
		}
	})
}

// The positive control for the seam above. It is the whole reason a zero count is evidence: the
// v1 open path derives a key from the passphrase (sealed.go, deriveAEAD), so the seam is on a live
// call site. If a refactor moves the derivation off argon2IDKey, this test goes red and every
// "never entered" assertion in this file is correctly exposed as vacuous.
func TestTheArgon2idSeamIsEnteredByTheV1Path(t *testing.T) {
	calls := argon2Seam(t)
	p := filepath.Join(t.TempDir(), "vault.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := open(t, p, "pw"); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if *calls == 0 {
		t.Fatal("the seam was never entered on the v1 path: a zero count anywhere else proves nothing")
	}
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
	// The golden's own dek.id bytes, re-encoded without padding, must not be accepted: one decoder,
	// one alphabet. The same *value*, deliberately - encoding zeros instead would also change the
	// bytes, and the test would then pass whether the padding or the value was what was refused.
	id, err := base64.StdEncoding.DecodeString(h.DEK.ID)
	if err != nil {
		t.Fatalf("dek.id decode: %v", err)
	}
	raw := base64.RawStdEncoding.EncodeToString(id)
	if raw == h.DEK.ID {
		t.Fatalf("RawStdEncoding of dek.id is identical to StdEncoding: %q", raw)
	}
	if base64.StdEncoding.EncodeToString(id) != h.DEK.ID {
		t.Fatalf("the golden's dek.id is not StdEncoding of its own bytes")
	}
	hdr := bytes.Replace(golden, []byte(h.DEK.ID), []byte(raw), 1)
	if _, _, err := parseHeader(hdr); !errors.Is(err, errCorrupt) {
		t.Fatalf("unpadded dek.id of the right value accepted: want errCorrupt, got %v", err)
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
	// The passphrase and dpapi slot texts, lifted from the golden so the two cap cases encode
	// exactly what the single-slot case does.
	const passSlot = `{"id":"EBESExQVFhc=","type":"passphrase","created":"2026-11-07T12:00:00Z",` +
		`"argon2id":{"t":3,"m":65536,"p":4,"salt":"QEFCQ0RFRkdISUpLTE1OTw=="},` +
		`"wrap":{"nonce":"UFFSU1RVVldYWVpb","ct":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"}}`
	const dpapiSlot = `{"id":"ICEiIyQlJic=","type":"dpapi","scope":"machine",` +
		`"created":"2026-11-07T12:00:00Z","wrap":{"blob":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3w=="}}`
	for _, s := range []string{passSlot, dpapiSlot} {
		if !strings.Contains(golden, s) {
			t.Fatalf("the golden no longer contains the slot this table repeats: %s", s)
		}
	}
	// withSlots replaces the whole slots array rather than prepending to it, so each cap case
	// carries exactly the slots it names. Keeping the golden's other two slots on the end would
	// make "nine passphrase slots" an eleven-slot header, and the slot cap and the passphrase cap
	// would then be indistinguishable: whichever fired first would pass the case.
	head := `"slots":[`
	prefix := golden[:strings.Index(golden, head)+len(head)]
	withSlots := func(parts ...string) string {
		return prefix + strings.Join(parts, ",") + "]}"
	}
	// Each copy gets its own id. Distinct ids on purpose: slot ids are unique within a header
	// (TestDuplicateSlotIDIsErrMalformed), so n copies of one literal would be refused as
	// duplicates and every cap case below - and both positive controls - would answer for the
	// wrong reason, which is the same trap the comment above withSlots describes.
	repeatSlot := func(s string, n int) []string {
		at := strings.Index(s, `","type":"`)
		if !strings.HasPrefix(s, `{"id":"`) || at < 0 {
			t.Fatalf("the slot text no longer starts with an id: %s", s)
		}
		parts := make([]string, n)
		for i := range parts {
			id := base64.StdEncoding.EncodeToString([]byte{byte(i), 1, 2, 3, 4, 5, 6, 7})
			parts[i] = `{"id":"` + id + s[at:]
		}
		return parts
	}
	// Seventeen slots with one passphrase among them: only the slot cap can refuse this.
	overSlotCap := withSlots(append([]string{passSlot}, repeatSlot(dpapiSlot, maxSlots)...)...)
	// Nine slots, all passphrase: under the slot cap, so only the passphrase cap can refuse it.
	overPassCap := withSlots(repeatSlot(passSlot, maxPassphraseSlots+1)...)
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
		{"seventeen slots, one of them a passphrase", overSlotCap},
		{"nine slots, every one a passphrase", overPassCap},
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
	// The positive controls for the two caps. Without them the cases above would pass just as well
	// against a parser that refused every slot array, and the caps could sit one short.
	t.Run("sixteen slots is accepted", func(t *testing.T) {
		h := withSlots(append([]string{passSlot}, repeatSlot(dpapiSlot, maxSlots-1)...)...)
		_, slots, err := parseHeader([]byte(h))
		if err != nil {
			t.Fatalf("a header at the slot cap was refused: %v", err)
		}
		if len(slots) != maxSlots {
			t.Fatalf("got %d slots, want %d", len(slots), maxSlots)
		}
	})
	t.Run("eight passphrase slots is accepted", func(t *testing.T) {
		h := withSlots(repeatSlot(passSlot, maxPassphraseSlots)...)
		_, slots, err := parseHeader([]byte(h))
		if err != nil {
			t.Fatalf("a header at the passphrase cap was refused: %v", err)
		}
		if len(slots) != maxPassphraseSlots {
			t.Fatalf("got %d slots, want %d", len(slots), maxPassphraseSlots)
		}
	})
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
	// The counting seam rather than noArgon2, because the second half of this test opens a header
	// that PARSES, and the open flow now reaches its passphrase slot and derives a key from it -
	// which is the correct behaviour since the slot walk landed. The stub keeps the real derivation
	// out of the test's runtime; the "never entered" assertion belongs to the malformed-header
	// cases, which TestHeaderParamBoundsRejectedBeforeAllocation and
	// TestHdrLenOver64KiBIsErrCorruptWithNoAllocation own.
	argon2Seam(t)
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
	_, err := open(t, p2, "pw")
	if errors.Is(err, errCorrupt) {
		t.Fatalf("a well-formed v2 header reports as malformed: %v", err)
	}
	// The passphrase here is wrong and the key source is EnvKey, whose Machine is nil, so the one
	// slot anything could be handed a key for is the passphrase one: ErrBadKey, naming that kind and
	// counting the two machine slots this host held no key for. An id, a salt, a nonce or a wrapped
	// key in that string would be a value in an error message.
	if !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey for a parseable v2 header, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "slot types tried: passphrase; 2 this host held no key for") {
		t.Fatalf("the error does not name what was tried and count what was not: %q", msg)
	}
	if strings.Contains(msg, slotTypeDPAPI) || strings.Contains(msg, slotTypeKEKFile) {
		t.Fatalf("the error names a machine kind EnvKey offers no opener for: %q", msg)
	}
	for _, leak := range []string{
		"EBESExQVFhc=", "ICEiIyQlJic=", "MDEyMzQ1Njc=", // slot ids
		"QEFCQ0RFRkdISUpLTE1OTw==", "UFFSU1RVVldYWVpb", // salt, nonce
		"AAECAwQFBgcICQoLDA0ODw==", "vault-kek", "pw", // dek id, credential name, passphrase
	} {
		if strings.Contains(msg, leak) {
			t.Fatalf("the error carries %q: %q", leak, msg)
		}
	}
}

// The accept side of every bound, at both ends. Without these the rejection table above would pass
// just as well against a parser that refused every value, and each bound could sit one short of
// where the format states it.
func TestHeaderParamBoundsAcceptBothEnds(t *testing.T) {
	golden := string(goldenHeader(t))
	for _, tc := range []struct{ name, header string }{
		{"t at the floor", strings.Replace(golden, `"t":3`, `"t":1`, 1)},
		{"t at the ceiling", strings.Replace(golden, `"t":3`, `"t":10`, 1)},
		{"p at the floor", strings.Replace(golden, `"p":4`, `"p":1`, 1)},
		{"p at the ceiling", strings.Replace(golden, `"p":4`, `"p":16`, 1)},
		{"m at the floor", strings.Replace(golden, `"m":65536`, `"m":8`, 1)},
		{"m at the ceiling", strings.Replace(golden, `"m":65536`, `"m":1048576`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noArgon2(t)
			if tc.header == golden {
				t.Fatalf("the case did not change the golden header")
			}
			if _, _, err := parseHeader([]byte(tc.header)); err != nil {
				t.Fatalf("a value at the bound was refused: %v", err)
			}
		})
	}
	// The other end of TestHdrLenOver64KiBIsErrCorruptWithNoAllocation's off-by-one pair: exactly
	// maxHdrLen is accepted, so the cap is `>` and not `>=`. The header's content is junk - this is
	// rawHeaderOf's bound, which is checked before anything is parsed.
	t.Run("hdrLen exactly at the cap", func(t *testing.T) {
		noArgon2(t)
		file := v2File(v2VaultMagic, bytes.Repeat([]byte("x"), maxHdrLen))
		aad, headerJSON, err := rawHeaderOf(file)
		if err != nil {
			t.Fatalf("hdrLen = maxHdrLen was refused: %v", err)
		}
		if len(aad) != v2PrefixLen+maxHdrLen || len(headerJSON) != maxHdrLen {
			t.Fatalf("aad %d bytes and header %d bytes, want %d and %d",
				len(aad), len(headerJSON), v2PrefixLen+maxHdrLen, maxHdrLen)
		}
	})
}

// --- duplicate slot ids ---

// Two slots with the same id is malformed, not merely odd. The id is length-prefixed into slotAAD
// precisely so a slot cannot be moved between slots, and marshalHeader keys `changed` by id: a
// duplicate makes one edit land on two slots, and makes "which slot opened the file" unanswerable.
func TestDuplicateSlotIDIsErrMalformed(t *testing.T) {
	golden := string(goldenHeader(t))
	// A three-slot header, the third wearing the first's id: under every cap, so only a duplicate
	// check can refuse it.
	dup := strings.Replace(golden,
		`{"id":"MDEyMzQ1Njc=","type":"kek-file"`,
		`{"id":"EBESExQVFhc=","type":"kek-file"`, 1)
	if dup == golden {
		t.Fatal("the case did not change the golden header")
	}
	noArgon2(t)
	if _, _, err := parseHeader([]byte(dup)); !errors.Is(err, errCorrupt) {
		t.Fatalf("parseHeader: want errCorrupt, got %v", err)
	}
	p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, []byte(dup))
	_, err := open(t, p, "pw")
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Open: want ErrMalformed, got %v", err)
	}
	if errors.Is(err, ErrBadKey) {
		t.Fatalf("Open also reports a bad key: %v", err)
	}
}

// --- a slot type this binary does not know ---

// unknownSlot is a slot of a type from a newer server. It carries an `argon2id` member this binary
// has no business reading and bounds that would be refused outright on a passphrase slot, so a
// parser that applied the known-type rules to it would refuse the whole file.
const unknownSlot = `{"id":"QUJDREVGR0g=","type":"tpm-v3","created":"2026-11-07T12:00:00Z",` +
	`"argon2id":{"t":99,"m":4294967295,"p":99,"salt":"not base64 at all"},` +
	`"wrap":{"handle":"AAEC","sealed":"AAEC"}}`

// withExtraSlot puts one more slot at the head of the golden's slots array.
func withExtraSlot(t *testing.T, slot string) []byte {
	t.Helper()
	golden := string(goldenHeader(t))
	const head = `"slots":[`
	out := strings.Replace(golden, head, head+slot+",", 1)
	if out == golden {
		t.Fatal("the slots array was not found in the golden header")
	}
	return []byte(out)
}

// The spec's forward-compatibility rule: an unknown slot type is skipped, never refused, and its
// bytes survive a header-changing save unchanged. The argon2id bounds exist to stop a crafted
// header reaching the derivation, and the derivation is only reachable for a `passphrase` slot, so
// applying them to a type this binary will never derive from buys nothing and costs the round trip.
func TestUnknownSlotTypeRoundTripsByteIdentical(t *testing.T) {
	noArgon2(t)
	hdr := withExtraSlot(t, unknownSlot)
	h, slots, err := parseHeader(hdr)
	if err != nil {
		t.Fatalf("a slot of an unknown type was refused: %v", err)
	}
	if len(slots) != 4 || slots[0].Type != "tpm-v3" {
		t.Fatalf("got %d slots, first %q; want 4 and tpm-v3", len(slots), slots[0].Type)
	}
	// Not in `changed`, so retention is what is under test and not encodeSlot.
	out, err := marshalHeader(h, nil)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if !bytes.Equal(hdr, out) {
		t.Fatalf("the round trip changed the bytes:\n in  %s\n out %s", hdr, out)
	}
	if !bytes.Contains(out, []byte(unknownSlot)) {
		t.Fatalf("the unknown slot was re-encoded rather than retained: %s", out)
	}
	// It sits with the machine slots in try order: only `passphrase` goes last, and a type this
	// binary cannot name is certainly not a prompt it can answer.
	var got []string
	for _, s := range tryOrder(slots) {
		got = append(got, s.Type)
	}
	want := "tpm-v3,dpapi,kek-file,passphrase"
	if strings.Join(got, ",") != want {
		t.Fatalf("try order %v, want %v", got, want)
	}
}

// The one error an operator sees when nothing opened the file names the kinds this binary knows and
// counts the rest. A slot type is attacker-controlled text up to 255 printable bytes, and the error
// goes to stderr and into the operator's paste buffer: echoing it back verbatim hands a crafted
// header a line of output, which is how a terminal escape or a forged instruction gets there.
func TestTriedSummaryNamesTriedKindsAndCountsTheRest(t *testing.T) {
	// A parseable header, so the walk reaches its passphrase slot and derives: the counting seam,
	// not noArgon2. See TestFileShorterThanMinimumIsErrCorrupt.
	argon2Seam(t)
	// 255 bytes of printable ASCII, the quote and the backslash among them, so the fixture also
	// proves the type is carried as JSON and not spliced into the header as text.
	var sb strings.Builder
	for i := 0; sb.Len() < 255; i++ {
		sb.WriteByte(byte(0x20 + i%95))
	}
	hostile := sb.String()[:255]
	quoted, err := json.Marshal(hostile)
	if err != nil {
		t.Fatalf("marshal the hostile type: %v", err)
	}
	slot := `{"id":"QUJDREVGR0g=","type":` + string(quoted) +
		`,"created":"2026-11-07T12:00:00Z","wrap":{"x":"AAEC"}}`
	hdr := withExtraSlot(t, slot)
	if _, slots, perr := parseHeader(hdr); perr != nil {
		t.Fatalf("the hostile-type header must parse, so the error path is reached: %v", perr)
	} else if len(slots) != 4 {
		t.Fatalf("got %d slots, want 4", len(slots))
	}
	p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, hdr)
	_, err = open(t, p, "pw")
	if !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey for a parseable v2 header, got %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, hostile) {
		t.Fatalf("the error carries the slot's type verbatim: %q", msg)
	}
	// Not a prefix of it either: a truncated 255-byte type is still the attacker's text.
	if strings.Contains(msg, hostile[:32]) {
		t.Fatalf("the error carries a prefix of the slot's type: %q", msg)
	}
	if !strings.Contains(msg, "1 unknown") {
		t.Fatalf("the error does not account for the unknown slot: %q", msg)
	}
	// Counted apart from the two machine slots, which are a kind this binary knows and this host has
	// no key for: the first says "wrong binary for this file", the second "wrong host".
	if !strings.Contains(msg, "slot types tried: passphrase; 2 this host held no key for") {
		t.Fatalf("the error does not name what was tried and count what was not: %q", msg)
	}
}

// --- the writer cannot emit what the parser refuses ---

// marshalHeader is the only writer of a v2 header. Every bound parseHeader enforces it enforces
// too, by parsing its own output: a file this binary wrote and cannot read again is a vault nobody
// can open, and the caps are the one thing a caller adding slots in a loop can walk past.
func TestMarshalHeaderRefusesWhatTheParserWouldReject(t *testing.T) {
	noArgon2(t)
	mkDPAPI := func(n byte) Slot {
		return Slot{
			ID:      base64.StdEncoding.EncodeToString([]byte{n, 1, 2, 3, 4, 5, 6, 7}),
			Type:    slotTypeDPAPI,
			Scope:   "machine",
			Created: "2026-11-07T12:00:00Z",
			Wrap:    WrapInfo{Blob: base64.StdEncoding.EncodeToString(make([]byte, 64))},
		}
	}
	added := func(n int) map[string]Slot {
		m := map[string]Slot{}
		for i := 0; i < n; i++ {
			s := mkDPAPI(byte(0x80 + i))
			m[s.ID] = s
		}
		return m
	}
	// The golden's three slots, one of them a passphrase, are the baseline for every case.
	h, slots, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	// Thirteen more is sixteen, the cap: accepted, and the positive control that the cases below
	// are refused for their own reason and not because the writer refuses any addition at all.
	t.Run("sixteen slots is written", func(t *testing.T) {
		out, err := marshalHeader(h, added(maxSlots-len(slots)))
		if err != nil {
			t.Fatalf("a header at the slot cap was refused: %v", err)
		}
		if _, got, err := parseHeader(out); err != nil || len(got) != maxSlots {
			t.Fatalf("the parser read back %d slots, err %v", len(got), err)
		}
	})
	t.Run("seventeen slots is refused", func(t *testing.T) {
		if _, err := marshalHeader(h, added(maxSlots-len(slots)+1)); !errors.Is(err, errCorrupt) {
			t.Fatalf("want errCorrupt, got %v", err)
		}
	})
	t.Run("nine passphrase slots is refused", func(t *testing.T) {
		pass := map[string]Slot{}
		for i := 0; i < maxPassphraseSlots; i++ {
			s := slots[0]
			s.ID = base64.StdEncoding.EncodeToString([]byte{byte(0xc0 + i), 1, 2, 3, 4, 5, 6, 7})
			pass[s.ID] = s
		}
		if _, err := marshalHeader(h, pass); !errors.Is(err, errCorrupt) {
			t.Fatalf("want errCorrupt, got %v", err)
		}
	})
	t.Run("an argon2id cost out of bounds is refused", func(t *testing.T) {
		s := slots[0]
		if s.Type != slotTypePassphrase || s.Argon2id == nil {
			t.Fatalf("the golden's first slot is no longer a passphrase slot: %+v", s)
		}
		p := *s.Argon2id
		p.M = maxArgonMem + 1
		s.Argon2id = &p
		if _, err := marshalHeader(h, map[string]Slot{s.ID: s}); !errors.Is(err, errCorrupt) {
			t.Fatalf("want errCorrupt, got %v", err)
		}
	})
	t.Run("a created stamp the parser refuses is refused", func(t *testing.T) {
		s := slots[1]
		s.Created = "2026-11-07T12:00:00+00:00"
		if _, err := marshalHeader(h, map[string]Slot{s.ID: s}); !errors.Is(err, errCorrupt) {
			t.Fatalf("want errCorrupt, got %v", err)
		}
	})
	// hdrLen is the one bound parsing the output cannot catch, because rawHeaderOf checks it
	// against the file's length prefix and not against the JSON.
	t.Run("a header over the hdrLen cap is refused", func(t *testing.T) {
		s := slots[2]
		s.Name = strings.Repeat("n", maxHdrLen)
		if _, err := marshalHeader(h, map[string]Slot{s.ID: s}); !errors.Is(err, errCorrupt) {
			t.Fatalf("want errCorrupt, got %v", err)
		}
	})
}

// encodeSlot is the path a changed or added slot takes, and the only one whose member order comes
// from the struct rather than from the bytes on disk. Routing all three of the golden's slots
// through `changed` makes the golden itself the assertion: reorder a field in Slot, Argon2Params or
// WrapInfo, or drop an omitempty, and these bytes move.
func TestEncodedSlotMemberOrderMatchesTheGolden(t *testing.T) {
	golden := goldenHeader(t)
	h, slots, err := parseHeader(golden)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	changed := make(map[string]Slot, len(slots))
	for _, s := range slots {
		changed[s.ID] = s
	}
	out, err := marshalHeader(h, changed)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if !bytes.Equal(golden, out) {
		t.Fatalf("re-encoding every slot changed the bytes:\n golden %s\n got    %s", golden, out)
	}
	// The golden alone cannot pin every pair. No slot in it carries both `scope` and `name`, and no
	// `wrap` carries both `nonce` and `blob`, so swapping either pair in the structs moves nothing
	// and the comparison above stays green. One slot wearing every optional member at once is the
	// only fixture that pins them all - and it has to be of a type this binary does not know,
	// because the parser rightly refuses a known type whose wrap is two shapes at once, and
	// marshalHeader now parses its own output.
	full := slots[1]
	full.Type = "tpm-v3"
	full.Scope = "machine"
	full.Name = "vault-kek"
	full.Argon2id = &Argon2Params{T: 3, M: 65536, P: 4, Salt: "QEFCQ0RFRkdISUpLTE1OTw=="}
	full.Wrap = WrapInfo{Nonce: "UFFSU1RVVldYWVpb", CT: "AAEC", Blob: "AAEC"}
	out, err = marshalHeader(h, map[string]Slot{full.ID: full})
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	at := -1
	for _, want := range []string{
		`{"id":"` + full.ID, `","type":"tpm-v3"`, `,"scope":"machine"`, `,"name":"vault-kek"`,
		`,"created":"`, `,"argon2id":{"t":3`, `,"m":65536`, `,"p":4`, `,"salt":"`,
		`,"wrap":{"nonce":"`, `","ct":"`, `","blob":"`,
	} {
		i := strings.Index(string(out)[at+1:], want)
		if i < 0 {
			t.Fatalf("the encoded slot does not contain %q in order: %s", want, out)
		}
		at += 1 + i
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

// The parser is as strict as the writer: `created` is RFC 3339 in UTC at one-second precision with
// the Z designator, and nothing else. An offset or a fraction names the same instant, so accepting
// one would not be wrong about the time - it would be a second spelling of a stamp the byte-exact
// encoding rules say has one, and two headers that differ only there would not be byte-comparable.
func TestCreatedMustBeTheUTCSecondsZForm(t *testing.T) {
	noArgon2(t)
	golden := string(goldenHeader(t))
	for _, tc := range []struct{ name, stamp string }{
		{"a zero offset instead of Z", "2026-11-07T12:00:00+00:00"},
		{"a real offset", "2026-11-07T07:00:00-05:00"},
		{"a fraction of a second", "2026-11-07T12:00:00.5Z"},
		{"lower case designators", "2026-11-07t12:00:00z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkCreated(tc.stamp); !errors.Is(err, errCorrupt) {
				t.Fatalf("checkCreated(%q): want errCorrupt, got %v", tc.stamp, err)
			}
			hdr := strings.Replace(golden,
				`"type":"passphrase","created":"2026-11-07T12:00:00Z"`,
				`"type":"passphrase","created":"`+tc.stamp+`"`, 1)
			if hdr == golden {
				t.Fatal("the case did not change the golden header")
			}
			if _, _, err := parseHeader([]byte(hdr)); !errors.Is(err, errCorrupt) {
				t.Fatalf("parseHeader: want errCorrupt, got %v", err)
			}
		})
	}
	// The accept side: the one form the writer emits, from the writer itself.
	if err := checkCreated(nowString()); err != nil {
		t.Fatalf("the parser refuses what nowString writes: %v", err)
	}
	if err := checkCreated("2026-11-07T12:00:00Z"); err != nil {
		t.Fatalf("the golden's own stamp was refused: %v", err)
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

// --- unknown-slot retention across a header-changing save, and the warning ---

// captureLog swaps this package's log sink for a buffer, the way internal/usage and internal/web
// swap theirs. It is a logx logger, so the test reads exactly what an operator would: an
// allowlisted key is written, anything else is "[dropped]", and every value is redacted and capped.
// A test that calls this must not call t.Parallel: the sink is package state.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = logx.New(&buf)
	t.Cleanup(func() { logger = prev })
	return &buf
}

// logLines decodes the captured lines. Each must be one JSON object on one line: that is the
// property that makes a hostile slot type harmless, so the decode is part of the assertion.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("a log line is not one JSON object: %q: %v", raw, err)
		}
		out = append(out, m)
	}
	return out
}

// headerWithoutPassphraseSlots is the golden header with its one passphrase slot dropped: a header
// this binary must still read and must refuse to write. It is built with encodeCompact rather than
// marshalHeader because marshalHeader refusing it is the thing under test.
func headerWithoutPassphraseSlots(t *testing.T) ([]byte, Header) {
	t.Helper()
	h, _, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	kept := make([]json.RawMessage, 0, len(h.Slots))
	for _, elem := range h.Slots {
		if slotTypeOf(elem) == slotTypePassphrase {
			continue
		}
		kept = append(kept, elem)
	}
	if len(kept) == len(h.Slots) {
		t.Fatal("the golden header no longer has a passphrase slot to drop")
	}
	h.Slots = kept
	b, err := encodeCompact(h)
	if err != nil {
		t.Fatalf("encodeCompact: %v", err)
	}
	return b, h
}

// The header-changing half of the retention rule. TestUnknownSlotTypeRoundTripsByteIdentical above
// proves a save that changes nothing keeps the bytes; this one changes another slot - a fresh
// argon2id salt on the passphrase slot, which is what change-passphrase does - and the unknown
// slot's bytes still have to come through untouched.
func TestUnknownSlotBytesSurviveAHeaderChangingSave(t *testing.T) {
	noArgon2(t)
	hdr := withExtraSlot(t, unknownSlot)
	h, slots, err := parseHeader(hdr)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	pass := slots[1]
	if pass.Type != slotTypePassphrase || pass.Argon2id == nil {
		t.Fatalf("the golden's first slot is no longer a passphrase slot: %+v", pass)
	}
	p := *pass.Argon2id
	p.Salt = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, saltLen))
	pass.Argon2id = &p
	out, err := marshalHeader(h, map[string]Slot{pass.ID: pass})
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	if bytes.Equal(hdr, out) {
		t.Fatal("the save changed nothing, so it is not a header-changing save")
	}
	if !bytes.Contains(out, []byte(unknownSlot)) {
		t.Fatalf("the unknown slot's bytes did not survive the save: %s", out)
	}
	// The mutation check, and the concrete reason retention reads from the raw bytes: route the
	// unknown slot through `changed` and encodeSlot re-encodes it from the typed Slot, which has no
	// field for this slot's `handle` or `sealed` wrap members. They are silently dropped - a newer
	// server's slot turned into one this binary invented. That is what the test above forbids.
	t.Run("re-encoding the unknown slot loses its wrap members", func(t *testing.T) {
		noArgon2(t)
		unknown := slots[0]
		if unknown.Type != "tpm-v3" {
			t.Fatalf("the fixture's unknown slot moved: %+v", unknown)
		}
		out, err := marshalHeader(h, map[string]Slot{unknown.ID: unknown})
		if err != nil {
			t.Fatalf("marshalHeader: %v", err)
		}
		if bytes.Contains(out, []byte(unknownSlot)) {
			t.Fatal("the fixture was retained even though it was named in `changed`")
		}
		for _, lost := range []string{`"handle"`, `"sealed"`} {
			if bytes.Contains(out, []byte(lost)) {
				t.Fatalf("%s survived the re-encode, so this test proves nothing: %s", lost, out)
			}
		}
	})
}

// Skipped on open, with one warning per skipped slot naming the slot and its type - and nothing
// else. The open still fails here, because no slot opener is wired to the v2 read path yet (see
// openSealedV2): the warning is what this test is about, and it is emitted on the way to that
// answer either way.
func TestUnknownSlotIsSkippedOnOpenWithAWarning(t *testing.T) {
	// A parseable header: the walk skips the unknown slot, reaches the golden's passphrase slot and
	// derives from it, so this is the counting seam rather than noArgon2.
	argon2Seam(t)
	buf := captureLog(t)
	hdr := withExtraSlot(t, unknownSlot)
	p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, hdr)
	if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("Open: want ErrBadKey, got %v", err)
	}
	lines := logLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want exactly one (one per unknown slot, none for a known one): %q",
			len(lines), buf.String())
	}
	line := lines[0]
	if got := line["slot"]; got != "QUJDREVGR0g=" {
		t.Fatalf("slot = %v, want the unknown slot's id", got)
	}
	if got := line["slottype"]; got != "tpm-v3" {
		t.Fatalf("slottype = %v, want tpm-v3", got)
	}
	if got := line["level"]; got != "WARN" {
		t.Fatalf("level = %v, want WARN", got)
	}
	// Nothing from the slot but its id and its type: not the wrap, not the argon2id members this
	// binary has no business reading, and no key the allowlist would have dropped anyway.
	for k := range line {
		switch k {
		case "time", "level", "msg", "component", "slot", "slottype":
		default:
			t.Fatalf("the warning carries an unexpected key %q: %q", k, buf.String())
		}
	}
	for _, forbidden := range []string{"AAEC", "not base64 at all", "argon2id", "salt", "[dropped]"} {
		if strings.Contains(buf.String(), forbidden) {
			t.Fatalf("the warning carries %q: %q", forbidden, buf.String())
		}
	}
}

// A slot's type and id are attacker-chosen text from a header nothing has authenticated yet, and
// this line is written where an operator reads it. The property that makes that safe is structural:
// one JSON object per line, so neither field can splice a line of its own, and logx caps every
// value. (The stderr side is the other half of the rule and is asserted separately, by
// TestTriedSummaryNamesTriedKindsAndCountsTheRest: an error string that is pasted into a ticket
// names the kinds that were tried and counts the rest, rather than echoing the type.)
func TestUnknownSlotWarningCannotBeSplicedByAHostileSlot(t *testing.T) {
	// A parseable header, so the walk derives from the golden's passphrase slot: the counting seam.
	argon2Seam(t)
	// 255 bytes of printable ASCII, the quote and the backslash among them, and an id spelled with
	// an embedded newline - which base64 ignores, so it decodes to the same eight bytes and reaches
	// the log line as given.
	var sb strings.Builder
	for i := 0; sb.Len() < 255; i++ {
		sb.WriteByte(byte(0x20 + i%95))
	}
	hostile := sb.String()[:255]
	quoted, err := json.Marshal(hostile)
	if err != nil {
		t.Fatalf("marshal the hostile type: %v", err)
	}
	buf := captureLog(t)
	slot := `{"id":"QUJD\nREVGR0g=","type":` + string(quoted) +
		`,"created":"2026-11-07T12:00:00Z","wrap":{"x":"AAEC"}}`
	p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, withExtraSlot(t, slot))
	if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("Open: want ErrBadKey, got %v", err)
	}
	// One object on one line: logLines fails the test if either field broke out of its string.
	lines := logLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want one: %q", len(lines), buf.String())
	}
	// The type comes back whole, and that is the assertion rather than a length bound: asciiType
	// already caps a type at 255 bytes and logx caps a value at 256, so "is it under the cap" is a
	// question that cannot be answered no and proves nothing. What is worth pinning is that all 255
	// hostile bytes - the quote and the backslash among them - arrive as the value of one JSON
	// member, neither truncated nor rewritten by the redactor on their way there.
	got, ok := lines[0]["slottype"].(string)
	if !ok {
		t.Fatalf("slottype is not a string: %q", buf.String())
	}
	if got != hostile {
		t.Fatalf("slottype came back as %d bytes %q, want the 255 hostile bytes unchanged", len(got), got)
	}
	// And neither field spliced: the whole output is one line, so the id's embedded newline and
	// every control-looking byte in the type were escaped by the encoder.
	if strings.Count(strings.TrimRight(buf.String(), "\n"), "\n") != 0 {
		t.Fatalf("the id's newline reached the output unescaped: %q", buf.String())
	}
}

// --- a `changed` entry's map key against the slot's own id ---

// marshalHeader finds a slot by the `changed` map's key and then encodes that Slot's own `id`. A
// pair whose key and `id` disagree used to be written out in silence: the slot kept its place and
// its wrap but came back under a different id, and a slot's id is length-prefixed into its AAD
// (slotAAD), so every wrap bound to the old id stops opening. Nothing downstream catches it -
// another valid eight-byte base64 id is a valid id, so the file parses and the self-parse inside
// marshalHeader passes.
//
// Strict string equality is the right check, not a decode-and-compare: a caller gets the id from
// parseHeader and hands back the string it was given, and a re-spelled base64 id - one with an
// embedded newline, which base64 ignores - is a different byte string in the AAD's length prefix
// anyway, so treating it as the same slot would be the bug rather than the fix.
func TestMarshalHeaderRefusesAChangedSlotWhoseIDDoesNotMatchItsKey(t *testing.T) {
	noArgon2(t)
	h, slots, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	pass := slots[0]
	if pass.Type != slotTypePassphrase {
		t.Fatalf("the golden's first slot is no longer the passphrase slot: %+v", pass)
	}
	mis := pass
	mis.ID = base64.StdEncoding.EncodeToString([]byte("IJKLMNOP"))
	if mis.ID == pass.ID {
		t.Fatal("the fixture's two ids are equal, so the mismatch is not being tested")
	}
	out, err := marshalHeader(h, map[string]Slot{pass.ID: mis})
	if !errors.Is(err, errSlotIDMismatch) {
		t.Fatalf("marshalHeader: want errSlotIDMismatch, got %v (out %d bytes)", err, len(out))
	}
	if out != nil {
		t.Fatalf("refused and still returned %d bytes", len(out))
	}
	// Not errCorrupt: the header on disk was fine, the call was not. An operator told "malformed
	// vault file" goes looking for a corrupt disk or rotates a correct passphrase.
	if errors.Is(err, errCorrupt) {
		t.Fatalf("a caller's mistake was reported as a malformed file: %v", err)
	}
	// Neither id is echoed, escaped or otherwise.
	for _, id := range []string{pass.ID, mis.ID} {
		if strings.Contains(err.Error(), id) {
			t.Fatalf("the error echoes a slot id: %q", err.Error())
		}
	}
	// The positive control: the same slot under its matching key writes, and keeps its id.
	out, err = marshalHeader(h, map[string]Slot{pass.ID: pass})
	if err != nil {
		t.Fatalf("the matching pair was refused: %v", err)
	}
	if !bytes.Contains(out, []byte(pass.ID)) {
		t.Fatalf("the slot's id is not in the output: %s", out)
	}
}

// The same mismatch on the append path, which is a separate loop over `added`. The map key decides
// the order two slots added in one call come out in, and the Slot's own `id` is what gets written,
// so a disagreeing pair appended a slot under an id the caller never named.
func TestMarshalHeaderRefusesAnAddedSlotWhoseIDDoesNotMatchItsKey(t *testing.T) {
	noArgon2(t)
	h, slots, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	add := slots[0]
	add.ID = base64.StdEncoding.EncodeToString([]byte("BODYBODY"))
	key := base64.StdEncoding.EncodeToString([]byte("KEYKEYKE"))
	// Both ids must be absent from the header, or this lands in the loop above instead.
	for _, s := range slots {
		if s.ID == key || s.ID == add.ID {
			t.Fatalf("a fixture id collides with an existing slot: %+v", s)
		}
	}
	out, err := marshalHeader(h, map[string]Slot{key: add})
	if !errors.Is(err, errSlotIDMismatch) {
		t.Fatalf("marshalHeader: want errSlotIDMismatch, got %v (out %d bytes)", err, len(out))
	}
	if out != nil {
		t.Fatalf("refused and still returned %d bytes", len(out))
	}
	if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), add.ID) {
		t.Fatalf("the error echoes a slot id: %q", err.Error())
	}
	// The positive control: appended under its own id it is written, and under that id.
	out, err = marshalHeader(h, map[string]Slot{add.ID: add})
	if err != nil {
		t.Fatalf("the matching pair was refused: %v", err)
	}
	if !bytes.Contains(out, []byte(add.ID)) {
		t.Fatalf("the appended slot's id is not in the output: %s", out)
	}
	if bytes.Contains(out, []byte(key)) {
		t.Fatalf("the map key leaked into the output: %s", out)
	}
}

// --- zero passphrase slots: refused on write, readable on open ---

// Spec: "A file with zero `passphrase` slots is refused on write (ErrNoRecoverySlot)." marshalHeader
// is the only writer of a v2 header, so that is where the refusal lives - there is no second path a
// caller could reach past it.
func TestSaveWithZeroPassphraseSlotsIsRefused(t *testing.T) {
	noArgon2(t)
	hdr, h := headerWithoutPassphraseSlots(t)
	if _, _, err := parseHeader(hdr); err != nil {
		t.Fatalf("the fixture must parse, or the refusal under test is not the one that fired: %v", err)
	}
	out, err := marshalHeader(h, nil)
	if !errors.Is(err, ErrNoRecoverySlot) {
		t.Fatalf("marshalHeader: want ErrNoRecoverySlot, got %v", err)
	}
	if out != nil {
		t.Fatalf("refused and still returned %d bytes", len(out))
	}
	// The count is of what would be written, not of what was read: a change that retypes the last
	// passphrase slot into something else is the same refusal, and it is the shape remove-slot and
	// change-passphrase will hit (Task 3b.2).
	t.Run("retyping the last passphrase slot is the same refusal", func(t *testing.T) {
		noArgon2(t)
		full, slots, err := parseHeader(goldenHeader(t))
		if err != nil {
			t.Fatalf("parseHeader: %v", err)
		}
		if full.passphraseSlotCount() != 1 {
			t.Fatalf("the golden has %d passphrase slots, want one", full.passphraseSlotCount())
		}
		retyped := Slot{ID: slots[0].ID, Type: slotTypeDPAPI, Scope: "machine", Created: slots[0].Created,
			Wrap: WrapInfo{Blob: base64.StdEncoding.EncodeToString(make([]byte, 64))}}
		if _, err := marshalHeader(full, map[string]Slot{retyped.ID: retyped}); !errors.Is(err, ErrNoRecoverySlot) {
			t.Fatalf("want ErrNoRecoverySlot, got %v", err)
		}
	})
	// The positive control: the same writer, with the passphrase slot present, writes.
	t.Run("the golden header still writes", func(t *testing.T) {
		noArgon2(t)
		full, _, err := parseHeader(goldenHeader(t))
		if err != nil {
			t.Fatalf("parseHeader: %v", err)
		}
		if _, err := marshalHeader(full, nil); err != nil {
			t.Fatalf("a header with a passphrase slot was refused: %v", err)
		}
	})
}

// The other half of the same rule: such a file still opens, so a hand-damaged header can be read
// and repaired. The answer here is ErrBadKey because no opener is wired yet - what matters is that
// it is neither errCorrupt nor the write-side refusal.
func TestOpenWithZeroPassphraseSlotsStillSucceeds(t *testing.T) {
	noArgon2(t)
	hdr, h := headerWithoutPassphraseSlots(t)
	if h.passphraseSlotCount() != 0 {
		t.Fatalf("the fixture has %d passphrase slots, want none", h.passphraseSlotCount())
	}
	p := writeV2(t, t.TempDir(), "vault.bin", v2VaultMagic, hdr)
	_, err := open(t, p, "pw")
	if !errors.Is(err, ErrBadKey) {
		t.Fatalf("Open: want ErrBadKey, got %v", err)
	}
	if errors.Is(err, errCorrupt) || errors.Is(err, ErrNoRecoverySlot) {
		t.Fatalf("a readable header was reported as unreadable or unwritable: %v", err)
	}
}

// The two counters the slot operations will ask. They read the retained raw elements, so they agree
// with what marshalHeader would write rather than with a decoded copy that might have drifted.
func TestPassphraseSlotCountAndUnknownSlots(t *testing.T) {
	noArgon2(t)
	full, _, err := parseHeader(goldenHeader(t))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if got := full.passphraseSlotCount(); got != 1 {
		t.Fatalf("golden passphraseSlotCount = %d, want 1", got)
	}
	if got := full.unknownSlots(); len(got) != 0 {
		t.Fatalf("golden unknownSlots = %+v, want none", got)
	}
	withUnknown, _, err := parseHeader(withExtraSlot(t, unknownSlot))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if got := withUnknown.passphraseSlotCount(); got != 1 {
		t.Fatalf("passphraseSlotCount = %d, want 1: an unknown slot is not a passphrase slot", got)
	}
	unknown := withUnknown.unknownSlots()
	if len(unknown) != 1 || unknown[0].Type != "tpm-v3" || unknown[0].ID != "QUJDREVGR0g=" {
		t.Fatalf("unknownSlots = %+v, want the one tpm-v3 slot", unknown)
	}
	_, none := headerWithoutPassphraseSlots(t)
	if got := none.passphraseSlotCount(); got != 0 {
		t.Fatalf("passphraseSlotCount = %d on a header with none", got)
	}
}

// ErrUnknownSlotPresent is the sentinel `rotate` and `remove-slot` of another slot refuse with
// (Task 3b.2). Nothing in this binary returns it yet - there are no slot operations - so what is
// asserted here is the contract a caller will match on: a wrapped error is still errors.Is it.
func TestErrUnknownSlotPresentIsMatchableWhenWrapped(t *testing.T) {
	err := fmt.Errorf("%w: slot %s", ErrUnknownSlotPresent, "QUJDREVGR0g=")
	if !errors.Is(err, ErrUnknownSlotPresent) {
		t.Fatalf("a wrapped ErrUnknownSlotPresent is not matchable: %v", err)
	}
	if errors.Is(err, ErrNoRecoverySlot) || errors.Is(err, errCorrupt) {
		t.Fatalf("ErrUnknownSlotPresent collides with another sentinel: %v", err)
	}
}

// --- create-on-open stays v1 ---

// A data dir with no vault, opened with a passphrase, still produces a CSV1 file. `server vault
// init` is the only thing that will ever create a v2 vault (Task 3b.3, plan revision 8 item 2), and
// nothing reachable from a plain `server run` may start writing v2. This is a permanent assertion:
// TestV1VaultStillWritesV1AfterEveryMutator covers the mutators on an existing file; this one
// covers the creation, and that Open itself writes nothing at all.
func TestCreateOnOpenStillWritesV1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open wrote a file: stat err %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(data[:len(magic)]); got != magic {
		t.Fatalf("create-on-open wrote magic %q, want %q", got, magic)
	}
	if bytes.HasPrefix(data, []byte(v2VaultMagic)) {
		t.Fatal("create-on-open wrote a v2 vault")
	}
}

func TestKeyringCreateOnOpenStillWritesCSK1(t *testing.T) {
	t.Setenv(keyEnv, "pw")
	p := filepath.Join(t.TempDir(), KeyringFileName)
	k, err := OpenKeyring(p, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenKeyring wrote a file: stat err %v", err)
	}
	if _, err := k.Generate("h1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(data[:len(keyringMagic)]); got != keyringMagic {
		t.Fatalf("create-on-open wrote magic %q, want %q", got, keyringMagic)
	}
	if bytes.HasPrefix(data, []byte(v2KeyringMagic)) {
		t.Fatal("create-on-open wrote a v2 keyring")
	}
}

// FuzzOpenHeader fuzzes everything after the magic: the big-endian header length, the header JSON
// and whatever follows. Every number in there is attacker-controlled, and a passphrase slot's
// argon2id cost is read before any key exists to authenticate it with, so the parser is the only
// thing standing between a crafted file and an allocation sized from it.
//
// The properties: never a panic; every failure is errCorrupt or ErrNewerFormat and never ErrBadKey;
// a header length over the cap is refused without the file having to be that long; and a header
// that does parse is inside every bound the writer is held to.
//
// The slot unwrap half of this task is FuzzSlotUnwrap, below.
func FuzzOpenHeader(f *testing.F) {
	golden, err := os.ReadFile(filepath.Join("testdata", "header-golden.json"))
	if err != nil {
		f.Fatalf("golden: %v", err)
	}
	golden = bytes.TrimSuffix(golden, []byte("\n"))

	tail := func(header []byte) []byte { return v2File(v2VaultMagic, header)[len(v2VaultMagic):] }
	f.Add(tail(golden))
	// Truncations at every field boundary of the golden file: the length prefix itself, the header
	// mid-way, the header exactly, and the payload one byte short of the tag.
	whole := tail(golden)
	for _, n := range []int{0, 1, 3, 4, 5, 4 + len(golden)/2, 4 + len(golden), len(whole) - 1} {
		if n >= 0 && n <= len(whole) {
			f.Add(whole[:n])
		}
	}
	// A header length that must be refused before anything is sized from it.
	big := make([]byte, 4)
	binary.BigEndian.PutUint32(big, 1<<20)
	f.Add(big)
	// Costs and counts outside the bounds, a short salt, and a slot array over the cap.
	salt := base64.StdEncoding.EncodeToString(make([]byte, saltLen))
	shortSalt := base64.StdEncoding.EncodeToString(make([]byte, saltLen-1))
	dekID := base64.StdEncoding.EncodeToString(make([]byte, dekIDLen))
	slotID := base64.StdEncoding.EncodeToString(make([]byte, slotIDLen))
	nonce := base64.StdEncoding.EncodeToString(make([]byte, nonceLen))
	ct := base64.StdEncoding.EncodeToString(make([]byte, wrapCTLen))
	pass := func(t, m, p uint64, s string) string {
		return fmt.Sprintf(`{"id":%q,"type":"passphrase","created":"2026-11-08T00:00:00Z","argon2id":{"t":%d,"m":%d,"p":%d,"salt":%q},"wrap":{"nonce":%q,"ct":%q}}`,
			slotID, t, m, p, s, nonce, ct)
	}
	header := func(slots string) []byte {
		return []byte(fmt.Sprintf(`{"v":2,"dek":{"id":%q,"created":"2026-11-08T00:00:00Z"},"slots":[%s]}`, dekID, slots))
	}
	f.Add(tail(header(pass(0, 65536, 4, salt))))
	f.Add(tail(header(pass(3, 1<<32-1, 4, salt))))
	f.Add(tail(header(pass(3, 65536, 0, salt))))
	f.Add(tail(header(pass(3, 65536, 4, shortSalt))))
	many := make([]string, 17)
	for i := range many {
		many[i] = pass(3, 65536, 4, salt)
	}
	f.Add(tail(header(strings.Join(many, ","))))
	f.Add(tail([]byte(`{"v":3,"dek":{},"slots":[]}`)))
	f.Add(tail([]byte(`{"v":2,"dek":{},"slots":[],"extra":1}`)))

	f.Fuzz(func(t *testing.T, afterMagic []byte) {
		data := append([]byte(v2VaultMagic), afterMagic...)
		var declared uint32
		if len(afterMagic) >= 4 {
			declared = binary.BigEndian.Uint32(afterMagic[:4])
		}
		aad, headerJSON, err := rawHeaderOf(data)
		if err != nil {
			if !errors.Is(err, errCorrupt) {
				t.Fatalf("rawHeaderOf = %v, want errCorrupt", err)
			}
			return
		}
		if declared > maxHdrLen {
			t.Fatalf("a header length of %d was accepted, over the %d cap", declared, maxHdrLen)
		}
		if len(aad) != v2PrefixLen+len(headerJSON) || uint32(len(headerJSON)) != declared {
			t.Fatalf("aad %d bytes, header %d bytes, declared %d", len(aad), len(headerJSON), declared)
		}
		h, slots, err := parseHeader(headerJSON)
		switch {
		case err == nil:
		case errors.Is(err, errCorrupt), errors.Is(err, ErrNewerFormat):
			return
		default:
			t.Fatalf("parseHeader = %v, want errCorrupt or ErrNewerFormat", err)
		}
		if h.V != headerVersion {
			t.Fatalf("parsed v = %d", h.V)
		}
		if len(slots) > maxSlots || len(slots) != len(h.Slots) {
			t.Fatalf("%d slots parsed, %d raw, cap %d", len(slots), len(h.Slots), maxSlots)
		}
		passphrases := 0
		for _, s := range slots {
			if s.Type != slotTypePassphrase {
				continue
			}
			passphrases++
			if s.Argon2id == nil {
				t.Fatal("a passphrase slot parsed with no argon2id")
			}
			p := *s.Argon2id
			if p.T < minArgonTime || p.T > maxArgonTime || p.P < minArgonPar || p.P > maxArgonPar ||
				p.M < minArgonMem || p.M > maxArgonMem {
				t.Fatalf("argon2id cost out of bounds: %+v", p)
			}
		}
		if passphrases > maxPassphraseSlots {
			t.Fatalf("%d passphrase slots, cap %d", passphrases, maxPassphraseSlots)
		}
	})
}

// FuzzSlotUnwrap fuzzes one slot's wrap: its nonce, its ciphertext and the additional data it is
// bound to. openSlot is the one function every symmetric slot type goes through - the passphrase
// slot and the kek-file slot both end there - and it is reached with no parse in front of it here,
// which is exactly why dekIDFromAAD checks the AAD's shape itself.
//
// The properties: never a panic; every failure wraps ErrBadKey or errCorrupt and nothing else; and a
// success returns a key of exactly keyLen bytes, never the short or long plaintext an authenticated
// wrap written by something that is not this format could carry.
func FuzzSlotUnwrap(f *testing.F) {
	kek := bytes.Repeat([]byte{0x2b}, keyLen)
	dek := bytes.Repeat([]byte{0x3c}, keyLen)
	aad := slotAAD(v2VaultMagic, make([]byte, dekIDLen), make([]byte, slotIDLen), slotTypePassphrase)
	nonce, ct, err := sealSlot(kek, dek, aad)
	if err != nil {
		f.Fatalf("seed seal: %v", err)
	}
	f.Add(nonce, ct, aad)
	// One byte short and one byte long on each field, and the empty cases. A wrap of the wrong
	// length must be refused on its length rather than handed to the AEAD.
	f.Add(nonce, ct[:len(ct)-1], aad)
	f.Add(nonce, append(append([]byte(nil), ct...), 0), aad)
	f.Add(nonce[:nonceLen-1], ct, aad)
	f.Add(append(append([]byte(nil), nonce...), 0), ct, aad)
	f.Add([]byte(nil), []byte(nil), aad)
	f.Add(nonce, ct, []byte(nil))
	f.Add(nonce, ct, aad[:len(aad)-1])
	// An AAD whose length prefixes disagree with its fields: the shape check, not the AEAD, owns it.
	bad := append([]byte(nil), aad...)
	bad[4] = 0xff
	f.Add(nonce, ct, bad)
	// A wrap that authenticates and carries something other than a key. sealWith exists for exactly
	// this: sealSlot refuses to build it and openSlot must still refuse to believe it.
	short, serr := sealWithFixedKey(kek, aad, bytes.Repeat([]byte{0x4d}, keyLen-1))
	if serr != nil {
		f.Fatalf("seed short wrap: %v", serr)
	}
	f.Add(short.nonce, short.ct, aad)

	f.Fuzz(func(t *testing.T, nonce, ct, aad []byte) {
		got, err := openSlot(kek, nonce, ct, aad)
		if err != nil {
			if !errors.Is(err, ErrBadKey) && !errors.Is(err, errCorrupt) {
				t.Fatalf("openSlot = %v, want ErrBadKey or errCorrupt", err)
			}
			if got != nil {
				t.Fatalf("openSlot returned %d bytes alongside an error", len(got))
			}
			return
		}
		if len(got) != keyLen {
			t.Fatalf("openSlot returned a %d-byte key", len(got))
		}
	})
}

// sealWithFixedKey seals plain for one slot the way sealSlot does, but without sealSlot's refusal to
// wrap anything other than a key - so the corpus can carry a wrap that authenticates and holds the
// wrong number of bytes.
func sealWithFixedKey(kek, aad, plain []byte) (sealedWrap, error) {
	dekID, err := dekIDFromAAD(aad)
	if err != nil {
		return sealedWrap{}, err
	}
	wk, err := wrapKey(kek, dekID, aad)
	if err != nil {
		return sealedWrap{}, err
	}
	defer zero(wk)
	return sealWith(wk, plain, aad)
}
