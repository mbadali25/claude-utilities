package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sort"
	"time"
)

// This file holds the v2 header: its types, the parser and the one writer. Nothing here opens a
// slot - the slot wrap and the three openers are later tasks - and nothing here writes a file.
// `server vault init` is the only thing that will ever create a v2 vault; every write path in this
// binary still writes v1 (TestV1VaultStillWritesV1AfterEveryMutator pins that).
//
// Every number in a header is attacker-controlled, because the header is not authenticated until
// the payload opens, and a passphrase slot's argon2id cost is read before any key exists to
// authenticate it with. So the bounds below are checked on the parsed integers before a single
// allocation is sized from them and before the derivation can be reached - a header claiming
// m = 4 TiB must be refused by this parser, never by the allocator inside argon2id.

// Layout and bounds. Changing one of these numbers changes the file format.
const (
	// headerVersion is the only `v` this binary reads or writes. Anything else is ErrNewerFormat:
	// v2's extension point is the slot type, not the header.
	headerVersion = 2
	// v2PrefixLen is the magic plus the big-endian header length that precedes the header JSON.
	v2PrefixLen = 8
	// maxHdrLen caps the header before anything is sized from hdrLen.
	maxHdrLen = 64 << 10
	// gcmTagLen is the AES-GCM tag, the shortest a sealed payload can be.
	gcmTagLen = 16

	dekIDLen  = 16
	slotIDLen = 8
	// wrapCTLen is a sealed 32-byte DEK plus its tag.
	wrapCTLen = 32 + gcmTagLen

	// maxSlots and maxPassphraseSlots bound the slot array before it is walked.
	maxSlots           = 16
	maxPassphraseSlots = 8

	// argon2id parameter bounds. The 8 MiB memory floor is there so a downgraded cost is visible
	// rather than silently cheap; the 1 GiB ceiling is there so a crafted header cannot make this
	// process try to allocate the machine.
	minArgonTime = 1
	maxArgonTime = 10
	minArgonPar  = 1
	maxArgonPar  = 16
	minArgonMem  = 8
	maxArgonMem  = 1048576
)

// Slot type names. They are bound into every slot's AAD, so they are part of the format.
const (
	slotTypePassphrase = "passphrase"
	slotTypeDPAPI      = "dpapi"
	slotTypeKEKFile    = "kek-file"
)

// randRead and nowFn are the package's only sources of randomness and of the current time, so a
// golden-file test can pin both and rebuild a file byte for byte. They are replaced in tests the
// way renameFn already is.
var (
	randRead = rand.Read
	nowFn    = time.Now
)

// Header is a v2 file's top-level header. Its members are exactly these three, in this order: the
// top level is closed, and a `v` other than 2 or any fourth member is ErrNewerFormat rather than
// malformed. Slots stays []json.RawMessage so an untouched slot - including one of a type this
// binary does not know - is re-emitted from the bytes it arrived as.
type Header struct {
	V     int               `json:"v"`
	DEK   DEKInfo           `json:"dek"`
	Slots []json.RawMessage `json:"slots"`
}

// DEKInfo identifies one generation of the data encryption key. The id is 16 random bytes and is
// not secret: it is the HKDF salt and part of every slot's AAD, which is what stops a slot being
// moved between generations.
type DEKInfo struct {
	ID      string `json:"id"`
	Created string `json:"created"`
}

// Slot is one key slot, decoded. Field order is the format's member order; Scope, Name and
// Argon2id are omitted when empty, which is what makes one struct produce all three shapes the
// spec's example shows.
//
// raw is the bytes this slot arrived as, kept so a header-changing save re-emits an untouched slot
// unchanged - byte for byte, whether or not this binary understands its type.
type Slot struct {
	ID       string        `json:"id"`
	Type     string        `json:"type"`
	Scope    string        `json:"scope,omitempty"`
	Name     string        `json:"name,omitempty"`
	Created  string        `json:"created"`
	Argon2id *Argon2Params `json:"argon2id,omitempty"`
	Wrap     WrapInfo      `json:"wrap"`

	raw json.RawMessage `json:"-"`
}

// Argon2Params is a passphrase slot's recorded cost, so it can be raised later without a format
// bump. Every field is bounds-checked before the derivation is reachable.
type Argon2Params struct {
	T    uint32 `json:"t"`
	M    uint32 `json:"m"`
	P    uint32 `json:"p"`
	Salt string `json:"salt"`
}

// WrapInfo is the wrapped DEK. A symmetric slot carries nonce and ct; a dpapi slot carries blob.
type WrapInfo struct {
	Nonce string `json:"nonce,omitempty"`
	CT    string `json:"ct,omitempty"`
	Blob  string `json:"blob,omitempty"`
}

// nowString is the one way a `created` stamp is produced: RFC 3339 in UTC at one-second precision,
// always with the Z designator. No fractional seconds and no offset, so two headers written in
// different time zones are byte-comparable.
func nowString() string { return nowFn().UTC().Truncate(time.Second).Format(time.RFC3339) }

// rawHeaderOf returns the payload's additional data and the header's JSON, both as slices of the
// bytes read from disk: the AAD is magic(4) || hdrLen(4, big-endian) || header JSON, and the header
// JSON is the tail of it. The bounds come first and in this order on purpose - nothing may be sized
// from hdrLen until hdrLen is capped, and the header must be wholly present before it is parsed.
//
// Slices of the file, never a re-marshal. The payload is sealed under the bytes that were written,
// so a reader that re-encoded the parsed header to rebuild the AAD would fail to open a file whose
// writer ordered one member differently - and would be trusting the parse to be lossless, which is
// exactly what an attacker would attack.
func rawHeaderOf(data []byte) (aad, headerJSON []byte, err error) {
	if len(data) < v2PrefixLen {
		return nil, nil, errCorrupt
	}
	hdrLen := binary.BigEndian.Uint32(data[4:v2PrefixLen])
	if hdrLen > maxHdrLen {
		return nil, nil, errCorrupt
	}
	// uint64 throughout, so the sum of four attacker-influenced lengths cannot wrap on a 32-bit
	// build and let a short file past.
	if uint64(len(data)) < uint64(v2PrefixLen)+uint64(hdrLen)+uint64(nonceLen)+uint64(gcmTagLen) {
		return nil, nil, errCorrupt
	}
	end := v2PrefixLen + int(hdrLen)
	return data[:end], data[v2PrefixLen:end], nil
}

// parseHeader decodes a v2 header's JSON bytes. It returns the header with its slots still in the
// bytes they arrived as, the slots decoded, and an error: ErrNewerFormat when the top level is not
// this version's, errCorrupt for anything malformed or out of bounds.
//
// Two stages, deliberately. The top level is decoded as a map first so "exactly these members" can
// be enforced before any value is trusted, and `slots` as []json.RawMessage so an unknown slot
// type survives a round trip. Neither stage sizes anything from a number in the header.
func parseHeader(raw []byte) (Header, []Slot, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return Header{}, nil, errCorrupt
	}
	// Closed top level, checked before `v`: a header carrying both a fourth member and a version
	// this binary knows is still a header written by something newer.
	for k := range top {
		if k != "v" && k != "dek" && k != "slots" {
			return Header{}, nil, ErrNewerFormat
		}
	}
	// A missing member is malformed, not newer: "any other top-level member is ErrNewerFormat" is
	// about members this binary does not know, and a header with no `dek` names no version at all.
	for _, k := range []string{"v", "dek", "slots"} {
		if _, ok := top[k]; !ok {
			return Header{}, nil, errCorrupt
		}
	}
	var h Header
	// `v` first and on its own, so a version this binary cannot read is reported as such before
	// anything else in the header is believed. A `v` that is not a number names no version either.
	if err := json.Unmarshal(top["v"], &h.V); err != nil {
		return Header{}, nil, errCorrupt
	}
	if h.V != headerVersion {
		return Header{}, nil, ErrNewerFormat
	}
	if err := json.Unmarshal(top["dek"], &h.DEK); err != nil {
		return Header{}, nil, errCorrupt
	}
	if err := json.Unmarshal(top["slots"], &h.Slots); err != nil {
		return Header{}, nil, errCorrupt
	}
	if err := decodeExactly(h.DEK.ID, dekIDLen); err != nil {
		return Header{}, nil, err
	}
	if err := checkCreated(h.DEK.Created); err != nil {
		return Header{}, nil, err
	}
	// The slot count is capped before the array is walked, so a header listing thousands of slots
	// costs one length check rather than thousands of decodes.
	if len(h.Slots) > maxSlots {
		return Header{}, nil, errCorrupt
	}
	slots := make([]Slot, 0, len(h.Slots))
	passphrases := 0
	for _, elem := range h.Slots {
		s, err := parseSlot(elem)
		if err != nil {
			return Header{}, nil, err
		}
		if s.Type == slotTypePassphrase {
			passphrases++
			if passphrases > maxPassphraseSlots {
				return Header{}, nil, errCorrupt
			}
		}
		slots = append(slots, s)
	}
	return h, slots, nil
}

// parseSlot decodes one slot and bounds-checks everything in it that this binary understands. A
// slot of an unknown type is still checked for the fields every slot has - its id and its stamp
// are part of the AAD and the audit line - and its wrap is left alone, because only the type that
// wrote it knows that shape.
func parseSlot(raw json.RawMessage) (Slot, error) {
	var s Slot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Slot{}, errCorrupt
	}
	s.raw = append(json.RawMessage(nil), raw...)
	if err := decodeExactly(s.ID, slotIDLen); err != nil {
		return Slot{}, err
	}
	// The type is length-prefixed with one byte inside slotAAD and must be printable ASCII, so no
	// NUL and nothing past 255 bytes can ever reach that byte string.
	if !asciiType(s.Type) {
		return Slot{}, errCorrupt
	}
	if err := checkCreated(s.Created); err != nil {
		return Slot{}, err
	}
	switch s.Type {
	case slotTypePassphrase, slotTypeKEKFile:
		if err := decodeExactly(s.Wrap.Nonce, nonceLen); err != nil {
			return Slot{}, err
		}
		if err := decodeExactly(s.Wrap.CT, wrapCTLen); err != nil {
			return Slot{}, err
		}
		if s.Wrap.Blob != "" {
			return Slot{}, errCorrupt
		}
	case slotTypeDPAPI:
		// The blob's length is the platform's business; that it decodes, and that it is not also
		// pretending to be a symmetric wrap, is this parser's.
		if _, err := base64.StdEncoding.DecodeString(s.Wrap.Blob); err != nil || s.Wrap.Blob == "" {
			return Slot{}, errCorrupt
		}
		if s.Wrap.Nonce != "" || s.Wrap.CT != "" {
			return Slot{}, errCorrupt
		}
	}
	if s.Type == slotTypePassphrase {
		if s.Argon2id == nil {
			return Slot{}, errCorrupt
		}
		if err := checkArgon2(*s.Argon2id); err != nil {
			return Slot{}, err
		}
	} else if s.Argon2id != nil {
		return Slot{}, errCorrupt
	}
	return s, nil
}

// checkArgon2 bounds every recorded cost. This runs on the parsed integers, before anything is
// sized from them and before argon2IDKey is reachable, which is the whole point: the memory figure
// is what an attacker would use to make this process allocate the machine.
func checkArgon2(p Argon2Params) error {
	if p.T < minArgonTime || p.T > maxArgonTime {
		return errCorrupt
	}
	if p.P < minArgonPar || p.P > maxArgonPar {
		return errCorrupt
	}
	if p.M < minArgonMem || p.M > maxArgonMem {
		return errCorrupt
	}
	return decodeExactly(p.Salt, saltLen)
}

// decodeExactly refuses a field that is not padded StdEncoding base64 of exactly n bytes. One
// decoder and one alphabet: RawStdEncoding and the URL alphabet are not accepted anywhere, and a
// decoded length other than the one the format states is malformed, not a bad key.
func decodeExactly(field string, n int) error {
	b, err := base64.StdEncoding.DecodeString(field)
	if err != nil || len(b) != n {
		return errCorrupt
	}
	return nil
}

// checkCreated refuses a stamp this binary cannot read. A header's stamp is never trusted for a
// decision - the slot try order is fixed by kind, not by age - but an unparseable one means the
// header was not written by anything that follows this format, and that is worth saying before any
// crypto runs rather than after.
func checkCreated(s string) error {
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return errCorrupt
	}
	return nil
}

// asciiType reports whether a slot type can be carried in the one-byte-length-prefixed field of
// slotAAD: 1 to 255 bytes, printable ASCII, no NUL.
func asciiType(t string) bool {
	if len(t) == 0 || len(t) > 255 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

// tryOrder returns the slots in the order they must be tried: machine-held slots first, in header
// order, then every passphrase slot. The order is fixed by kind and never by a stamp, so a header
// claiming a slot was created a century from now cannot reorder anything.
//
// It matters in both directions. A service has no passphrase and must succeed on a machine slot,
// so a passphrase slot tried first would only produce a prompt it cannot answer; an operator at a
// console has the passphrase, and spending it on a slot that was going to work anyway is a prompt
// nobody needed.
func tryOrder(slots []Slot) []Slot {
	out := make([]Slot, 0, len(slots))
	for _, s := range slots {
		if s.Type != slotTypePassphrase {
			out = append(out, s)
		}
	}
	for _, s := range slots {
		if s.Type == slotTypePassphrase {
			out = append(out, s)
		}
	}
	return out
}

// marshalHeader writes the header's bytes: compact, no trailing newline, HTML left alone, members
// in the format's order. changed maps a slot id to its new form; every slot not named there is
// emitted from the bytes it arrived as, so an untouched slot - known type or not - is byte
// identical before and after. A slot in changed whose id is not already present is appended, in id
// order, so adding two slots in one call is deterministic.
//
// The result is the new rawHeader and therefore the new payload AAD. The caller re-seals under it;
// nothing re-marshals a header to produce AAD for a payload it did not just write.
func marshalHeader(h Header, changed map[string]Slot) ([]byte, error) {
	out := Header{V: headerVersion, DEK: h.DEK, Slots: make([]json.RawMessage, 0, len(h.Slots)+len(changed))}
	seen := map[string]bool{}
	for _, elem := range h.Slots {
		var probe struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(elem, &probe); err != nil {
			return nil, errCorrupt
		}
		seen[probe.ID] = true
		if s, ok := changed[probe.ID]; ok {
			enc, err := encodeSlot(s)
			if err != nil {
				return nil, err
			}
			out.Slots = append(out.Slots, enc)
			continue
		}
		out.Slots = append(out.Slots, elem)
	}
	added := make([]string, 0, len(changed))
	for id := range changed {
		if !seen[id] {
			added = append(added, id)
		}
	}
	sort.Strings(added)
	for _, id := range added {
		enc, err := encodeSlot(changed[id])
		if err != nil {
			return nil, err
		}
		out.Slots = append(out.Slots, enc)
	}
	return encodeCompact(out)
}

// encodeSlot encodes one changed or added slot from its typed form. Only a slot the caller touched
// goes through here; everything else keeps its original bytes.
func encodeSlot(s Slot) (json.RawMessage, error) {
	b, err := encodeCompact(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// encodeCompact is the one encoder: compact, SetEscapeHTML(false) so `<`, `>` and `&` are left as
// themselves, and exactly one trailing newline trimmed.
//
// The newline is json.Encoder.Encode's, and this byte contract forbids it: hdrLen counts it and the
// payload AAD covers hdrLen, so a stray newline would be a silent format change. json.Marshal emits
// no newline but has no way to turn HTML escaping off, so the encoder plus the trim is the path.
func encodeCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, errCorrupt
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
