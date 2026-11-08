package vault

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// This file holds the slot operations: add a slot, remove one (which rotates the data key in the
// same write), rotate on demand, change the passphrase, and the two read-only inspectors the CLI's
// `status` and `verify` are built on.
//
// Three rules shape everything here, and each of them is a refusal before a write rather than a
// repair after one:
//
//  1. **Every refusal lands before replaceFile.** A rotation has to re-wrap EVERY slot, so a slot
//     whose key this process cannot reach, or whose type it does not know, has to be found before
//     the first byte is written - otherwise the file is left half-way through a generation change.
//     regenerateLocked therefore builds a sealer for every surviving slot, and proves each one
//     works on a throwaway wrap, before it draws the new data key.
//  2. **The last passphrase slot is never removed.** It is the recovery rung for every machine-key
//     loss case in the design (Premise 3), and a vault whose only key belongs to one host is gone
//     with that host.
//  3. **The `.bak` is dealt with before the new generation becomes visible.** A copy sealed under
//     the old slots still opens with the key a removal just took away, so it is re-sealed under the
//     new generation where it can be and deleted where it cannot - and the caller prints which.
//     The window this trades for is harmless: a crash between the two leaves the file the command
//     started with and no copy.

// The format names Inspect reports. They are the strings an operator reads, and `status`,
// `verify` and the runbooks all use these spellings.
const (
	FormatAbsent = "absent"
	FormatV1     = "v1"
	FormatV2     = "v2"
)

var (
	// ErrLastPassphraseSlot means a removal would leave a file with no passphrase slot. The write
	// path refuses such a file anyway (ErrNoRecoverySlot); this is the earlier, clearer refusal, so
	// an operator is told which slot they tried to remove and why rather than being handed the
	// writer's rule.
	ErrLastPassphraseSlot = errors.New("vault: refusing to remove the last passphrase slot: it is the recovery key for every machine-key loss")

	// ErrNotV2 means the file is not in the v2 format, so it has no key slots to operate on. It is
	// its own error and emphatically not ErrBadKey: a v1 file and an absent one are both answered by
	// `server vault migrate` / `server vault init`, and an operator pushed towards rotating a
	// correct passphrase is a stated Anti-goal.
	ErrNotV2 = errors.New("vault: this file has no key slots (it is not v2); run `server vault migrate`")

	// ErrSlotNotFound means no slot in the header carries that id.
	ErrSlotNotFound = errors.New("vault: no key slot has that id")

	// ErrSlotExists means a slot with that id is already in the header. The id is length-prefixed
	// into every wrap's AAD, so two slots under one id would leave "which slot opened this file"
	// unanswerable in the audit line.
	ErrSlotExists = errors.New("vault: a key slot with that id is already in the header")
)

// The `.bak` outcomes, as the command prints them. bakResealed, bakRemoved and bakAbsent live in
// vaultop.go, which is where the settle step reads them; the two removal reasons and the v1 case
// are here because only a mutator can produce them.
const (
	// A .bak no surviving slot opens is deleted: it is openable by the key being removed and by
	// nothing this command holds, which is the hole the ordering exists to close.
	bakRemovedUnopenable = bakRemoved + " (no available slot opened it)"
	// Bytes that will not parse as a header are not a recovery copy at all.
	bakRemovedCorrupt = bakRemoved + " (its header will not parse)"
	// A v1 .bak is a pre-migration artefact, not a copy of this generation: deleting it would take
	// the v1 rollback with it, and re-sealing it would turn a v1 artefact into a v2 file. It is left
	// exactly where it is, and the command names what owns v1 artefacts.
	bakKeptV1 = "bak kept, it is v1 (`server vault finalize-migration` removes v1 copies)"
)

// encB64 is the one encoder for a field this package writes: padded StdEncoding, the same alphabet
// decodeExactly accepts.
func encB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// kekCredentialName is the credential name a kek-file slot this binary creates records in its
// `name`, and it is the same default resolveKEK looks for when HostKeyOptions names none. The slot
// stores the name and never a path: a path in the header would be a second place the truth lives.
const kekCredentialName = "vault-kek"

// --- key sources ---

// machineKeys is WithMachineKeys' KeySource: a passphrase source with this host's machine openers
// behind it.
type machineKeys struct {
	pass    KeySource
	opts    HostKeyOptions
	once    sync.Once
	openers []SlotOpener
}

// WithMachineKeys returns a KeySource offering pass's passphrase and this host's machine-held
// openers. A nil pass means this process has no passphrase at all, which is exactly what
// `vault verify` without `--all-slots` is: open with the machine slot or do not open.
//
// The openers are resolved once and kept, because one command opens the vault and then the keyring
// and resolving twice would mean a second systemd-creds child per run.
func WithMachineKeys(pass KeySource, opts HostKeyOptions) KeySource {
	return &machineKeys{pass: pass, opts: opts}
}

func (m *machineKeys) Passphrase() (string, error) {
	if m.pass == nil {
		return "", fmt.Errorf("%w: this command was not given a passphrase (try `--all-slots`)", ErrNoKey)
	}
	return m.pass.Passphrase()
}

func (m *machineKeys) Machine() []SlotOpener {
	m.once.Do(func() { m.openers = HostKeys(m.opts) })
	return m.openers
}

// --- sealers: the wrapping half of a slot ---

// A slotSealer wraps the data encryption key for one slot. It is the counterpart of SlotOpener and
// is deliberately unexported: a slot type is only addable by a binary that knows how to wrap it, so
// there is no third-party implementation to accept.
type slotSealer interface {
	seal(dek, aad []byte) (WrapInfo, error)
}

// passphraseSealer wraps under an argon2id-derived key. The derivation is cached because a rotation
// seals every slot and a pre-flight probe seals once more: argon2id at the real cost is tenths of a
// second, and deriving it three times for one command is time an operator waits for nothing.
type passphraseSealer struct {
	pass   string
	params Argon2Params
	kek    []byte
}

func (s *passphraseSealer) seal(dek, aad []byte) (WrapInfo, error) {
	if s.kek == nil {
		kek, err := passphraseKEK(s.pass, s.params)
		if err != nil {
			return WrapInfo{}, err
		}
		s.kek = kek
	}
	nonce, ct, err := sealSlot(s.kek, dek, aad)
	if err != nil {
		return WrapInfo{}, err
	}
	return WrapInfo{Nonce: encB64(nonce), CT: encB64(ct)}, nil
}

// kekSealer wraps under a 32-byte key-encryption key: the kek-file slot's shape.
type kekSealer struct{ kek []byte }

func (s kekSealer) seal(dek, aad []byte) (WrapInfo, error) {
	nonce, ct, err := sealSlot(s.kek, dek, aad)
	if err != nil {
		return WrapInfo{}, err
	}
	return WrapInfo{Nonce: encB64(nonce), CT: encB64(ct)}, nil
}

// dpapiSealer protects the data key under the machine's DPAPI key, with the slot's AAD as the
// entropy. Off Windows dpapiWrap answers errDPAPIUnsupported, so the pre-flight probe refuses the
// slot there rather than a half-written file discovering it.
type dpapiSealer struct{}

func (dpapiSealer) seal(dek, aad []byte) (WrapInfo, error) {
	blob, err := dpapiWrap(dek, aad)
	if err != nil {
		return WrapInfo{}, err
	}
	return WrapInfo{Blob: encB64(blob)}, nil
}

// sealerSet resolves one sealer per slot, asking the key source at most once for the passphrase and
// at most once for the machine openers - the same contract recoverDEK keeps on the opening side,
// and for the same reasons: argon2id is expensive and a systemd-creds child is a process.
type sealerSet struct {
	ks           KeySource
	passAsked    bool
	pass         string
	passErr      error
	machineAsked bool
	openers      []SlotOpener
}

// sealerFor returns the sealer for one slot, or the reason this process cannot wrap it. The error
// is the operator's next step: ErrKEKUnreachable means the key is where it should be and this
// process may not have it, ErrUnknownSlotPresent means this is the wrong binary for the file.
func (ss *sealerSet) sealerFor(s Slot) (slotSealer, error) {
	switch s.Type {
	case slotTypePassphrase:
		if !ss.passAsked {
			ss.passAsked = true
			ss.pass, ss.passErr = ss.ks.Passphrase()
			if ss.passErr == nil && ss.pass == "" {
				// A KeySource that breaks its own contract must not get a key derived from "": that
				// key would open nothing and would re-seal the file under a passphrase nobody chose.
				ss.passErr = fmt.Errorf("%w: the key source returned an empty passphrase", ErrNoKey)
			}
		}
		if ss.passErr != nil {
			return nil, ss.passErr
		}
		if s.Argon2id == nil {
			return nil, fmt.Errorf("%w: a passphrase slot carries no argon2id parameters", errCorrupt)
		}
		return &passphraseSealer{pass: ss.pass, params: *s.Argon2id}, nil
	case slotTypeDPAPI:
		if s.Scope != "" && s.Scope != dpapiScopeMachine {
			return nil, fmt.Errorf("%w: slot %s is a dpapi slot of a scope this binary does not write", errCorrupt, s.ID)
		}
		return dpapiSealer{}, nil
	case slotTypeKEKFile:
		if !ss.machineAsked {
			ss.machineAsked = true
			ss.openers = ss.ks.Machine()
		}
		op := openerFor(ss.openers, slotTypeKEKFile)
		if op == nil {
			return nil, fmt.Errorf("%w: slot %s is a kek-file slot and this host resolved no KEK", ErrKEKUnreachable, s.ID)
		}
		// The opener is this package's own, so the KEK it resolved is reachable from here. A
		// SlotOpener from anywhere else can open a slot but cannot wrap one, and saying so by slot id
		// is better than a rotation that writes a file with one stale wrap in it.
		kf, ok := op.(*kekFileSlotOpener)
		if !ok {
			return nil, fmt.Errorf("%w: slot %s: this host's kek-file opener cannot wrap", ErrKEKUnreachable, s.ID)
		}
		if kf.err != nil {
			return nil, fmt.Errorf("%w: slot %s: %w", ErrKEKUnreachable, s.ID, kf.err)
		}
		return kekSealer{kek: kf.kek}, nil
	}
	return nil, fmt.Errorf("%w: slot %s is of type %s", ErrUnknownSlotPresent, s.ID, s.Type)
}

// --- the inspectors status and verify stand on ---

// SlotInfo is one slot as `status` and `verify` report it: what it is and whether this host could
// use it. Never a wrap, never a blob, never a parameter an operator cannot act on.
type SlotInfo struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Scope   string `json:"scope,omitempty"`
	Name    string `json:"name,omitempty"`
	Created string `json:"created"`
	// Known is false for a slot type this binary does not understand: skipped on open, retained on
	// write, and a refusal for anything that must re-wrap every slot.
	Known bool `json:"known"`
	// HostHoldsKey is true when this host has a machine opener for this slot's kind. It is never
	// true for a passphrase slot: the key for that one is in an operator's head, not on the host.
	HostHoldsKey bool `json:"hostHoldsKey"`
}

// FileInfo is one sealed file as `status` reports it, read from the header alone - no key, no
// passphrase, no payload. That is what makes it safe to run while the service holds the lock.
type FileInfo struct {
	Name   string     `json:"name"`
	Format string     `json:"format"`
	DEKID  string     `json:"dekId,omitempty"`
	Slots  []SlotInfo `json:"slots,omitempty"`
}

// SlotResult is one slot's outcome in a `verify` run. Reason is from a closed set, so a crafted
// header cannot write a line of an operator's output.
type SlotResult struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Opened bool   `json:"opened"`
	Reason string `json:"reason"`
}

// The closed set of SlotResult reasons.
const (
	slotOpened      = "opened"
	slotDidNotOpen  = "did not open"
	slotNoHostKey   = "this host holds no key for it"
	slotUnreachable = "its key is configured and unreachable"
	slotUnknownType = "unknown type, skipped on open"
	slotNotTried    = "not tried (needs --all-slots)"
	// A passphrase slot with no passphrase to offer. Deliberately not slotNoHostKey: the key for
	// this slot is in an operator's head, and "this host holds no key" would send them looking for
	// a file.
	slotNoPassphrase = "no passphrase was available"
)

// VerifyResult is one file's verification: what the file is, what each slot did, and whether the
// payload opened and parsed. Entries is a count and the only thing here derived from the payload:
// nothing in this struct is a key, a wrap, an account label or an identity.
type VerifyResult struct {
	File      FileInfo     `json:"file"`
	Tried     []SlotResult `json:"tried"`
	PayloadOK bool         `json:"payloadOk"`
	Entries   int          `json:"entries"`
}

// Inspect reads a sealed file's header and says what it is. It opens nothing and needs no key, so
// it is safe on a file another process holds the lock for.
//
// An absent or empty file is not an error - a fresh install has neither file, and a host that never
// ran with --tunnels has no keyring - and a magic this binary does not know is errCorrupt.
func Inspect(path string) (FileInfo, error) {
	info := FileInfo{Name: filepath.Base(path), Format: FormatAbsent}
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return info, nil
	}
	if err != nil {
		return info, fmt.Errorf("vault: read %s: %w", filepath.Base(path), err)
	}
	if len(data) == 0 {
		return info, nil
	}
	switch {
	case bytes.HasPrefix(data, []byte(v2VaultMagic)), bytes.HasPrefix(data, []byte(v2KeyringMagic)):
		info.Format = FormatV2
	case bytes.HasPrefix(data, []byte(magic)), bytes.HasPrefix(data, []byte(keyringMagic)):
		info.Format = FormatV1
		return info, nil
	default:
		return info, errCorrupt
	}
	_, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return info, err
	}
	h, slots, err := parseHeader(headerJSON)
	if err != nil {
		return info, err
	}
	info.DEKID = dekIDPrefix(h.DEK.ID)
	// HostKeyOptions{} on purpose: `status` names what this host COULD use and must not shell out to
	// systemd-creds or read /etc to answer. The root-only route is `verify`'s and the mutators'.
	openers := HostKeys(HostKeyOptions{})
	for _, s := range slots {
		si := SlotInfo{ID: s.ID, Type: s.Type, Scope: s.Scope, Name: s.Name,
			Created: s.Created, Known: knownSlotType(s.Type)}
		if si.Known && s.Type != slotTypePassphrase {
			si.HostHoldsKey = usableOpener(openerFor(openers, s.Type))
		}
		info.Slots = append(info.Slots, si)
	}
	return info, nil
}

// usableOpener reports whether an opener is one this host can actually use. A kek-file opener
// carrying a refusal is NOT usable - it exists so the open flow can report ErrKEKUnreachable rather
// than quietly asking for a passphrase - and reporting it as a key this host holds would tell an
// operator the opposite of what they need to know.
func usableOpener(op SlotOpener) bool {
	if op == nil {
		return false
	}
	if kf, ok := op.(*kekFileSlotOpener); ok {
		return kf.err == nil && len(kf.kek) == keyLen
	}
	return true
}

// dekIDPrefix is the first eight characters of a dek.id, which is what `status` and `verify` print.
// The id is not secret - it is the HKDF salt and part of every slot's AAD - and the prefix is enough
// to tell two generations apart in a line an operator reads.
func dekIDPrefix(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// VerifyFile opens one sealed file and reports which slots opened it and whether the payload parses.
// It takes no lock and writes nothing.
//
// allSlots is the difference between the two checks the spec defines: without it only the machine
// slots are tried, which is the question "can the service start"; with it every slot is tried in
// turn, which is the question "is every key still good" and the one the runbook asks after a
// change-passphrase, an add-slot or a restore.
func VerifyFile(path string, ks KeySource, allSlots bool) (VerifyResult, error) {
	info, err := Inspect(path)
	res := VerifyResult{File: info}
	if err != nil {
		return res, err
	}
	if info.Format != FormatV2 {
		return res, ErrNotV2
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return res, fmt.Errorf("vault: read %s: %w", filepath.Base(path), err)
	}
	aad, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return res, err
	}
	h, slots, err := parseHeader(headerJSON)
	if err != nil {
		return res, err
	}
	magicStr := fileKind(data)
	v2 := v2Magic(magicStr)
	dekID, derr := base64.StdEncoding.DecodeString(h.DEK.ID)
	if derr != nil || len(dekID) != dekIDLen {
		return res, errCorrupt
	}

	var dek []byte
	var unreachable error
	w := &verifyWalk{ks: ks, allSlots: allSlots}
	for _, s := range tryOrder(slots) {
		r := SlotResult{ID: s.ID, Type: s.Type}
		op, reason := w.openerForSlot(s)
		if op == nil {
			r.Reason = reason
			res.Tried = append(res.Tried, r)
			continue
		}
		slotID, serr := base64.StdEncoding.DecodeString(s.ID)
		if serr != nil || len(slotID) != slotIDLen {
			return res, errCorrupt
		}
		got, uerr := op.Unwrap(s, slotAAD(v2, dekID, slotID, s.Type))
		switch {
		case uerr == nil:
			r.Opened, r.Reason = true, slotOpened
			// The first key that opens is the one the payload is opened with; the rest are proved and
			// thrown away, because --all-slots is a check of every slot and not a race to the payload.
			if dek == nil {
				dek = got
			} else {
				zero(got)
			}
		case errors.Is(uerr, ErrKEKUnreachable):
			r.Reason = slotUnreachable
			if unreachable == nil {
				unreachable = uerr
			}
		default:
			r.Reason = slotDidNotOpen
		}
		res.Tried = append(res.Tried, r)
	}
	if dek == nil {
		// Which answer comes back is a decision, not a fallthrough, on the same reasoning recoverDEK
		// is built on: a configured-and-unreachable key is never reported as a bad one.
		switch {
		case unreachable != nil:
			return res, unreachable
		case w.passErr != nil && allSlots:
			return res, w.passErr
		}
		return res, fmt.Errorf("%w: no slot opened %s", ErrBadKey, filepath.Base(path))
	}
	defer zero(dek)
	aead, err := payloadAEAD(dek)
	if err != nil {
		return res, err
	}
	body := data[len(aad):]
	plain, oerr := aead.Open(nil, body[:nonceLen], body[nonceLen:], aad)
	if oerr != nil {
		return res, fmt.Errorf("%w: the payload did not open under this file's data key", ErrBadKey)
	}
	res.PayloadOK = true
	n, perr := countEntries(magicStr, plain)
	if perr != nil {
		res.PayloadOK = false
		return res, perr
	}
	res.Entries = n
	return res, nil
}

// verifyWalk holds one verify run's lazily-asked key material: the passphrase at most once, the
// machine openers at most once - the same contract recoverDEK keeps, so a verify of a
// passphrase-only file never starts a systemd-creds child and a machine-only one never prompts.
type verifyWalk struct {
	ks        KeySource
	allSlots  bool
	askedPass bool
	passOpen  SlotOpener
	passErr   error
	askedMach bool
	openers   []SlotOpener
}

// openerForSlot returns the opener to try for one slot, or nil and the reason there is none. The
// reason is from the closed set above: it is printed, so it may never carry a slot's type verbatim
// or anything else out of a header nothing has authenticated.
func (w *verifyWalk) openerForSlot(s Slot) (SlotOpener, string) {
	if !knownSlotType(s.Type) {
		return nil, slotUnknownType
	}
	if s.Type != slotTypePassphrase {
		if !w.askedMach {
			w.askedMach = true
			w.openers = w.ks.Machine()
		}
		if op := openerFor(w.openers, s.Type); op != nil {
			return op, ""
		}
		return nil, slotNoHostKey
	}
	if !w.allSlots {
		return nil, slotNotTried
	}
	if !w.askedPass {
		w.askedPass = true
		pass, perr := w.ks.Passphrase()
		switch {
		case perr != nil:
			w.passErr = perr
		case pass == "":
			w.passErr = fmt.Errorf("%w: the key source returned an empty passphrase", ErrNoKey)
		default:
			w.passOpen = passphraseSlotOpener{pass: pass}
		}
	}
	if w.passOpen == nil {
		return nil, slotNoPassphrase
	}
	return w.passOpen, ""
}

// fileKind names which of the two sealed files this is, from its own magic. The file says what it
// is, so a caller cannot ask for the wrong payload parse.
func fileKind(data []byte) string {
	if bytes.HasPrefix(data, []byte(v2KeyringMagic)) || bytes.HasPrefix(data, []byte(keyringMagic)) {
		return keyringMagic
	}
	return magic
}

// countEntries parses a decrypted payload and returns how many things are in it. It is the "and
// their payload parses" half of verify's definition, and it returns a COUNT: the payload holds
// account labels, identities and login blocks, none of which may reach an operator's terminal.
func countEntries(magicStr string, plain []byte) (int, error) {
	switch magicStr {
	case keyringMagic:
		var p keyringPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return 0, errCorrupt
		}
		return len(p.Keys), nil
	default:
		var list []Account
		if err := json.Unmarshal(plain, &list); err != nil {
			return 0, errCorrupt
		}
		return len(list), nil
	}
}

// --- the mutators ---

// v2Locked returns this vault's parsed header, or ErrNotV2 for a file that did not arrive as v2.
// The data key is the discriminator, exactly as it is for the writer: a file with no data key has
// no slots, and there is no argument to any of these that turns a v1 file into a v2 one.
//
// The header is re-parsed from rawHeader rather than read from the in-memory Header, because
// rawHeader is what is on disk: the slots a mutation must re-wrap are the ones the file carries.
// Caller holds v.mu.
func (v *Vault) v2Locked() (Header, []Slot, error) {
	if v.file == nil || v.file.dek == nil || len(v.file.rawHeader) <= v2PrefixLen {
		return Header{}, nil, ErrNotV2
	}
	h, slots, err := parseHeader(v.file.rawHeader[v2PrefixLen:])
	if err != nil {
		return Header{}, nil, err
	}
	return h, slots, nil
}

// AddSlot wraps this vault's CURRENT data key into one new slot and writes the file once. Every
// existing slot keeps its wrap, so every key that opened the file before still opens it - which is
// what makes this the recovery step for a lost machine key: open with the passphrase, add a slot
// for the new host key, and the service can start again.
//
// s carries the type, and optionally a name (a kek-file slot's credential name). The id, the
// `created` stamp and a passphrase slot's argon2id parameters come from this package's own seams,
// because they must: an id is 8 bytes of randomness and a salt is 16, and a caller that supplied
// either would be choosing key material from outside the one place that owns it. A caller MAY
// supply an id - a test pinning a fixture does - and it is checked and refused if it is taken.
//
// material is the new slot's key-encryption material, read according to the slot's type: the
// passphrase's bytes for a `passphrase` slot (this function derives the KEK from it with a fresh
// salt), the 32-byte KEK for a `kek-file` slot, and nil for `dpapi`, whose protector holds its own
// key. One parameter rather than three, so there is no shape in which two are set and disagree.
func (v *Vault) AddSlot(s Slot, material []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	h, slots, err := v.v2Locked()
	if err != nil {
		return err
	}
	if !knownSlotType(s.Type) {
		return fmt.Errorf("vault: add-slot: %q is not a slot type this binary can create", s.Type)
	}
	if len(slots) >= maxSlots {
		return fmt.Errorf("vault: add-slot: the header already holds %d slots, which is the maximum", maxSlots)
	}
	if s.Type == slotTypePassphrase && countPassphraseSlots(slots) >= maxPassphraseSlots {
		return fmt.Errorf("vault: add-slot: the header already holds %d passphrase slots, which is the maximum", maxPassphraseSlots)
	}
	if s.ID == "" {
		id := make([]byte, slotIDLen)
		if _, rerr := randRead(id); rerr != nil {
			return fmt.Errorf("vault: add-slot: slot id: %w", rerr)
		}
		s.ID = encB64(id)
	} else if derr := decodeExactly(s.ID, slotIDLen); derr != nil {
		return derr
	}
	for _, ex := range slots {
		if ex.ID == s.ID {
			return fmt.Errorf("%w: %s", ErrSlotExists, s.ID)
		}
	}
	s.Created = nowString()
	s.Argon2id = nil
	switch s.Type {
	case slotTypePassphrase:
		salt := make([]byte, saltLen)
		if _, rerr := randRead(salt); rerr != nil {
			return fmt.Errorf("vault: add-slot: salt: %w", rerr)
		}
		s.Argon2id = &Argon2Params{T: argonTime, M: argonMem, P: argonPar, Salt: encB64(salt)}
	case slotTypeDPAPI:
		s.Scope = dpapiScopeMachine
	case slotTypeKEKFile:
		if s.Name == "" {
			s.Name = kekCredentialName
		}
	}
	sealer, err := v.sealerFromMaterial(s, material)
	if err != nil {
		return err
	}
	aad, err := slotAADOf(h, s)
	if err != nil {
		return err
	}
	wrap, err := sealer.seal(v.file.dek, aad)
	if err != nil {
		return err
	}
	s.Wrap = wrap
	if err := v.saveLocked(map[string]Slot{s.ID: s}); err != nil {
		return err
	}
	logger.Info("vault: key slot added", "op", "add-slot", "slot", s.ID, "slottype", s.Type,
		"result", "added", "slots", len(slots)+1)
	return nil
}

// sealerFromMaterial builds the sealer for a slot being created out of the material the caller
// handed in. It is AddSlot's half of the slot-type switch; a rotation's half is sealerSet, which
// takes its material from the key source instead.
//
// A nil material for a kek-file slot means "the KEK this host already resolves", which is the
// normal case: the CLI never sees a KEK, because key material does not need to cross a package
// boundary to be wrapped. Creating one - 32 new bytes, the credstore entry, the unit drop-in and a
// daemon-reload - belongs to `vault init`/`vault migrate`, which plan those steps before taking
// them, so with no KEK to wrap under this refuses and names them.
func (v *Vault) sealerFromMaterial(s Slot, material []byte) (slotSealer, error) {
	switch s.Type {
	case slotTypePassphrase:
		if len(material) == 0 {
			return nil, fmt.Errorf("%w: add-slot was given no passphrase for a passphrase slot", ErrNoKey)
		}
		if s.Argon2id == nil {
			return nil, fmt.Errorf("%w: a passphrase slot carries no argon2id parameters", errCorrupt)
		}
		return &passphraseSealer{pass: string(material), params: *s.Argon2id}, nil
	case slotTypeKEKFile:
		if len(material) == 0 {
			return v.hostKEKSealer()
		}
		if len(material) != keyLen {
			return nil, fmt.Errorf("%w: a kek-file slot needs a %d-byte key, got %d bytes",
				ErrKEKUnreachable, keyLen, len(material))
		}
		return kekSealer{kek: material}, nil
	case slotTypeDPAPI:
		if len(material) != 0 {
			return nil, errors.New("vault: add-slot: a dpapi slot takes no key material; its protector holds its own")
		}
		return dpapiSealer{}, nil
	}
	return nil, fmt.Errorf("vault: add-slot: %q is not a slot type this binary can create", s.Type)
}

// hostKEKSealer wraps under the KEK this host resolves through the key source this vault was opened
// with - the same openers, the same routes, the same refusals, so `add-slot --type kek-file` can
// never wrap under a key the open flow would not have used.
func (v *Vault) hostKEKSealer() (slotSealer, error) {
	named := "`server vault init` or `server vault migrate` creates one"
	if v.ks == nil {
		return nil, fmt.Errorf("%w: this vault was opened with no key source; %s", ErrKEKUnreachable, named)
	}
	op := openerFor(v.ks.Machine(), slotTypeKEKFile)
	if op == nil {
		return nil, fmt.Errorf("%w: no KEK resolves on this host, so there is nothing to wrap under; %s",
			ErrKEKUnreachable, named)
	}
	kf, ok := op.(*kekFileSlotOpener)
	if !ok {
		return nil, fmt.Errorf("%w: this host's kek-file opener cannot wrap", ErrKEKUnreachable)
	}
	if kf.err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKEKUnreachable, kf.err)
	}
	return kekSealer{kek: kf.kek}, nil
}

// slotAADOf builds one slot's additional data from a header's dek.id and the slot's own id and type.
// One function, so AddSlot and a rotation cannot disagree about what a slot is bound to.
func slotAADOf(h Header, s Slot) ([]byte, error) {
	dekID, err := base64.StdEncoding.DecodeString(h.DEK.ID)
	if err != nil || len(dekID) != dekIDLen {
		return nil, errCorrupt
	}
	slotID, err := base64.StdEncoding.DecodeString(s.ID)
	if err != nil || len(slotID) != slotIDLen {
		return nil, errCorrupt
	}
	return slotAAD(v2VaultMagic, dekID, slotID, s.Type), nil
}

// RemoveSlot removes one slot AND rotates the data key in the same write, which is the only way a
// removal means anything: the removed holder's wrapped copy is of a key the file no longer uses.
//
// The returned string is what the command prints about the recovery copy beside the file: re-sealed
// under the new generation, removed because nothing could open it, removed because it would not
// parse, absent, or kept because it is a v1 artefact.
//
// Refusals, all of them before any write: the last passphrase slot (ErrLastPassphraseSlot), an id
// no slot carries (ErrSlotNotFound), and a slot of an unknown type anywhere else in the header
// (ErrUnknownSlotPresent) - the rotation has to re-wrap every surviving slot, and nothing here can
// wrap one it does not understand. Removing the unknown slot ITSELF is allowed, and is the way out.
func (v *Vault) RemoveSlot(id string, ks KeySource) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.regenerateLocked(ks, id, "remove-slot")
}

// Rotate draws a new data key and re-wraps it into every slot, then re-seals the payload under it.
// Every slot must be reachable: a kek-file slot whose key this process cannot read, or a slot of a
// type this binary does not know, is a refusal naming the slot, and there is deliberately no flag
// that drops it instead - dropping a slot is RemoveSlot, by that name, with its own `.bak` handling.
//
// The recovery copy is handled exactly as RemoveSlot handles it; the action is logged (op=bak)
// rather than returned, because a rotation's caller has no slot to report about.
func (v *Vault) Rotate(ks KeySource) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.regenerateLocked(ks, "", "rotate")
	return err
}

// regenerateLocked is RemoveSlot's and Rotate's shared body: drop a slot if asked, re-wrap every
// survivor under a fresh data key, deal with the recovery copy, then write the file once.
//
// The order is the spec's, and the two halves of it are not interchangeable. Every refusal and
// every sealer is resolved and PROVED - each sealer wraps a throwaway key before the real one is
// drawn - while the file on disk is still untouched; only then is the `.bak` re-sealed or deleted,
// and only after that does the new generation become visible. A crash between those last two leaves
// the file the command started with, which is the harmless half of the window.
//
// Caller holds v.mu.
func (v *Vault) regenerateLocked(ks KeySource, dropID, op string) (string, error) {
	h, slots, err := v.v2Locked()
	if err != nil {
		return "", err
	}
	var dropped Slot
	if dropID != "" {
		found := false
		for _, s := range slots {
			if s.ID == dropID {
				dropped, found = s, true
			}
		}
		if !found {
			return "", fmt.Errorf("%w: %s", ErrSlotNotFound, dropID)
		}
	}
	survivors := make([]Slot, 0, len(slots))
	for _, s := range slots {
		if s.ID != dropID {
			survivors = append(survivors, s)
		}
	}
	if dropped.Type == slotTypePassphrase && countPassphraseSlots(survivors) == 0 {
		return "", ErrLastPassphraseSlot
	}
	// The same rule from the other direction, and it is not redundant. A v2 file with no passphrase
	// slot at all can be OPENED - a hand-damaged header has to be readable to be repairable - and on
	// such a file neither the clause above nor anything else here fires, because the slot being
	// removed is not a passphrase slot. The writer refuses it (ErrNoRecoverySlot, from
	// marshalHeader), but the writer is reached AFTER the recovery copy has been dealt with, and the
	// delete branch of that step is not undoable: the operator would get a clean refusal and no
	// .bak. Checked here, before a key is drawn and before anything is touched.
	if countPassphraseSlots(survivors) == 0 {
		return "", ErrNoRecoverySlot
	}
	// Unknown survivors first and on their own: "this is the wrong binary for this file" is a
	// different instruction from "this host cannot reach a key", and an operator handed both at once
	// acts on neither.
	var unknown []string
	for _, s := range survivors {
		if !knownSlotType(s.Type) {
			unknown = append(unknown, fmt.Sprintf("%s (type %s)", s.ID, s.Type))
		}
	}
	if len(unknown) > 0 {
		return "", fmt.Errorf("%w: %s cannot be re-wrapped by this binary; remove it with `server vault remove-slot <id>`",
			ErrUnknownSlotPresent, strings.Join(unknown, ", "))
	}
	sealers, err := proveSealers(ks, survivors, h)
	if err != nil {
		return "", err
	}

	// The new generation. Both values are drawn after every refusal, so a refused command has not
	// even generated a key.
	newDEK := make([]byte, keyLen)
	if _, rerr := randRead(newDEK); rerr != nil {
		return "", fmt.Errorf("vault: rotate: data key: %w", rerr)
	}
	defer zero(newDEK)
	newDEKID := make([]byte, dekIDLen)
	if _, rerr := randRead(newDEKID); rerr != nil {
		return "", fmt.Errorf("vault: rotate: dek id: %w", rerr)
	}
	kept := make([]json.RawMessage, 0, len(h.Slots))
	for _, elem := range h.Slots {
		var probe struct {
			ID string `json:"id"`
		}
		if uerr := json.Unmarshal(elem, &probe); uerr != nil {
			return "", errCorrupt
		}
		if probe.ID != dropID {
			kept = append(kept, elem)
		}
	}
	newHeader := Header{V: headerVersion,
		DEK:   DEKInfo{ID: encB64(newDEKID), Created: nowString()},
		Slots: kept}
	changed := make(map[string]Slot, len(survivors))
	for i, s := range survivors {
		slotID, derr := base64.StdEncoding.DecodeString(s.ID)
		if derr != nil || len(slotID) != slotIDLen {
			return "", errCorrupt
		}
		wrap, serr := sealers[i].seal(newDEK, slotAAD(v2VaultMagic, newDEKID, slotID, s.Type))
		if serr != nil {
			return "", serr
		}
		next := s
		next.Wrap = wrap
		changed[s.ID] = next
	}
	newAEAD, err := payloadAEAD(newDEK)
	if err != nil {
		return "", err
	}

	// (ii) the recovery copy, before the new generation is visible on disk.
	bakResult, err := resealBakWith(v.file.path, magic, v.file.dek, newDEK, newAEAD, newHeader, changed, ks)
	if err != nil {
		return "", err
	}

	// (iii) the new generation. The in-memory state is advanced first because writeV2 seals the
	// payload under the header it is about to write; a failure puts all of it back, and the file on
	// disk is untouched because every refusal is already behind us and replaceFile is atomic.
	prevDEK, prevAEAD, prevHeader, prevRaw := v.file.dek, v.file.aead, v.file.header, v.file.rawHeader
	v.file.dek, v.file.aead, v.file.header = newDEK, newAEAD, newHeader
	if err := v.saveLocked(changed); err != nil {
		v.file.dek, v.file.aead, v.file.header, v.file.rawHeader = prevDEK, prevAEAD, prevHeader, prevRaw
		return bakResult, err
	}
	// newDEK is this vault's key from here on, so the deferred zero above must not reach it: the
	// sealed file keeps a copy of its own.
	v.file.dek = append([]byte(nil), newDEK...)
	// One audit line per run, in keys logx already allows. A removal names the slot it removed; a
	// rotation has no slot to name, and an empty value would read as one.
	args := []any{"op", op, "result", "rotated", "slots", len(survivors)}
	if dropID != "" {
		args = append(args, "slot", dropID, "slottype", dropped.Type)
	}
	logger.Info("vault: data key rotated", args...)
	return bakResult, nil
}

// proveSealers resolves a sealer for every slot and proves each one can actually wrap, by sealing a
// throwaway key under a throwaway slot AAD. The probe is the point: a kek-file opener can be
// present and refuse, and DPAPI can be unavailable, and finding either one halfway through a
// generation change would leave a file whose slots do not all open it. Every reason is collected so
// an operator is told about all of their unreachable slots at once, not the first.
//
// A passphrase slot gets a second, stronger probe against the CURRENT header h: the one passphrase
// this run holds must actually OPEN the slot before the slot is re-wrapped under it. Two
// independent passphrase slots are a designed shape - a second operator, and the staged rotation
// the spec names - and a run holding one of the two passphrases could otherwise re-wrap the other
// slot under its own, which locks the second operator out and hands this passphrase a second slot.
// That is a silent change to who can open the vault, so it is a refusal naming the slot, and the
// way out is `remove-slot` of that slot (it is not the last passphrase slot) or the passphrase for it.
func proveSealers(ks KeySource, slots []Slot, h Header) ([]slotSealer, error) {
	ss := &sealerSet{ks: ks}
	out := make([]slotSealer, len(slots))
	probeDEK := make([]byte, keyLen)
	probeID := make([]byte, dekIDLen)
	var reasons []string
	var unreachable, unknownType, other error
	for i, s := range slots {
		sealer, err := ss.sealerFor(s)
		if err == nil && s.Type == slotTypePassphrase {
			err = proveOpens(s, h, ss.pass)
		}
		if err == nil {
			slotID, derr := base64.StdEncoding.DecodeString(s.ID)
			if derr != nil || len(slotID) != slotIDLen {
				return nil, errCorrupt
			}
			_, err = sealer.seal(probeDEK, slotAAD(v2VaultMagic, probeID, slotID, s.Type))
		}
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", s.ID, err))
			switch {
			case errors.Is(err, ErrKEKUnreachable):
				unreachable = err
			case errors.Is(err, ErrUnknownSlotPresent):
				unknownType = err
			default:
				other = err
			}
			continue
		}
		out[i] = sealer
	}
	if len(reasons) == 0 {
		return out, nil
	}
	// One sentinel for the whole refusal, chosen so the CLI's exit code and the operator's next step
	// match the most actionable cause. The text names every slot either way.
	lead := other
	switch {
	case unreachable != nil:
		lead = ErrKEKUnreachable
	case unknownType != nil:
		lead = ErrUnknownSlotPresent
	}
	return nil, fmt.Errorf("%w: cannot re-wrap every slot (%s)", lead, strings.Join(reasons, "; "))
}

// proveOpens reports whether pass unwraps this passphrase slot under the header it is in today. The
// data key it recovers is thrown away immediately: this is an authorisation check on the slot, not a
// key the caller needs - the new generation's key is drawn after every refusal.
//
// ErrNoKey rather than ErrBadKey: nothing here is a wrong passphrase for the FILE (the file is open),
// it is a slot this run holds no key for, which is the same shape as a kek-file slot this host cannot
// reach. It also maps to the console's exit 2 and is one of the refusals that provably wrote nothing.
func proveOpens(s Slot, h Header, pass string) error {
	aad, err := slotAADOf(h, s)
	if err != nil {
		return err
	}
	dek, uerr := (passphraseSlotOpener{pass: pass}).Unwrap(s, aad)
	if uerr != nil {
		return fmt.Errorf("%w: this run's passphrase does not open passphrase slot %s, so re-wrapping it "+
			"would retype it to this passphrase; remove that slot or supply its passphrase", ErrNoKey, s.ID)
	}
	zero(dek)
	return nil
}

// ChangePassphrase re-wraps the SAME data key under a new passphrase, with a fresh argon2id salt.
// Nothing else changes: the data key, the dek.id, every machine slot and the payload stay exactly
// as they were, so this is a cheap operation and not a rotation in disguise.
//
// Every passphrase slot the OLD passphrase opens is re-wrapped. A second passphrase slot belonging
// to another operator is left alone, which is what makes two independent passphrase slots useful.
//
// Documented behaviour, not a bug: a v1 copy left in the data dir (`vault.bin.v1.<ts>`, a v1
// `.bak`) is a passphrase-only envelope of its own, and the OLD passphrase still opens it.
// `status` says so while any exists and `finalize-migration` is what ends it.
func (v *Vault) ChangePassphrase(old, next string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	h, slots, err := v.v2Locked()
	if err != nil {
		return err
	}
	if next == "" {
		return fmt.Errorf("%w: the new passphrase is empty", ErrNoKey)
	}
	if countPassphraseSlots(slots) == 0 {
		return ErrNoRecoverySlot
	}
	changed := make(map[string]Slot, 1)
	for _, s := range slots {
		if s.Type != slotTypePassphrase {
			continue
		}
		aad, aerr := slotAADOf(h, s)
		if aerr != nil {
			return aerr
		}
		dek, uerr := (passphraseSlotOpener{pass: old}).Unwrap(s, aad)
		if uerr != nil {
			// Not this slot's passphrase. A second operator's slot is none of this run's business.
			continue
		}
		zero(dek)
		salt := make([]byte, saltLen)
		if _, rerr := randRead(salt); rerr != nil {
			return fmt.Errorf("vault: change-passphrase: salt: %w", rerr)
		}
		params := Argon2Params{T: argonTime, M: argonMem, P: argonPar, Salt: encB64(salt)}
		sealer := &passphraseSealer{pass: next, params: params}
		wrap, serr := sealer.seal(v.file.dek, aad)
		if serr != nil {
			return serr
		}
		nextSlot := s
		nextSlot.Argon2id = &params
		nextSlot.Wrap = wrap
		changed[s.ID] = nextSlot
	}
	if len(changed) == 0 {
		return fmt.Errorf("%w: the passphrase given opened no passphrase slot", ErrBadKey)
	}
	if err := v.saveLocked(changed); err != nil {
		return err
	}
	logger.Info("vault: passphrase changed", "op", "change-passphrase", "result", "changed",
		"slots", len(changed))
	return nil
}

// countPassphraseSlots counts the decoded slots a passphrase can open.
func countPassphraseSlots(slots []Slot) int {
	n := 0
	for _, s := range slots {
		if s.Type == slotTypePassphrase {
			n++
		}
	}
	return n
}

// saveLocked writes the accounts back with a slot change applied to the header. It is the v2-only
// sibling of save: a nil changed is an ordinary save, and every slot the caller did not name is
// re-emitted from the bytes it arrived as. Caller holds v.mu.
func (v *Vault) saveLocked(changed map[string]Slot) error {
	plain, err := v.accountsJSON()
	if err != nil {
		return err
	}
	return v.file.writeV2(magic, plain, changed)
}

// resealBakWith deals with the recovery copy beside path before a new generation becomes visible.
//
// A `.bak` is the same sealed envelope the file was, so after a slot removal it would still open
// with the key that was just removed. It is therefore opened - with the old data key when its
// generation matches, or with any slot the key source can still use when it does not - re-sealed
// under the new data key and the new header, and written back. Bytes nothing can open, or nothing
// can parse, are deleted instead, and both outcomes are printed and logged.
//
// A v1 `.bak` is left alone: it is a pre-migration artefact, deleting it would take the v1 rollback
// with it, and re-sealing it would quietly turn a v1 copy into a v2 file.
func resealBakWith(livePath, magicStr string, oldDEK, newDEK []byte, newAEAD cipher.AEAD,
	newHeader Header, changed map[string]Slot, ks KeySource) (string, error) {
	bak := livePath + bakSuffix
	data, err := os.ReadFile(filepath.Clean(bak))
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
		return bakAbsent, nil
	}
	if err != nil {
		return "", fmt.Errorf("vault: read %s: %w", filepath.Base(bak), err)
	}
	v2 := v2Magic(magicStr)
	if !bytes.HasPrefix(data, []byte(v2)) {
		if bytes.HasPrefix(data, []byte(magicStr)) {
			logger.Info("vault: recovery copy kept", "op", "bak", "result", "kept", "format", FormatV1)
			return bakKeptV1, nil
		}
		return removeBak(bak, bakRemovedCorrupt, "corrupt-header")
	}
	plain, reason, ok := openBakPayload(data, magicStr, oldDEK, ks)
	if !ok {
		if reason == "corrupt-header" {
			return removeBak(bak, bakRemovedCorrupt, reason)
		}
		return removeBak(bak, bakRemovedUnopenable, reason)
	}
	staged := &sealed{path: bak, dek: newDEK, aead: newAEAD, header: newHeader}
	if err := staged.writeV2(magicStr, plain, changed); err != nil {
		return "", err
	}
	logger.Info("vault: recovery copy re-sealed", "op", "bak", "result", "resealed")
	return bakResealed, nil
}

// openBakPayload decrypts a v2 recovery copy, trying the data key the live file is being replaced
// from first and then every slot the key source can use. ok is false for bytes that will not parse
// and for bytes nothing available opens, and the reason says which: the caller deletes both and the
// two cases send an operator to different places.
func openBakPayload(data []byte, magicStr string, oldDEK []byte, ks KeySource) ([]byte, string, bool) {
	aad, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return nil, "corrupt-header", false
	}
	h, slots, err := parseHeader(headerJSON)
	if err != nil {
		return nil, "corrupt-header", false
	}
	body := data[len(aad):]
	// The same generation: one AEAD open and no key resolution at all, which is the normal case.
	if aead, aerr := payloadAEAD(oldDEK); aerr == nil {
		if plain, oerr := aead.Open(nil, body[:nonceLen], body[nonceLen:], aad); oerr == nil {
			return plain, "", true
		}
	}
	// An earlier generation. It is re-sealed rather than deleted whenever a slot still opens it:
	// deleting a copy that is recoverable is exactly the loss the printed line has to be able to
	// say did not happen (Review Focus 4).
	dek, rerr := recoverDEK(magicStr, h, slots, ks)
	if rerr != nil {
		return nil, "unopenable", false
	}
	defer zero(dek)
	aead, aerr := payloadAEAD(dek)
	if aerr != nil {
		return nil, "unopenable", false
	}
	plain, oerr := aead.Open(nil, body[:nonceLen], body[nonceLen:], aad)
	if oerr != nil {
		return nil, "unopenable", false
	}
	return plain, "", true
}

// settleReseal is the real resealBak: the step SettleVaultOp runs on a journal that reached
// StageRenamed. There the new generation is already on disk, so the live file's own data key and
// header are what the copy beside it must be re-sealed under - the settle has no other record of
// them, which is why it reads them back rather than being handed them.
//
// Anything it cannot read falls back to the delete-only behaviour the seam shipped with: a live
// file that is not a readable v2 file, or one no slot opens, leaves nothing to re-seal under, and a
// .bak openable by a key that was just removed is the hole the ordering exists to close. The
// command prints which happened.
func settleReseal(path string, _ VaultOp, ks KeySource) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return removeBakOnly(path, VaultOp{}, ks)
	}
	magicStr := fileKind(data)
	if v2 := v2Magic(magicStr); v2 == "" || !bytes.HasPrefix(data, []byte(v2)) {
		return removeBakOnly(path, VaultOp{}, ks)
	}
	_, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return removeBakOnly(path, VaultOp{}, ks)
	}
	h, slots, err := parseHeader(headerJSON)
	if err != nil {
		return removeBakOnly(path, VaultOp{}, ks)
	}
	dek, err := recoverDEK(magicStr, h, slots, ks)
	if err != nil {
		return removeBakOnly(path, VaultOp{}, ks)
	}
	defer zero(dek)
	aead, err := payloadAEAD(dek)
	if err != nil {
		return removeBakOnly(path, VaultOp{}, ks)
	}
	return resealBakWith(path, magicStr, dek, dek, aead, h, nil, ks)
}

// removeBak deletes a recovery copy and reports what it was. The reason is from a closed set and
// goes in the log line; the printed string is the one the runbook quotes.
func removeBak(path, result, reason string) (string, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("vault: remove %s: %w", filepath.Base(path), err)
	}
	logger.Warn("vault: recovery copy removed", "op", "bak", "result", "removed", "reason", reason)
	return result, nil
}
