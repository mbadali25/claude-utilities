package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"

	"claude-utilities/internal/credfile"
)

// This file holds the one copy of the at-rest crypto: argon2id key derivation from the
// environment passphrase, AES-256-GCM with the header bound as additional data, and the
// temp-then-rename write with an owner-only mode. The account vault (vault.go) and the tunnel
// keyring (keyring.go) both use it, under different magic strings and different files.
//
// Separate files, deliberately: adding a payload to vault.bin would change its format, and an
// older server binary would then read it as corrupt - which deletes the rollback the tunnels
// migration depends on at every step.

// v2VaultMagic and v2KeyringMagic are the v2 format's magic strings. This binary reads both - the
// header parser lives in slots.go - and writes one back only over a file that already carried it:
// `server vault init` is the only thing that will ever CREATE a v2 file, and writeV2 is reachable
// only from a sealed that arrived as v2 (see write). They are deliberately not in vault.go's const
// block with `magic`, which is the one magic the v1 write path may use.
const (
	v2VaultMagic   = "CSV2"
	v2KeyringMagic = "CSK2"
)

// ErrNewerFormat means the file was written by a server newer than this one. Since v2 landed the
// condition is the header's `v`, not the magic: a `v` other than 2, or a top-level member this
// binary does not know, is a header written by something newer. It is not errCorrupt: "malformed
// vault file" sends an operator looking for a corrupt disk or a wrong passphrase, and the one
// thing that must not happen is a correct passphrase being rotated out of confusion.
var ErrNewerFormat = errors.New("vault: written by a newer server; downgrade with `server vault downgrade` on the newer binary")

// ErrMalformed is the exported face of errCorrupt, for the one caller outside this package that
// has to tell a file this binary cannot parse from a runtime failure: cmd/server maps it to exit 4,
// the same code a newer format gets, because a restart cannot make either readable. It is the same
// error value, so errors.Is matches both names.
//
// Exported rather than renamed: errCorrupt is asserted by name in a dozen tests here, and a
// rename would churn every one of them for no behaviour.
//
// Being the same value as errCorrupt widens exit 4 deliberately, and that is worth stating because
// it is wider than the v2 header the spec's bound was written for. errCorrupt is also what the v1
// path answers for a bad magic, a truncated file or a header shorter than magic+salt+nonce, so
// those now exit 4 where they used to exit 1. That is the right code for all of them on the same
// reasoning the spec gives for an out-of-bounds v2 number: a restart cannot make the bytes
// readable, so the service units must not retry it, and "malformed" must never be reported as a
// bad key, because an operator pushed towards rotating a correct passphrase is an Anti-goal.
// The spec's exit table does not yet carry a `malformed` row for 4; the code and the runbook do.
var ErrMalformed = errCorrupt

// v2Magic is the v2 magic for the same kind of file as magicStr, or "" for a magic with no v2
// counterpart. One function, so there is no place a reader can accept the other file's v2 magic.
func v2Magic(magicStr string) string {
	switch magicStr {
	case magic:
		return v2VaultMagic
	case keyringMagic:
		return v2KeyringMagic
	}
	return ""
}

// argon2IDKey is argon2.IDKey unless a test replaces it. The seam exists so a test can prove the
// header's recorded cost never reaches the derivation: a parameter out of bounds must be refused on
// the parsed integer, not by the allocator inside argon2id.
var argon2IDKey = argon2.IDKey

// deriveAEAD derives the file key from the passphrase and salt and returns the AEAD.
func deriveAEAD(pass string, salt []byte) (cipher.AEAD, error) {
	key := argon2IDKey([]byte(pass), salt, argonTime, argonMem, argonPar, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	return aead, nil
}

// sealed is one encrypted file: its path, its AEAD, and whichever of the two formats' state it was
// opened under.
//
// v1 fills salt and leaves dek, rawHeader and header zero; v2 fills the other three and leaves salt
// nil. dek is the discriminator the writer branches on, and that is the whole reason nothing a v1
// open produces can take the v2 write path: a file that did not arrive as v2 has no data key, so
// there is no input to Open that turns a CSV1 file or an absent one into a v2 write.
//
// It carries no lock and is NOT safe for concurrent use. writeV2 advances rawHeader and header after
// a successful replaceFile, so two writers on one sealed could seal a payload under a header the
// other has already replaced. The owners hold the lock instead: every caller of write goes through
// Vault.save under v.mu (vault.go) or Keyring.saveLocked under k.mu (keyring.go), which is what
// makes Vault's "safe for concurrent use" true. A future caller must hold one of those.
type sealed struct {
	path string
	salt []byte
	aead cipher.AEAD

	// dek is the v2 data encryption key, in memory only. The AEAD above is derived from it; the key
	// itself is kept because a slot operation has to re-wrap it (Task 3b.2).
	dek []byte
	// rawHeader is the payload's additional data: the first 8 + hdrLen bytes exactly as they were
	// read from disk, or as they were last written. Never a re-marshal of header - the payload is
	// sealed under the bytes that were written, and rebuilding them from a parse would be trusting
	// the parse to be lossless, which is what an attacker would attack.
	rawHeader []byte
	// header is the parsed header. Its Slots are the raw JSON elements, which IS the retention
	// mechanism: marshalHeader re-emits every untouched slot from them, so a slot of a type this
	// binary does not know survives a write byte for byte.
	header Header
}

// openSealed reads path and returns the sealed file plus its plaintext. A missing or empty file
// yields a fresh salt and nil plaintext, and nothing is written to disk. magic must be 4 bytes.
func openSealed(path, magicStr string, ks KeySource) (*sealed, []byte, error) {
	data, readErr := os.ReadFile(filepath.Clean(path))
	// The v2 branch comes before the passphrase is even looked for, and that ordering is the point:
	// reading the magic and parsing the header need no passphrase, and telling an operator to "set
	// environment variable CLAUDESWAP_KEY" for a file whose header is unreadable is how a correct
	// passphrase ends up rotated out of confusion. Keyed on the magic this caller asked for, so a
	// keyring's magic in a vault's path stays errCorrupt. HasPrefix, not a slice compare: a file
	// shorter than the magic must not index past its end.
	if v2 := v2Magic(magicStr); readErr == nil && v2 != "" && bytes.HasPrefix(data, []byte(v2)) {
		return openSealedV2(path, magicStr, data, ks)
	}
	// Everything below here keeps the order it had before the magic test moved above it: a file
	// this binary might be able to read asks for the passphrase first, so a missing key still
	// wins over errCorrupt and over an unreadable file, as it always did.
	//
	// The passphrase comes from the KeySource and its error is returned unchanged: the source knows
	// what it tried and names it (EnvKey names the variable, PromptKey says stdin was empty), and
	// wrapping that again here would bury the one detail an operator acts on. Machine key slots are
	// not consulted: a v1 header has none, so there is nothing for an opener to unwrap.
	pass, err := ks.Passphrase()
	if err != nil {
		return nil, nil, err
	}
	// A KeySource that breaks its own contract - empty passphrase, no error - must not get a key
	// derived from "": that key would open nothing today and would re-seal the vault under a
	// passphrase nobody chose.
	if pass == "" {
		return nil, nil, fmt.Errorf("%w: the key source returned an empty passphrase", ErrNoKey)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("vault: read: %w", readErr)
	}
	s := &sealed{path: path}
	if len(data) == 0 {
		s.salt = make([]byte, saltLen)
		if _, rerr := randRead(s.salt); rerr != nil {
			return nil, nil, fmt.Errorf("vault: salt: %w", rerr)
		}
		s.aead, err = deriveAEAD(pass, s.salt)
		return s, nil, err
	}
	hdr := len(magicStr) + saltLen
	if len(data) < hdr+nonceLen || string(data[:len(magicStr)]) != magicStr {
		return nil, nil, errCorrupt
	}
	s.salt = append([]byte(nil), data[len(magicStr):hdr]...)
	if s.aead, err = deriveAEAD(pass, s.salt); err != nil {
		return nil, nil, err
	}
	plain, oerr := s.aead.Open(nil, data[hdr:hdr+nonceLen], data[hdr+nonceLen:], data[:hdr])
	if oerr != nil {
		return nil, nil, ErrBadKey
	}
	return s, plain, nil
}

// openSealedV2 opens a v2 file: it parses the header, walks the slots in try order until one
// produces the data key, then opens the payload under that key with the header's own bytes as the
// additional data.
//
// The order of the first two steps is the design and not an implementation detail. Reading the
// magic and parsing the header need no key at all, so a file this binary cannot read is answered
// from the bytes and nothing is ever asked for a passphrase on the way: telling an operator to set
// CLAUDESWAP_KEY for a header that is malformed, or written by a newer server, is how a correct
// passphrase ends up rotated out of confusion, which is a stated Anti-goal.
func openSealedV2(path, magicStr string, data []byte, ks KeySource) (*sealed, []byte, error) {
	aad, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return nil, nil, err
	}
	h, slots, err := parseHeader(headerJSON)
	if err != nil {
		return nil, nil, err
	}
	// A slot of a type this binary does not know is skipped, never refused, and one warning per
	// skipped slot says so. It comes before the attempt rather than after the failure: a header
	// written by a newer server may well open through one of its known slots, and the operator still
	// wants to know a slot was passed over.
	warnSkippedSlots(h)
	dek, err := recoverDEK(magicStr, h, slots, ks)
	if err != nil {
		return nil, nil, err
	}
	aead, err := payloadAEAD(dek)
	if err != nil {
		zero(dek)
		return nil, nil, err
	}
	// The payload is everything after the header: a 12-byte nonce then the sealed bytes. rawHeaderOf
	// has already proved there are at least nonceLen+gcmTagLen of them.
	body := data[len(aad):]
	plain, oerr := aead.Open(nil, body[:nonceLen], body[nonceLen:], aad)
	if oerr != nil {
		// The slot wrap authenticated, so the data key is this file's. A payload that then refuses
		// means the payload or a header byte that is not in any slot's AAD was changed - the file's
		// own GCM tag is the one thing that covers those - and "wrong key or tampered file" is
		// exactly that. Not errCorrupt: the bytes parse, and the file is not malformed.
		zero(dek)
		return nil, nil, fmt.Errorf("%w: the payload did not open under this file's data key", ErrBadKey)
	}
	s := &sealed{path: path, aead: aead, dek: dek,
		rawHeader: append([]byte(nil), aad...), header: h}
	return s, plain, nil
}

// recoverDEK walks the slots and returns the data encryption key the first one to open gives up.
//
// The try order is tryOrder's: machine-held slots first in header order, then every passphrase slot.
// A service has no passphrase and must succeed on a machine slot, so a passphrase slot tried first
// would only produce a prompt it cannot answer; an operator at a console has one, and spending it on
// a slot that was going to work anyway is a prompt nobody needed.
//
// Both key sources are consulted lazily and at most once. ks.Passphrase() is called when the first
// passphrase slot is reached and never again - argon2id is deliberately expensive, and eight
// passphrase slots are allowed - and ks.Machine() is called when the first machine slot is reached,
// so a passphrase-only vault never starts a systemd-creds child to learn it had no use for one.
//
// Which error comes back when nothing opens is a decision, not a fallthrough, because the three
// answers send an operator in three different directions:
//
//   - ErrKEKUnreachable, if a machine opener reported one. The key is configured and this process
//     may not have it; the fix is a root shell or a mode bit. It must never be reported as a bad
//     key, which reads as "rotate something that is very probably correct". A later slot that OPENS
//     still wins, though - the passphrase is the designed recovery rung for exactly this case.
//   - the key source's own error, if not a single slot could be attempted. Nothing was tried, so
//     there is no key to call bad, and the actionable line is the one EnvKey or PromptKey wrote
//     (which variable, or that stdin was empty).
//   - ErrBadKey otherwise, naming the slot kinds that were tried and no value from any of them.
//
// "Tried" means handed to an opener, and the list is collected as the walk runs rather than derived
// from the header afterwards. The two are not the same set: a slot of a kind this host has no opener
// for, and a slot of a type this binary does not know, are never given a key, and reporting them as
// tried sends an operator after a credential that was never asked for. The spec's service line is
// `no slot could unwrap (tried: dpapi)` on a restored data dir whose header also carries the
// passphrase slot the service cannot use.
func recoverDEK(magicStr string, h Header, slots []Slot, ks KeySource) ([]byte, error) {
	v2 := v2Magic(magicStr)
	if v2 == "" {
		// Unreachable: openSealed only takes this branch for a magic that has a v2 counterpart.
		return nil, fmt.Errorf("%w: this file kind has no v2 format", errCorrupt)
	}
	dekID, err := base64.StdEncoding.DecodeString(h.DEK.ID)
	if err != nil || len(dekID) != dekIDLen {
		return nil, errCorrupt
	}

	var (
		machine      []SlotOpener
		machineAsked bool
		passOpener   SlotOpener
		passAsked    bool
		passErr      error
		unreachable  error
		tried        []string
		noKey        int
		unknown      int
	)
	for _, s := range tryOrder(slots) {
		// Already warned about by warnSkippedSlots. Nothing here can wrap or unwrap it.
		if !knownSlotType(s.Type) {
			unknown++
			continue
		}
		var op SlotOpener
		if s.Type == slotTypePassphrase {
			if !passAsked {
				passAsked = true
				pass, perr := ks.Passphrase()
				switch {
				case perr != nil:
					passErr = perr
				case pass == "":
					// A KeySource that breaks its own contract - an empty passphrase and no error -
					// must not get a key derived from "": that key would open nothing today and
					// would re-seal the file under a passphrase nobody chose.
					passErr = fmt.Errorf("%w: the key source returned an empty passphrase", ErrNoKey)
				default:
					passOpener = passphraseSlotOpener{pass: pass}
				}
			}
			op = passOpener
		} else {
			if !machineAsked {
				machineAsked = true
				machine = ks.Machine()
			}
			op = openerFor(machine, s.Type)
		}
		// No opener for this kind on this host. Not a failure: it is what a console run looks like
		// on a vault that also has a dpapi slot from the host that created it.
		if op == nil {
			noKey++
			continue
		}
		slotID, derr := base64.StdEncoding.DecodeString(s.ID)
		if derr != nil || len(slotID) != slotIDLen {
			return nil, errCorrupt
		}
		tried = appendKind(tried, s.Type)
		dek, uerr := op.Unwrap(s, slotAAD(v2, dekID, slotID, s.Type))
		if uerr == nil {
			return dek, nil
		}
		// Kept rather than returned, so a later slot that opens still wins.
		if unreachable == nil && errors.Is(uerr, ErrKEKUnreachable) {
			unreachable = uerr
		}
	}
	switch {
	case unreachable != nil:
		return nil, unreachable
	case len(tried) == 0 && passErr != nil:
		return nil, passErr
	}
	return nil, fmt.Errorf("%w: no slot could unwrap the data key (%s)",
		ErrBadKey, triedSummary(tried, noKey, unknown, passErr))
}

// appendKind adds one slot kind to the tried list, keeping try order and refusing a duplicate. Eight
// passphrase slots are allowed, and an operator reading "passphrase, passphrase" learns nothing the
// single name does not say.
func appendKind(kinds []string, kind string) []string {
	for _, k := range kinds {
		if k == kind {
			return kinds
		}
	}
	return append(kinds, kind)
}

// openerFor picks the opener for one slot kind, or nil when this host has none. Matched on Type
// rather than on position: HostKeys omits the openers a host does not have, so the slice's indices
// mean nothing and a kind that is missing must answer "skip this slot", not "use the next opener".
func openerFor(openers []SlotOpener, slotType string) SlotOpener {
	for _, o := range openers {
		if o != nil && o.Type() == slotType {
			return o
		}
	}
	return nil
}

// payloadAEAD builds the AES-256-GCM AEAD the payload is sealed under, straight from the data key.
// No derivation: the DEK is already 32 random bytes, and the per-slot HKDF that separates the wraps
// has nothing to separate here, because there is one payload per file.
func payloadAEAD(dek []byte) (cipher.AEAD, error) {
	if len(dek) != keyLen {
		return nil, fmt.Errorf("%w: the data key is %d bytes, want %d", errCorrupt, len(dek), keyLen)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("vault: payload cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: payload gcm: %w", err)
	}
	return aead, nil
}

// triedSummary is the parenthesised half of the one error an operator sees when nothing opened the
// file: the kinds that were tried, then the two reasons a slot was not, then the key source's own
// reason when a passphrase slot was one of them. Types and counts only: a slot's id, its wrapped
// bytes and its parameters never appear in an error string.
//
// The two untried counts stay apart because they send an operator to different places. noKey is a
// slot of a kind this format defines and this host holds no key for - a dpapi slot on Linux, a
// kek-file slot with no KEK configured - and the fix is to add a slot this host can open, or to open
// it on the host that can. unknown is a slot of a type this binary has never heard of, which says a
// newer server wrote here and this one is the wrong binary for the file.
//
// Every name in tried has passed knownSlotType, so the three fixed strings of this format are the
// only things that can be printed, and the untried slots are counted rather than named. That is the
// point and not an accident: a slot's `type` is up to 255 bytes of attacker-chosen printable ASCII
// from a header that is not authenticated yet, and this string goes to stderr, into a log line and
// into whatever an operator pastes into a ticket. Echoing it back verbatim would hand a crafted
// header a line of the operator's output - which is how a forged instruction or a stray control
// sequence gets in front of a human.
//
// passErr is carried here rather than returned because the walk did try something, so the answer is
// ErrBadKey; dropping the reason the passphrase was never asked for would drop the only actionable
// line (which variable was not set, or that stdin was empty). It is the error's text and not its
// value, so errors.Is still matches ErrBadKey alone and the exit code an absent key maps to is
// unchanged.
func triedSummary(tried []string, noKey, unknown int, passErr error) string {
	var b strings.Builder
	list := "none"
	if len(tried) > 0 {
		list = strings.Join(tried, ", ")
	}
	fmt.Fprintf(&b, "slot types tried: %s", list)
	if noKey > 0 {
		fmt.Fprintf(&b, "; %d this host held no key for", noKey)
	}
	if unknown > 0 {
		fmt.Fprintf(&b, "; %d unknown", unknown)
	}
	if passErr != nil {
		fmt.Fprintf(&b, "; no passphrase was available: %v", passErr)
	}
	return b.String()
}

// bakSuffix names the one-deep recovery copy kept beside a sealed file before a destructive write.
const bakSuffix = ".bak"

// write seals plain with a fresh nonce and replaces the file atomically, owner-only. A file that was
// opened as v2 is written back as v2, under the header it arrived with; everything else is v1.
//
// The branch is on the data key and not on a flag the caller passes, which is what makes the
// downgrade impossible rather than merely unlikely: there is no argument to write that turns a v2
// file into a CSV1 one. (Nor the other way: `server vault init` is the only creator of a v2 file,
// Task 3b.3, so create-on-open stays v1 - see Open's comment.)
func (s *sealed) write(magicStr string, plain []byte) error {
	if s.dek != nil {
		return s.writeV2(magicStr, plain, nil)
	}
	nonce := make([]byte, nonceLen)
	if _, err := randRead(nonce); err != nil {
		return fmt.Errorf("vault: nonce: %w", err)
	}
	header := append([]byte(magicStr), s.salt...)
	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(nonce)
	buf.Write(s.aead.Seal(nil, nonce, plain, header))
	return replaceFile(s.path, buf.Bytes())
}

// writeV2 re-seals a v2 file: it emits the header, draws a fresh payload nonce, seals plain under
// the data key with those header bytes as the additional data, and replaces the file atomically.
//
// changed is the slot operation, keyed by slot id, or nil for an ordinary save. Every slot the
// caller did not name is re-emitted from the bytes it arrived as, so an untouched slot - including
// one of a type this binary does not know - keeps all of its members, their order and their values.
//
// Both of the writer's refusals come from marshalHeader rather than from a second copy of the rules
// here: it parses its own output, so every bound the reader enforces the writer enforces too, and it
// returns ErrNoRecoverySlot for a header with no passphrase slot and errSlotIDMismatch for a
// `changed` entry whose key and whose Slot's own id disagree. Both land BEFORE replaceFile, so a
// refused write leaves the file on disk exactly as it was.
//
// The new header bytes become the new rawHeader, and the payload is sealed under them in the same
// call. That ordering is the one that cannot drift: a slot operation that updated the header but
// sealed the payload under the previous AAD would produce a file that opens its slots and never its
// payload - once, and then never again.
//
// Every write draws its nonce from randRead and nothing reuses one. GCM with a repeated nonce under
// the same key leaks the key stream and the authentication key, and here the plaintext is the whole
// vault.
func (s *sealed) writeV2(magicStr string, plain []byte, changed map[string]Slot) error {
	v2 := v2Magic(magicStr)
	if v2 == "" {
		// Unreachable: a sealed carrying a data key was opened through openSealedV2, which is only
		// reached for a magic that has a v2 counterpart.
		return fmt.Errorf("%w: this file kind has no v2 format", errCorrupt)
	}
	headerJSON, err := marshalHeader(s.header, changed)
	if err != nil {
		return err
	}
	// The parse before the write, so the in-memory header can be advanced after a success without a
	// failure path on the far side of replaceFile. marshalHeader has already parsed these bytes, so
	// this cannot fail; it is here because the Header it returns is what retention reads next time.
	next, _, err := parseHeader(headerJSON)
	if err != nil {
		return err
	}
	if len(headerJSON) > maxHdrLen {
		return errCorrupt
	}
	raw := make([]byte, 0, v2PrefixLen+len(headerJSON))
	raw = append(raw, v2...)
	var n [4]byte
	//nolint:gosec // G115: marshalHeader caps the header at maxHdrLen (64 KiB), re-checked above.
	binary.BigEndian.PutUint32(n[:], uint32(len(headerJSON)))
	raw = append(raw, n[:]...)
	raw = append(raw, headerJSON...)

	nonce := make([]byte, nonceLen)
	if _, err := randRead(nonce); err != nil {
		return fmt.Errorf("vault: nonce: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(raw)
	buf.Write(nonce)
	buf.Write(s.aead.Seal(nil, nonce, plain, raw))
	if err := replaceFile(s.path, buf.Bytes()); err != nil {
		return err
	}
	s.rawHeader, s.header = raw, next
	return nil
}

// backup copies the file's current bytes to path+".bak" before a caller destroys them. It is the
// same sealed envelope, header and all, so the same passphrase opens the copy; nothing is decrypted
// here. A file that does not exist yet, or is empty, has nothing to preserve and is not an error.
//
// One generation deep on purpose: the point is to survive the delete the operator regrets on the
// spot, not to be an archive. A second delete overwrites the copy.
func (s *sealed) backup() error {
	data, err := os.ReadFile(filepath.Clean(s.path))
	if errors.Is(err, os.ErrNotExist) || len(data) == 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: backup read: %w", err)
	}
	return replaceFile(s.path+bakSuffix, data)
}

// replaceFile writes data to a temp file in dst's directory, owner-only, and renames it over dst.
// Both the sealed write and the backup copy go through here, so the mode, the Windows ACL and the
// directory sync cannot drift apart between them.
func replaceFile(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("vault: temp: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		removeQuiet(name)
		return fmt.Errorf("vault: write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil && !isWindowsChmodQuirk(err) {
		return fail(err)
	}
	// Windows: Chmod only toggles read-only, so set an owner-only ACL (no-op elsewhere).
	if err := credfile.RestrictFile(name); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		removeQuiet(name)
		return fmt.Errorf("vault: close: %w", err)
	}
	if err := renameFn(name, dst); err != nil {
		removeQuiet(name)
		return fmt.Errorf("vault: rename: %w", err)
	}
	credfile.SyncDir(dir)
	return nil
}
