package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// v2VaultMagic and v2KeyringMagic are the v2 format's magic strings. This binary now reads both -
// the header parser lives in slots.go - and writes neither: `server vault init` is the only thing
// that will ever create a v2 file. They are deliberately not in vault.go's const block with
// `magic`, which is the one magic a write path here may use.
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

// sealed is one encrypted file: its path, its salt and its AEAD.
type sealed struct {
	path string
	salt []byte
	aead cipher.AEAD
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
		return openSealedV2(data)
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

// openSealedV2 reads a v2 file's header and says what it found.
//
// It does not yet recover the data key. The slot wrap and the three slot openers are later tasks,
// so a well-formed v2 header this binary can parse has no slot it can unwrap and the answer is
// ErrBadKey, naming the slot types it would have tried and no value from any of them. That is the
// honest answer and it is the one the spec's open flow gives when no slot works; what changes when
// the openers land is that some of them succeed.
//
// No passphrase is asked for on this path at all: every answer here is reachable from the bytes.
func openSealedV2(data []byte) (*sealed, []byte, error) {
	_, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return nil, nil, err
	}
	_, slots, err := parseHeader(headerJSON)
	if err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("%w: no slot could unwrap the data key (slot types tried: %s)",
		ErrBadKey, slotTypeList(slots))
}

// slotTypeList names the slot kinds in try order, for the one error an operator sees when nothing
// opened the file. Types only: a slot's id, its wrapped bytes and its parameters never appear in an
// error string.
func slotTypeList(slots []Slot) string {
	if len(slots) == 0 {
		return "none"
	}
	out := make([]string, 0, len(slots))
	for _, s := range tryOrder(slots) {
		out = append(out, s.Type)
	}
	return strings.Join(out, ", ")
}

// bakSuffix names the one-deep recovery copy kept beside a sealed file before a destructive write.
const bakSuffix = ".bak"

// write seals plain with a fresh nonce and replaces the file atomically, owner-only.
func (s *sealed) write(magicStr string, plain []byte) error {
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
