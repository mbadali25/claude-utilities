package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

// newerVaultMagic and newerKeyringMagic are the magic strings the next format version writes.
// This binary cannot read either file; it recognises the magic only so it can say which binary
// wrote it. They are deliberately not in vault.go's const block with `magic`: nothing here may
// ever write one.
const (
	newerVaultMagic   = "CSV2"
	newerKeyringMagic = "CSK2"
)

// ErrNewerFormat means the file was written by a server newer than this one. It is not errCorrupt:
// "malformed vault file" sends an operator looking for a corrupt disk or a wrong passphrase, and
// the one thing that must not happen is a correct passphrase being rotated out of confusion.
var ErrNewerFormat = errors.New("vault: written by a newer server; downgrade with `server vault downgrade` on the newer binary")

// newerMagic is the magic the next format version writes for the same kind of file, or "" for a
// magic with no newer counterpart. One function, so there is no place a reader can accept the
// other file's newer magic.
func newerMagic(magicStr string) string {
	switch magicStr {
	case magic:
		return newerVaultMagic
	case keyringMagic:
		return newerKeyringMagic
	}
	return ""
}

// deriveAEAD derives the file key from the passphrase and salt and returns the AEAD.
func deriveAEAD(pass string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(pass), salt, argonTime, argonMem, argonPar, keyLen)
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
func openSealed(path, magicStr, keyEnv string) (*sealed, []byte, error) {
	data, readErr := os.ReadFile(filepath.Clean(path))
	// Before the header is parsed, before anything is allocated for it, before the key is derived
	// and - the whole point of being first - before the passphrase is even looked for: a file
	// written by a newer server says so, rather than looking malformed or looking like a missing
	// key. Reading four bytes of magic needs no passphrase, and telling an operator to "set
	// environment variable CLAUDESWAP_KEY" for a file no key can open is how a correct passphrase
	// ends up rotated out of confusion. Keyed on the magic this caller asked for, so a keyring's
	// magic in a vault's path stays errCorrupt. HasPrefix, not a slice compare: a file shorter
	// than the magic must not index past its end. A truncated CSV2 file is still reported as
	// newer - the magic alone names the writer, and this binary cannot tell a truncated v2 file
	// from a complete one either way.
	if nm := newerMagic(magicStr); readErr == nil && nm != "" && bytes.HasPrefix(data, []byte(nm)) {
		return nil, nil, ErrNewerFormat
	}
	// Everything below here keeps the order it had before the magic test moved above it: a file
	// this binary might be able to read asks for the passphrase first, so a missing key still
	// wins over errCorrupt and over an unreadable file, as it always did.
	pass := os.Getenv(keyEnv)
	if pass == "" {
		return nil, nil, fmt.Errorf("%w: set environment variable %s", ErrNoKey, keyEnv)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("vault: read: %w", readErr)
	}
	s := &sealed{path: path}
	if len(data) == 0 {
		s.salt = make([]byte, saltLen)
		if _, err := rand.Read(s.salt); err != nil {
			return nil, nil, fmt.Errorf("vault: salt: %w", err)
		}
		var err error
		s.aead, err = deriveAEAD(pass, s.salt)
		return s, nil, err
	}
	hdr := len(magicStr) + saltLen
	if len(data) < hdr+nonceLen || string(data[:len(magicStr)]) != magicStr {
		return nil, nil, errCorrupt
	}
	s.salt = append([]byte(nil), data[len(magicStr):hdr]...)
	var err error
	if s.aead, err = deriveAEAD(pass, s.salt); err != nil {
		return nil, nil, err
	}
	plain, err := s.aead.Open(nil, data[hdr:hdr+nonceLen], data[hdr+nonceLen:], data[:hdr])
	if err != nil {
		return nil, nil, ErrBadKey
	}
	return s, plain, nil
}

// bakSuffix names the one-deep recovery copy kept beside a sealed file before a destructive write.
const bakSuffix = ".bak"

// write seals plain with a fresh nonce and replaces the file atomically, owner-only.
func (s *sealed) write(magicStr string, plain []byte) error {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
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
