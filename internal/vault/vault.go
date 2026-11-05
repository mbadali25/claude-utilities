// Package vault stores account credential blocks in one encrypted file.
// Format: magic | argon2id salt (16) | GCM nonce (12) | AES-256-GCM sealed JSON.
// The header is bound to the ciphertext as additional data. It never logs or
// returns token values, and error text never includes file content.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"claude-utilities/internal/credfile"
)

const (
	magic     = "CSV1"
	saltLen   = 16
	nonceLen  = 12
	keyLen    = 32
	headerLen = len(magic) + saltLen
	argonTime = 3
	argonMem  = 64 * 1024 // KiB
	argonPar  = 4
)

var (
	// ErrNoKey means the key environment variable is unset or empty.
	ErrNoKey = errors.New("vault: encryption key not set")
	// ErrBadKey means the key is wrong or the file was tampered with.
	ErrBadKey = errors.New("vault: cannot decrypt (wrong key or tampered file)")

	errCorrupt = errors.New("vault: malformed vault file")

	// renameFn is replaced in tests to inject write failures.
	renameFn = os.Rename
)

// Account is one stored login. Block is the raw claudeAiOauth JSON.
type Account struct {
	ID       string          `json:"id"`
	Label    string          `json:"label"`
	Identity string          `json:"identity"`
	Block    json.RawMessage `json:"block,omitempty"`
	Updated  time.Time       `json:"updated"`
}

// Vault is an encrypted, file-backed account store safe for concurrent use.
type Vault struct {
	mu       sync.Mutex
	path     string
	salt     []byte
	aead     cipher.AEAD
	accounts map[string]Account
}

// Open loads the vault at path, creating an empty in-memory one if the file
// does not exist or is empty. The key is the value of env var keyEnv. Open
// never writes to disk.
func Open(path, keyEnv string) (*Vault, error) {
	pass := os.Getenv(keyEnv)
	if pass == "" {
		return nil, fmt.Errorf("%w: set environment variable %s", ErrNoKey, keyEnv)
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("vault: read: %w", err)
	}
	v := &Vault{path: path, accounts: map[string]Account{}}
	if len(data) == 0 {
		v.salt = make([]byte, saltLen)
		if _, err := rand.Read(v.salt); err != nil {
			return nil, fmt.Errorf("vault: salt: %w", err)
		}
		return v, v.setKey(pass)
	}
	if len(data) < headerLen+nonceLen || string(data[:len(magic)]) != magic {
		return nil, errCorrupt
	}
	v.salt = append([]byte(nil), data[len(magic):headerLen]...)
	if err := v.setKey(pass); err != nil {
		return nil, err
	}
	nonce := data[headerLen : headerLen+nonceLen]
	plain, err := v.aead.Open(nil, nonce, data[headerLen+nonceLen:], data[:headerLen])
	if err != nil {
		return nil, ErrBadKey
	}
	var list []Account
	if err := json.Unmarshal(plain, &list); err != nil {
		return nil, errCorrupt
	}
	for _, a := range list {
		v.accounts[a.ID] = a
	}
	return v, nil
}

func (v *Vault) setKey(pass string) error {
	key := argon2.IDKey([]byte(pass), v.salt, argonTime, argonMem, argonPar, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("vault: cipher: %w", err)
	}
	v.aead, err = cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("vault: gcm: %w", err)
	}
	return nil
}

func clone(a Account) Account {
	a.Block = append(json.RawMessage(nil), a.Block...)
	if len(a.Block) == 0 {
		a.Block = nil
	}
	return a
}

// Put inserts or replaces an account and persists the vault atomically.
func (v *Vault) Put(a Account) error {
	if a.ID == "" {
		return errors.New("vault: account id required")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, had := v.accounts[a.ID]
	v.accounts[a.ID] = clone(a)
	if err := v.save(); err != nil {
		if had {
			v.accounts[a.ID] = prev
		} else {
			delete(v.accounts, a.ID)
		}
		return err
	}
	return nil
}

// Get returns a copy of the account with the given id.
func (v *Vault) Get(id string) (Account, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	a, ok := v.accounts[id]
	if !ok {
		return Account{}, false
	}
	return clone(a), true
}

// List returns copies of all accounts, including Block, sorted by ID.
func (v *Vault) List() []Account {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Account, 0, len(v.accounts))
	for _, a := range v.accounts {
		out = append(out, clone(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ListPublic is List with every Block removed, for the UI.
func (v *Vault) ListPublic() []Account {
	out := v.List()
	for i := range out {
		out[i].Block = nil
	}
	return out
}

// Delete removes an account and persists. Deleting an unknown id is a no-op.
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, ok := v.accounts[id]
	if !ok {
		return nil
	}
	delete(v.accounts, id)
	if err := v.save(); err != nil {
		v.accounts[id] = prev
		return err
	}
	return nil
}

// save encrypts with a fresh nonce and replaces the file atomically (0600).
// Caller holds v.mu.
func (v *Vault) save() error {
	list := make([]Account, 0, len(v.accounts))
	for _, a := range v.accounts {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	plain, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("vault: nonce: %w", err)
	}
	header := append([]byte(magic), v.salt...)
	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(nonce)
	buf.Write(v.aead.Seal(nil, nonce, plain, header))

	dir := filepath.Dir(v.path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("vault: temp: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("vault: write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil && !isWindowsChmodQuirk(err) {
		return fail(err)
	}
	// Windows: Chmod only toggles read-only, so set an owner-only ACL (no-op elsewhere).
	if err := credfile.RestrictFile(name); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("vault: close: %w", err)
	}
	if err := renameFn(name, v.path); err != nil {
		os.Remove(name)
		return fmt.Errorf("vault: rename: %w", err)
	}
	credfile.SyncDir(dir)
	return nil
}

// isWindowsChmodQuirk tolerates Chmod being unsupported on a platform.
func isWindowsChmodQuirk(err error) bool { return errors.Is(err, errors.ErrUnsupported) }
