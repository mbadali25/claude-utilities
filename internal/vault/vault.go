// Package vault stores account credential blocks in one encrypted file.
// Format: magic | argon2id salt (16) | GCM nonce (12) | AES-256-GCM sealed JSON.
// The header is bound to the ciphertext as additional data. It never logs or
// returns token values, and error text never includes file content.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	magic    = "CSV1"
	saltLen  = 16
	nonceLen = 12
	keyLen   = 32
	// headerLen is the magic plus the salt: the prefix bound to the ciphertext as additional data.
	headerLen = len(magic) + saltLen
	argonTime = 3
	argonMem  = 64 * 1024 // KiB
	argonPar  = 4

	// MaxLabel is the longest account label in bytes (same cap as import).
	MaxLabel = 64
)

var (
	// ErrNoKey means this process has no key it can offer: the named environment variable is unset
	// or empty, stdin held no passphrase, or the KeySource is a service's and has none by design.
	ErrNoKey = errors.New("vault: encryption key not set")
	// ErrBadKey means the key is wrong or the file was tampered with.
	ErrBadKey = errors.New("vault: cannot decrypt (wrong key or tampered file)")

	// ErrNotFound means no account has the given id.
	ErrNotFound = errors.New("vault: unknown account")
	// ErrLabelInvalid means the label is empty after trimming or longer than MaxLabel bytes.
	ErrLabelInvalid = errors.New("vault: label must be 1-64 characters")
	// ErrLabelTaken means another account already has that label (case-insensitive).
	ErrLabelTaken = errors.New("vault: an account with that label already exists")

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
	file     *sealed
	accounts map[string]Account
}

// Open loads the vault at path, creating an empty in-memory one if the file
// does not exist or is empty. ks says which keys this process may use:
// EnvKey(name) for the behaviour this used to have from an environment
// variable name, PromptKey for an operator at a console. Open never writes to
// disk.
//
// The payload is a JSON array of accounts and stays that way: a server that is rolled back must
// still be able to read a vault a newer one has written, so tunnel keys live in their own file
// (keyring.go) rather than in a new envelope here.
func Open(path string, ks KeySource) (*Vault, error) {
	f, plain, err := openSealed(path, magic, ks)
	if err != nil {
		return nil, err
	}
	v := &Vault{file: f, accounts: map[string]Account{}}
	if plain == nil {
		return v, nil
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

// Relabel renames one account and persists atomically. The label is trimmed; it must be 1-MaxLabel
// bytes and unique among the other accounts, ignoring case. Only Label changes:
// Block, Identity and Updated are never touched. A failed write leaves the old label in place.
func (v *Vault) Relabel(id, label string) error {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > MaxLabel {
		return ErrLabelInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, ok := v.accounts[id]
	if !ok {
		return ErrNotFound
	}
	for otherID, a := range v.accounts {
		if otherID != id && strings.EqualFold(a.Label, label) {
			return ErrLabelTaken
		}
	}
	next := prev
	next.Label = label
	v.accounts[id] = next
	if err := v.save(); err != nil {
		v.accounts[id] = prev
		return err
	}
	return nil
}

// Delete removes an account and persists. It is the one call that destroys a stored login, so the
// file's previous bytes are copied to vault.bin.bak first: the copy is the same sealed envelope, so
// the same passphrase opens it, and an operator who deletes the wrong account can put it back.
//
// An unknown id is ErrNotFound and writes nothing - not the vault, not the backup - so a caller can
// answer 404 without racing a pre-check against the store. A failed write leaves the account in
// place; only the backup copy is then newer, which costs nothing.
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, ok := v.accounts[id]
	if !ok {
		return ErrNotFound
	}
	if err := v.file.backup(); err != nil {
		return err
	}
	delete(v.accounts, id)
	if err := v.save(); err != nil {
		v.accounts[id] = prev
		return err
	}
	return nil
}

// ReplaceBlock swaps one account's login block and nothing else: ID, label and identity stay. It is
// the "sign in again" write, so like Delete it copies the previous vault bytes to vault.bin.bak
// first, and a failed write puts the old block back. An unknown id is ErrNotFound and writes nothing.
func (v *Vault) ReplaceBlock(id string, block json.RawMessage, at time.Time) error {
	if len(block) == 0 {
		return errors.New("vault: block required")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	prev, ok := v.accounts[id]
	if !ok {
		return ErrNotFound
	}
	if err := v.file.backup(); err != nil {
		return err
	}
	next := prev
	next.Block, next.Updated = append(json.RawMessage(nil), block...), at
	v.accounts[id] = next
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
	return v.file.write(magic, plain)
}

// removeQuiet deletes a temp file on a failure path that already returns its own
// error, so a failed delete is not actionable.
func removeQuiet(p string) { _ = os.Remove(p) }

// isWindowsChmodQuirk tolerates Chmod being unsupported on a platform.
func isWindowsChmodQuirk(err error) bool { return errors.Is(err, errors.ErrUnsupported) }
