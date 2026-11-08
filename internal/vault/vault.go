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

	// ErrNoRecoverySlot means a v2 write would leave a file with no passphrase slot. Such a file can
	// still be opened - a hand-damaged header has to be readable to be repairable - but it cannot be
	// saved, because a machine slot is tied to one host: lose the host and the vault is gone with it.
	// It is also why a service, which has no passphrase, cannot create a vault from nothing.
	ErrNoRecoverySlot = errors.New("vault: refusing to write a vault with no passphrase slot")
	// ErrUnknownSlotPresent means the header carries a slot of a type this binary does not know. It
	// is not an error on open - such a slot is skipped and its bytes are retained - but it is the
	// refusal for an operation that would have to re-wrap every slot: `rotate`, and `remove-slot` of
	// any other slot. Task 3b.2 is its only caller; nothing returns it yet.
	ErrUnknownSlotPresent = errors.New("vault: a slot of an unknown type is present")

	errCorrupt = errors.New("vault: malformed vault file")

	// errSlotIDMismatch means a `changed` entry's map key and that Slot's own `id` disagree.
	// marshalHeader decides retention and placement by the map key but encodes the Slot's `id`, so an
	// unchecked mismatch silently rewrites a slot's id - and the id is length-prefixed into every
	// wrap's AAD (slotAAD), so every wrap bound to the old id stops opening while the file still
	// parses as valid. A caller's mistake rather than a damaged file, so it is its own sentinel and
	// not errCorrupt, which an operator reads as "corrupt disk or wrong passphrase". Unexported:
	// marshalHeader is internal and no caller outside this package can produce the condition.
	//
	// It names neither id. An id is attacker-chosen text out of a header nothing has authenticated
	// yet, and this string goes to stderr and into whatever an operator pastes into a ticket, where
	// it has no escaping around it - the same reasoning triedSummary is built on.
	errSlotIDMismatch = errors.New("vault: a changed slot's id does not match the id it is keyed by")

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
	// ks is the key source this vault was opened with, kept because a slot operation needs the same
	// keys the open used: `add-slot --type kek-file` wraps under the KEK this host resolves, and a
	// rotation re-wraps every machine slot. Keeping it means the KEK never crosses this package's
	// boundary to be handed back in, and that a slot can never be wrapped under a key the open flow
	// would not have accepted. It holds no more than it did during Open - EnvKey reads a variable,
	// PromptKey caches one line, HostKeys caches its openers - and none of it is ever logged.
	ks KeySource
}

// Open loads the vault at path, creating an empty in-memory one if the file
// does not exist or is empty. ks says which keys this process may use:
// EnvKey(name) for the behaviour this used to have from an environment
// variable name, PromptKey for an operator at a console. Open never writes to
// disk.
//
// ks must not be nil. A nil KeySource is a programmer error, not an input error: there is no
// sensible answer to "open this with no key source at all", and inventing one - falling back to an
// environment variable, say - is the second way in that decision O1 removed on purpose. It panics.
//
// The payload is a JSON array of accounts and stays that way: a server that is rolled back must
// still be able to read a vault a newer one has written, so tunnel keys live in their own file
// (keyring.go) rather than in a new envelope here.
//
// Create-on-open stays v1: `server vault init` is the only v2 creator (Task 3b.3), and no later
// task moves this writer. A v2 file needs a passphrase slot and a machine slot, a typed passphrase
// and a printed recovery rung, none of which a path inside Open has or could ask for - and a v2
// file with no passphrase slot is refused on write anyway (ErrNoRecoverySlot). So a console
// `server --listen ...` against an empty data dir still creates a CSV1 vault, exactly as today;
// the service's no-vault path is a refusal (exit 4, naming `vault init`), never a creation.
// TestCreateOnOpenStillWritesV1 is a permanent assertion of that, not a temporary one.
func Open(path string, ks KeySource) (*Vault, error) {
	f, plain, err := openSealed(path, magic, ks)
	if err != nil {
		return nil, err
	}
	v := &Vault{file: f, accounts: map[string]Account{}, ks: ks}
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
	plain, err := v.accountsJSON()
	if err != nil {
		return err
	}
	return v.file.write(magic, plain)
}

// accountsJSON is the payload: the account list as one JSON array, ordered by id so two writes of
// the same store produce the same bytes. It is shared with the slot mutators (slotops.go), which
// write the same payload under a changed header - one encoder, so a slot operation cannot write a
// payload shaped differently from an ordinary save. Caller holds v.mu.
func (v *Vault) accountsJSON() ([]byte, error) {
	list := make([]Account, 0, len(v.accounts))
	for _, a := range v.accounts {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	plain, err := json.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("vault: encode: %w", err)
	}
	return plain, nil
}

// removeQuiet deletes a temp file on a failure path that already returns its own
// error, so a failed delete is not actionable.
func removeQuiet(p string) { _ = os.Remove(p) }

// isWindowsChmodQuirk tolerates Chmod being unsupported on a platform.
func isWindowsChmodQuirk(err error) bool { return errors.Is(err, errors.ErrUnsupported) }
