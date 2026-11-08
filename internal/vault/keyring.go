package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Keyring stores the tunnel signing keys: one ed25519 key per host, encrypted at rest with the
// same argon2id + AES-256-GCM machinery and the same CLAUDESWAP_KEY passphrase as the account
// vault, in its own file. Separate file, not a new field in vault.bin: an older server binary
// must still be able to read a vault a newer one wrote, which is what makes the tunnels
// migration reversible at every step.
//
// A seed never leaves this process except as the ephemeral file ssh needs, and no HTTP response
// carries one: the web layer reads Public and Fingerprint, never Seed.
type Keyring struct {
	mu   sync.Mutex
	file *sealed
	keys map[string]TunnelKey
	// config is the tunnel configuration, stored opaquely. The vault must not know what a tunnel
	// Spec is - internal/tunnel imports this package, so the reverse would be a cycle - and the
	// configuration belongs in here rather than a plaintext file: a host address and a username
	// are not secrets on their own, but together they map the estate.
	config json.RawMessage
}

// keyringPayload is what the encrypted file holds.
type keyringPayload struct {
	Keys   []TunnelKey     `json:"keys"`
	Config json.RawMessage `json:"config,omitempty"`
}

// keyringMagic is the file's own magic, so a keyring and a vault can never be opened as each other.
const keyringMagic = "CSK1"

// KeyringFileName is the keyring's name inside the data dir.
const KeyringFileName = "tunnelkeys.bin"

// ErrRotating means the host is mid-rotation and the caller must finish or cancel it first.
var ErrRotating = errors.New("vault: a key rotation is already in progress for this host")

// TunnelKey is one host's tunnel key. Seed and PrevSeed are ed25519 seeds (ed25519.SeedSize
// bytes); everything else is safe to show.
type TunnelKey struct {
	HostID  string    `json:"hostId"`
	Seed    []byte    `json:"seed"`
	Created time.Time `json:"created"`
	// PrevSeed is the key being rotated away from. While it is set both authorized_keys lines are
	// valid, so a rotation abandoned halfway costs one extra authorised line and no service.
	PrevSeed    []byte    `json:"prevSeed,omitempty"`
	PrevCreated time.Time `json:"prevCreated,omitempty"`
}

// Rotating reports whether this key is mid-rotation.
func (k TunnelKey) Rotating() bool { return len(k.PrevSeed) == ed25519.SeedSize }

// KeyInfo is a key's metadata with no seed in it at all - a separate type rather than a TunnelKey
// with the seeds blanked, so there is no shape in which a seed field is expected to be empty and
// might one day be filled.
type KeyInfo struct {
	HostID      string    `json:"hostId"`
	Created     time.Time `json:"created"`
	Rotating    bool      `json:"rotating"`
	PrevCreated time.Time `json:"prevCreated,omitzero"`
}

func info(t TunnelKey) KeyInfo {
	return KeyInfo{HostID: t.HostID, Created: t.Created, Rotating: t.Rotating(),
		PrevCreated: t.PrevCreated}
}

// OpenKeyring loads the keyring at path, or an empty in-memory one when the file does not exist.
// ks says which keys this process may use, exactly as it does for Open - the keyring is sealed
// with the same passphrase as the vault, so both entry points hand the same KeySource to both.
// It never writes to disk.
func OpenKeyring(path string, ks KeySource) (*Keyring, error) {
	f, plain, err := openSealed(path, keyringMagic, ks)
	if err != nil {
		return nil, err
	}
	k := &Keyring{file: f, keys: map[string]TunnelKey{}}
	if plain == nil {
		return k, nil
	}
	var p keyringPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, errCorrupt
	}
	for _, t := range p.Keys {
		if len(t.Seed) != ed25519.SeedSize {
			return nil, errCorrupt
		}
		k.keys[t.HostID] = t
	}
	k.config = p.Config
	return k, nil
}

// Config returns the stored tunnel configuration, or nil when there is none.
func (k *Keyring) Config() json.RawMessage {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append(json.RawMessage(nil), k.config...)
}

// PutConfig replaces the stored tunnel configuration and persists. A failed write leaves the
// previous configuration in place, in memory and on disk.
func (k *Keyring) PutConfig(raw json.RawMessage) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	prev := k.config
	k.config = append(json.RawMessage(nil), raw...)
	if err := k.saveLocked(); err != nil {
		k.config = prev
		return err
	}
	return nil
}

func newSeed() ([]byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("vault: seed: %w", err)
	}
	return seed, nil
}

// Generate creates or replaces this host's key outright, discarding any rotation state. Use it
// for a first key; use Rotate to replace one that is in service.
func (k *Keyring) Generate(hostID string) (KeyInfo, error) {
	if hostID == "" {
		return KeyInfo{}, errors.New("vault: host id required")
	}
	seed, err := newSeed()
	if err != nil {
		return KeyInfo{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	prev, had := k.keys[hostID]
	next := TunnelKey{HostID: hostID, Seed: seed, Created: time.Now().UTC()}
	k.keys[hostID] = next
	if err := k.saveLocked(); err != nil {
		k.restoreLocked(hostID, prev, had)
		return KeyInfo{}, err
	}
	return info(next), nil
}

// Rotate generates a new key and keeps the current one as the previous: both lines are valid
// until CommitRotation. A host already mid-rotation is refused, so a half-done rotation cannot be
// stacked on another.
func (k *Keyring) Rotate(hostID string) (KeyInfo, error) {
	seed, err := newSeed()
	if err != nil {
		return KeyInfo{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, ok := k.keys[hostID]
	if !ok {
		return KeyInfo{}, ErrNotFound
	}
	if cur.Rotating() {
		return KeyInfo{}, ErrRotating
	}
	next := TunnelKey{HostID: hostID, Seed: seed, Created: time.Now().UTC(),
		PrevSeed: cur.Seed, PrevCreated: cur.Created}
	k.keys[hostID] = next
	if err := k.saveLocked(); err != nil {
		k.keys[hostID] = cur
		return KeyInfo{}, err
	}
	return info(next), nil
}

// CommitRotation deletes the old key, which is only safe once the new tunnel has settled. It is a
// no-op on a host that is not rotating.
func (k *Keyring) CommitRotation(hostID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, ok := k.keys[hostID]
	if !ok {
		return ErrNotFound
	}
	if !cur.Rotating() {
		return nil
	}
	next := cur
	next.PrevSeed, next.PrevCreated = nil, time.Time{}
	k.keys[hostID] = next
	if err := k.saveLocked(); err != nil {
		k.keys[hostID] = cur
		return err
	}
	return nil
}

// CancelRotation goes back to the previous key and discards the new one.
func (k *Keyring) CancelRotation(hostID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, ok := k.keys[hostID]
	if !ok {
		return ErrNotFound
	}
	if !cur.Rotating() {
		return nil
	}
	next := TunnelKey{HostID: hostID, Seed: cur.PrevSeed, Created: cur.PrevCreated}
	k.keys[hostID] = next
	if err := k.saveLocked(); err != nil {
		k.keys[hostID] = cur
		return err
	}
	return nil
}

// Delete removes a host's key material. It is the revoke: the line on the host can only be
// removed by the operator running the generated command, so the caller must say so plainly
// rather than reporting a clean revoke.
func (k *Keyring) Delete(hostID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	prev, ok := k.keys[hostID]
	if !ok {
		return nil
	}
	delete(k.keys, hostID)
	if err := k.saveLocked(); err != nil {
		k.keys[hostID] = prev
		return err
	}
	return nil
}

// Seed returns the private seed for this host. It is the one accessor that hands out key
// material: only the tunnel supervisor calls it, to write the ephemeral file ssh needs. It must
// never reach an HTTP response, a log line or an error string.
func (k *Keyring) Seed(hostID string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t, ok := k.keys[hostID]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), t.Seed...), true
}

// Get returns the host's key metadata. There is no accessor that returns a seed-shaped value
// with the seed removed: KeyInfo has no seed field at all.
func (k *Keyring) Get(hostID string) (KeyInfo, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t, ok := k.keys[hostID]
	if !ok {
		return KeyInfo{}, false
	}
	return info(t), true
}

// List returns every key's metadata, ordered by host id.
func (k *Keyring) List() []KeyInfo {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]KeyInfo, 0, len(k.keys))
	for _, t := range k.keys {
		out = append(out, info(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
}

// PublicKey returns the ed25519 public key for this host, and the previous one while it is
// rotating. Both are public values.
func (k *Keyring) PublicKey(hostID string) (cur, prev ed25519.PublicKey, ok bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t, ok := k.keys[hostID]
	if !ok {
		return nil, nil, false
	}
	cur = ed25519.NewKeyFromSeed(t.Seed).Public().(ed25519.PublicKey)
	if t.Rotating() {
		prev = ed25519.NewKeyFromSeed(t.PrevSeed).Public().(ed25519.PublicKey)
	}
	return cur, prev, true
}

// restoreLocked puts a replaced entry back after a failed write. Caller holds k.mu.
func (k *Keyring) restoreLocked(hostID string, prev TunnelKey, had bool) {
	if had {
		k.keys[hostID] = prev
		return
	}
	delete(k.keys, hostID)
}

// saveLocked persists the keyring. Caller holds k.mu.
func (k *Keyring) saveLocked() error {
	list := make([]TunnelKey, 0, len(k.keys))
	for _, t := range k.keys {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].HostID < list[j].HostID })
	plain, err := json.Marshal(keyringPayload{Keys: list, Config: k.config})
	if err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	return k.file.write(keyringMagic, plain)
}
