package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"claude-utilities/internal/vault"
)

// Manager is the whole tunnels feature: the configuration, the keys and the supervisor. The web
// layer talks only to this, so every rule about what may be shown and what may be logged lives
// in one place.
//
// The configuration is persisted inside the encrypted keyring file, not in a plaintext file
// beside it: an address and a username are not secrets, but together they map the estate, and
// they are already in the one file whose passphrase the operator has supplied.
type Manager struct {
	sup *Supervisor
	kr  *vault.Keyring

	mu sync.Mutex
	// rate holds the per-host, per-action timestamps the rate limits are computed from.
	rate map[string][]time.Time
	now  func() time.Time
}

// View is one tunnel as the admin UI sees it. Address and User are in it - the UI has fields for
// them - so a View must never be handed to a logger.
type View struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Address     string    `json:"address"`
	User        string    `json:"user"`
	Port        int       `json:"port"`
	Enabled     bool      `json:"enabled"`
	State       State     `json:"state"`
	Since       time.Time `json:"since"`
	Attempt     int       `json:"attempt"`
	Restarts1h  int       `json:"restarts1h"`
	LastRestart time.Time `json:"lastRestart,omitzero"`
	Reason      Reason    `json:"reason,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	// Fingerprint is the SHA256:... form of this host's tunnel key; Short is its first 8
	// characters, for the Hosts tab row.
	Fingerprint string `json:"fingerprint,omitempty"`
	Short       string `json:"shortFingerprint,omitempty"`
	HasKey      bool   `json:"hasKey"`
	Rotating    bool   `json:"rotating"`
	HasHostKey  bool   `json:"hasHostKey"`
	// HostKeyFingerprint is the host's OWN key, as seeded into known_hosts.
	HostKeyFingerprint string `json:"hostKeyFingerprint,omitempty"`
	// Install, Remove and InstallTight are the generated one-liners. They contain the public key
	// only; there is no endpoint anywhere that returns a private key.
	Install      string `json:"install,omitempty"`
	Remove       string `json:"remove,omitempty"`
	InstallTight string `json:"installTight,omitempty"`
	// RotateInstall is the install command for the NEW key during a rotation. Both lines are
	// valid until the rotation is committed.
	RotateInstall string `json:"rotateInstall,omitempty"`
	// RevokePending says a key was revoked here but its line is probably still on the host. A
	// false green here would be worse than the honest warning, so it survives a replacement key
	// and is cleared only when the operator says they ran RevokedRemove on the host.
	RevokePending bool `json:"revokePending"`
	// RevokedRemove takes the revoked key's line off the host. It stays available for as long as
	// RevokePending does, because nothing else can remove that line.
	RevokedRemove string `json:"revokedRemove,omitempty"`
}

// ErrNoKey means the host has no tunnel key yet, so there is nothing to show or rotate.
var ErrNoKeyYet = errors.New("tunnel: this host has no tunnel key yet; generate one first")

// NewManager builds the supervisor and loads the stored configuration. It starts nothing.
func NewManager(o Options, kr *vault.Keyring) (*Manager, error) {
	if kr == nil {
		return nil, errors.New("tunnel: a keyring is required")
	}
	if o.Keys == nil {
		o.Keys = kr
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	sup, err := New(o)
	if err != nil {
		return nil, err
	}
	m := &Manager{sup: sup, kr: kr, rate: map[string][]time.Time{}, now: o.Now}
	if m.now == nil {
		m.now = time.Now
	}
	specs, err := m.load()
	if err != nil {
		return nil, err
	}
	if len(specs) > 0 {
		if err := sup.Set(specs); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Start and Stop pass through to the supervisor.
func (m *Manager) Start(ctx context.Context) { m.sup.Start(ctx) }
func (m *Manager) Stop()                     { m.sup.Stop() }

func (m *Manager) load() ([]Spec, error) {
	raw := m.kr.Config()
	if len(raw) == 0 {
		return nil, nil
	}
	var specs []Spec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("tunnel: stored configuration is malformed: %w", err)
	}
	out := specs[:0]
	for _, s := range specs {
		if Validate(s) == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// apply persists the configuration and hands it to the supervisor. The order matters: a write
// that fails must not leave the supervisor running a configuration that is not stored.
func (m *Manager) apply(specs []Spec) error {
	for _, s := range specs {
		if err := Validate(s); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(specs)
	if err != nil {
		return fmt.Errorf("tunnel: encode configuration: %w", err)
	}
	if err := m.kr.PutConfig(raw); err != nil {
		return err
	}
	return m.sup.Set(specs)
}

// List returns every tunnel, with the generated commands filled in.
func (m *Manager) List() []View {
	specs := m.sup.Specs()
	out := make([]View, 0, len(specs))
	for _, s := range specs {
		out = append(out, m.view(s))
	}
	return out
}

// Get returns one tunnel.
func (m *Manager) Get(id string) (View, bool) {
	s, ok := m.sup.Spec(id)
	if !ok {
		return View{}, false
	}
	return m.view(s), true
}

// StateByID is what the Hosts tab joins on: the tunnel state keyed by host id, for the hosts
// that have a tunnel. A host with no tunnel is simply absent, and a tunnel with no enrolled host
// is in List but matches no host row - both directions tolerate a missing partner, because
// tunnel-first is the real onboarding order.
func (m *Manager) StateByID() map[string]View {
	out := map[string]View{}
	for _, v := range m.List() {
		out[v.ID] = v
	}
	return out
}

func (m *Manager) view(s Spec) View {
	v := View{ID: s.ID, Label: s.Label, Address: s.Address, User: s.User, Port: s.Port,
		Enabled: s.Enabled, HasHostKey: s.HostKey != "", RevokePending: s.RevokedKey != "",
		HostKeyFingerprint: HostKeyFingerprint(s.HostKey)}
	if t, ok := m.sup.Get(s.ID); ok {
		v.State, v.Since, v.Attempt = t.State, t.Since, t.Attempt
		v.Restarts1h, v.LastRestart = t.Restarts1h, t.LastRestart
		v.Reason, v.Detail = t.Reason, t.Detail
	}
	cur, prev, ok := m.kr.PublicKey(s.ID)
	if ok {
		v.HasKey = true
		v.Rotating = prev != nil
		if k, err := SSHPublicKey(cur); err == nil {
			v.Fingerprint = FingerprintKey(k)
			v.Short = Short(v.Fingerprint)
			if v.Rotating {
				// During the overlap the OLD key is the one in service, so the plain install
				// command stays the old line and the new one is offered separately.
				v.RotateInstall = InstallCommand(k, s.Label, s.Port, false)
			} else {
				v.Install = InstallCommand(k, s.Label, s.Port, false)
				v.InstallTight = InstallCommand(k, s.Label, s.Port, true)
				v.Remove = RemoveCommand(k)
			}
		}
		if prev != nil {
			if k, err := SSHPublicKey(prev); err == nil {
				v.Install = InstallCommand(k, s.Label, s.Port, false)
				v.InstallTight = InstallCommand(k, s.Label, s.Port, true)
				v.Remove = RemoveCommand(k)
			}
		}
	}
	if s.RevokedKey != "" {
		// The remove command is rebuilt from the public key kept for exactly this purpose: the
		// operator still has to run it on the host. The state only becomes revoke_pending while
		// there is no replacement key - once a fresh one is in service the real state is the
		// honest one, and the stale line is reported beside it rather than instead of it.
		v.RevokedRemove = removeCommandForBody(s.RevokedKey)
		if !v.HasKey {
			v.State = StateRevokePending
			v.Remove = v.RevokedRemove
		}
	}
	return v
}

// Add stores a new tunnel, generates its key and returns the view with the install command on it.
// It does not enable the tunnel: the operator has to paste the command and the host fingerprint
// first, and a tunnel enabled before that just fails with hostkey_not_seeded.
func (m *Manager) Add(s Spec) (View, error) {
	s.Label = strings.TrimSpace(s.Label)
	s.Address = strings.TrimSpace(s.Address)
	s.User = strings.TrimSpace(s.User)
	if s.Port == 0 {
		s.Port = DefaultPort
	}
	s.Enabled = false
	s.RevokedKey = ""
	if err := Validate(s); err != nil {
		return View{}, err
	}
	specs := m.sup.Specs()
	for _, e := range specs {
		if strings.EqualFold(e.Label, s.Label) {
			return View{}, fmt.Errorf("tunnel: a tunnel labelled %q already exists", s.Label)
		}
		if e.ID == s.ID {
			return View{}, fmt.Errorf("tunnel: a tunnel for that host already exists")
		}
	}
	if s.ID == "" {
		id, err := newID()
		if err != nil {
			return View{}, err
		}
		s.ID = id
	}
	if _, err := m.kr.Generate(s.ID); err != nil {
		return View{}, err
	}
	if err := m.apply(append(specs, s)); err != nil {
		_ = m.kr.Delete(s.ID) // do not leave a key for a tunnel that was not stored
		return View{}, err
	}
	v, _ := m.Get(s.ID)
	return v, nil
}

// Update changes a tunnel's address, user or port. The label and the id are fixed: the label is
// in the authorized_keys comment on the host, so renaming it here would silently disagree.
func (m *Manager) Update(id, address, user string, port int) (View, error) {
	specs := m.sup.Specs()
	found := false
	for i := range specs {
		if specs[i].ID != id {
			continue
		}
		found = true
		specs[i].Address = strings.TrimSpace(address)
		specs[i].User = strings.TrimSpace(user)
		if port != 0 {
			specs[i].Port = port
		}
		if err := Validate(specs[i]); err != nil {
			return View{}, err
		}
	}
	if !found {
		return View{}, ErrUnknown
	}
	if err := m.apply(specs); err != nil {
		return View{}, err
	}
	v, _ := m.Get(id)
	return v, nil
}

// SetEnabled switches a tunnel on or off. Enabling one with no seeded host key is refused rather
// than left to fail on the first dial.
func (m *Manager) SetEnabled(id string, on bool) (View, error) {
	specs := m.sup.Specs()
	found := false
	for i := range specs {
		if specs[i].ID != id {
			continue
		}
		found = true
		if on {
			if specs[i].HostKey == "" {
				return View{}, fmt.Errorf("%w", errHostKeyFirst)
			}
			if _, ok := m.kr.Get(id); !ok {
				return View{}, ErrNoKeyYet
			}
			// RevokedKey is left alone: a tunnel can legitimately run on a fresh key while an
			// older, revoked line is still sitting on the host.
		}
		specs[i].Enabled = on
	}
	if !found {
		return View{}, ErrUnknown
	}
	if err := m.apply(specs); err != nil {
		return View{}, err
	}
	v, _ := m.Get(id)
	return v, nil
}

var errHostKeyFirst = errors.New("tunnel: paste the host's own key fingerprint before enabling the tunnel")

// SeedHostKey records the host's own public key, which is what makes StrictHostKeyChecking=yes
// able to succeed. The operator reads it off the host; this server never learns it from the host.
func (m *Manager) SeedHostKey(id, text string) (View, error) {
	line, err := ParseHostKey(text)
	if err != nil {
		return View{}, err
	}
	specs := m.sup.Specs()
	found := false
	for i := range specs {
		if specs[i].ID == id {
			specs[i].HostKey = line
			found = true
		}
	}
	if !found {
		return View{}, ErrUnknown
	}
	if err := m.apply(specs); err != nil {
		return View{}, err
	}
	v, _ := m.Get(id)
	return v, nil
}

// Restart asks a tunnel to start now, skipping the remaining backoff. Rate limited.
func (m *Manager) Restart(id string) error {
	if _, ok := m.sup.Spec(id); !ok {
		return ErrUnknown
	}
	if err := m.limit("restart", id, 10*time.Second, 1); err != nil {
		return err
	}
	if err := m.limit("restart-hour", id, time.Hour, 6); err != nil {
		return err
	}
	return m.sup.Restart(id)
}

// GenerateKey creates this host's first key, or replaces one outright. Rotate is the safe way to
// replace a key that is in service; this one is for a host that has none.
func (m *Manager) GenerateKey(id string) (View, error) {
	if _, ok := m.sup.Spec(id); !ok {
		return View{}, ErrUnknown
	}
	if err := m.limit("key", id, time.Minute, 1); err != nil {
		return View{}, err
	}
	if _, err := m.kr.Generate(id); err != nil {
		return View{}, err
	}
	// The revoke reminder is NOT cleared here. A revoked key's authorized_keys line is still on
	// the host, and generating a replacement does nothing about it: clearing the reminder would
	// hide a line nobody has removed. Only ConfirmRevoked, the operator saying they ran the
	// command, clears it.
	v, _ := m.Get(id)
	return v, nil
}

// RotateKey generates a new key and keeps the old one valid. Both authorized_keys lines work
// until CommitRotation, so a rotation abandoned halfway costs one extra line and no service.
func (m *Manager) RotateKey(id string) (View, error) {
	if _, ok := m.sup.Spec(id); !ok {
		return View{}, ErrUnknown
	}
	if _, ok := m.kr.Get(id); !ok {
		return View{}, ErrNoKeyYet
	}
	if err := m.limit("key", id, time.Minute, 1); err != nil {
		return View{}, err
	}
	if _, err := m.kr.Rotate(id); err != nil {
		return View{}, err
	}
	// The tunnel must come up on the new key, so restart it now rather than waiting for a drop.
	_ = m.sup.Restart(id)
	v, _ := m.Get(id)
	return v, nil
}

// CommitRotation deletes the old key. The caller is expected to have seen the tunnel settle on
// the new one first; the UI only offers this once the state is up.
func (m *Manager) CommitRotation(id string) (View, error) {
	if _, ok := m.sup.Spec(id); !ok {
		return View{}, ErrUnknown
	}
	if err := m.kr.CommitRotation(id); err != nil {
		return View{}, err
	}
	v, _ := m.Get(id)
	return v, nil
}

// CancelRotation goes back to the key that was in service.
func (m *Manager) CancelRotation(id string) (View, error) {
	if _, ok := m.sup.Spec(id); !ok {
		return View{}, ErrUnknown
	}
	if err := m.kr.CancelRotation(id); err != nil {
		return View{}, err
	}
	_ = m.sup.Restart(id)
	v, _ := m.Get(id)
	return v, nil
}

// RevokeKey deletes the private key and disables the tunnel. The authorized_keys line on the
// host can only be removed by the operator, so the public key is kept - and only the public key -
// so the UI can keep offering the remove command and keep saying that the line is probably still
// there. Reporting a clean revoke would be a false green.
func (m *Manager) RevokeKey(id string) (View, error) {
	spec, ok := m.sup.Spec(id)
	if !ok {
		return View{}, ErrUnknown
	}
	cur, _, hasKey := m.kr.PublicKey(id)
	body := ""
	if hasKey {
		if k, err := SSHPublicKey(cur); err == nil {
			body = keyBody(k)
		}
	}
	if err := m.kr.Delete(id); err != nil {
		return View{}, err
	}
	specs := m.sup.Specs()
	for i := range specs {
		if specs[i].ID == spec.ID {
			specs[i].Enabled = false
			specs[i].RevokedKey = body
		}
	}
	if err := m.apply(specs); err != nil {
		return View{}, err
	}
	v, _ := m.Get(id)
	return v, nil
}

// ConfirmRevoked is the operator saying they have run the remove command on the host. It only
// clears this server's reminder; it cannot and does not verify the host.
func (m *Manager) ConfirmRevoked(id string) (View, error) {
	if _, ok := m.sup.Spec(id); !ok {
		return View{}, ErrUnknown
	}
	if err := m.clearRevoked(id); err != nil {
		return View{}, err
	}
	v, _ := m.Get(id)
	return v, nil
}

func (m *Manager) clearRevoked(id string) error {
	specs := m.sup.Specs()
	for i := range specs {
		if specs[i].ID == id {
			specs[i].RevokedKey = ""
		}
	}
	return m.apply(specs)
}

// Remove forgets a tunnel entirely, key included. The host's authorized_keys line is not touched,
// so the caller is told to revoke first - Remove on a host that still has a key returns the
// remove command in the view it answers with.
func (m *Manager) Remove(id string) (View, error) {
	before, ok := m.Get(id)
	if !ok {
		return View{}, ErrUnknown
	}
	if err := m.kr.Delete(id); err != nil {
		return View{}, err
	}
	specs := m.sup.Specs()
	keptSpecs := make([]Spec, 0, len(specs))
	for _, s := range specs {
		if s.ID != id {
			keptSpecs = append(keptSpecs, s)
		}
	}
	if err := m.apply(keptSpecs); err != nil {
		return View{}, err
	}
	return before, nil
}

// ImportFile reads the interim supervisor's host list and adds every host in it that is not
// already configured. The file is LEFT IN PLACE: it is the rollback path for the scheduled task,
// so this must not consume it. Importing twice adds nothing the second time.
func (m *Manager) ImportFile(path string) (added int, skipped int, err error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return 0, 0, fmt.Errorf("tunnel: cannot read the host list: %w", redactPath(err, path))
	}
	var entries []struct {
		Name string `json:"name"`
		Host string `json:"host"`
		User string `json:"user"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return 0, 0, errors.New("tunnel: the host list is not a JSON array of {name, host, user}")
	}
	for _, e := range entries {
		s := Spec{Label: e.Name, Address: e.Host, User: e.User, Port: DefaultPort}
		if _, aerr := m.Add(s); aerr != nil {
			skipped++
			continue
		}
		added++
	}
	if added == 0 && skipped == 0 {
		return 0, 0, errors.New("tunnel: the host list has no entries")
	}
	return added, skipped, nil
}

// redactPath keeps a file-system error from carrying the operator's profile path into a response.
func redactPath(err error, path string) error {
	msg := strings.ReplaceAll(err.Error(), path, "<path>")
	if home, herr := os.UserHomeDir(); herr == nil && home != "" {
		msg = strings.ReplaceAll(msg, home, "<home>")
	}
	return errors.New(msg)
}

// limit is a per-host, per-action rate limit: at most n events per window.
func (m *Manager) limit(action, id string, window time.Duration, n int) error {
	key := action + "\x00" + id
	m.mu.Lock()
	defer m.mu.Unlock()
	cut := m.now().Add(-window)
	keep := m.rate[key][:0]
	for _, t := range m.rate[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= n {
		m.rate[key] = keep
		return ErrRateLimited
	}
	m.rate[key] = append(keep, m.now())
	// Bound the table: one entry per host per action is already bounded by the host count, but
	// trim empty keys so a removed host does not linger.
	if len(m.rate[key]) == 0 {
		delete(m.rate, key)
	}
	return nil
}

// newID generates an id for a tunnel added before its agent is enrolled.
func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tunnel: id: %w", err)
	}
	return "tun-" + hex.EncodeToString(b), nil
}

// Labels is used by tests and by the audit line builder: labels only, never addresses.
func (m *Manager) Labels() []string {
	specs := m.sup.Specs()
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, s.Label)
	}
	sort.Strings(out)
	return out
}
