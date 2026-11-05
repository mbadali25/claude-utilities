package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/proto"
)

// hostRec is the persisted part of a host. Only the SHA-256 of its token is stored.
type hostRec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	OS      string `json:"os"`
	Hash    string `json:"hash"`
	Revoked bool   `json:"revoked,omitempty"`
}

type hostFile struct {
	Hosts []hostRec `json:"hosts"`
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("hub: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("hub: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *Hub) load() error {
	data, err := os.ReadFile(h.tokensPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hub: read hosts: %w", err)
	}
	var f hostFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("hub: parse hosts: %w", err)
	}
	for _, r := range f.Hosts {
		h.hosts[r.ID] = &host{hostRec: r}
		h.byHash[r.Hash] = r.ID
	}
	return nil
}

// saveLocked persists every host record atomically. Callers hold h.mu.
func (h *Hub) saveLocked() error {
	var f hostFile
	for _, ho := range h.hosts {
		f.Hosts = append(f.Hosts, ho.hostRec)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("hub: marshal hosts: %w", err)
	}
	return writePrivate(h.tokensPath, data)
}

// mintLocked registers a new host for hello and returns its id and token. Callers hold h.mu.
func (h *Hub) mintLocked(hello proto.Hello, c *conn) (id, token string, err error) {
	if id, err = randHex(8); err != nil {
		return "", "", err
	}
	if token, err = newToken(); err != nil {
		return "", "", err
	}
	ho := &host{hostRec: hostRec{ID: id, Name: hello.HostName, OS: hello.OS, Hash: hashToken(token)}, c: c, lastSeen: h.now()}
	h.hosts[id] = ho
	h.byHash[ho.Hash] = id
	if err = h.saveLocked(); err != nil {
		delete(h.hosts, id)
		delete(h.byHash, ho.Hash)
		return "", "", err
	}
	c.state, c.hostID = stateEnrolled, id
	return id, token, nil
}

// forgetLocked removes a host that never received its token. Callers hold h.mu.
func (h *Hub) forgetLocked(id string) {
	if ho := h.hosts[id]; ho != nil {
		delete(h.byHash, ho.Hash)
		delete(h.hosts, id)
		_ = h.saveLocked()
	}
}

// NewEnrolCode returns a single-use pre-approved enrolment code valid for EnrolCodeTTL.
func (h *Hub) NewEnrolCode() (code string, expires time.Time) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic("hub: crypto/rand failed: " + err.Error())
	}
	code = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	h.mu.Lock()
	defer h.mu.Unlock()
	expires = h.now().Add(EnrolCodeTTL)
	h.codes[code] = expires
	return code, expires
}

// Revoke disables hostID's token and drops its connection.
func (h *Hub) Revoke(hostID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	ho := h.hosts[hostID]
	if ho == nil {
		return ErrUnknownHost
	}
	ho.Revoked = true
	if err := h.saveLocked(); err != nil {
		ho.Revoked = false
		return err
	}
	if ho.c != nil {
		ho.c.close(websocket.StatusPolicyViolation, "revoked")
	}
	h.log.Info("host revoked", "action", "revoke", "host_id", hostID, "result", "ok")
	return nil
}

// admitToken accepts a reconnect by a valid, unrevoked token.
func (h *Hub) admitToken(c *conn) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(h.now())
	if len(h.badHits[c.ip]) >= BadHelloPerIP {
		return ErrRateLimited
	}
	ho := h.hosts[h.byHash[hashToken(c.hello.Token)]]
	if ho == nil {
		return ErrBadToken
	}
	if ho.Revoked {
		return ErrRevoked
	}
	if ho.c != nil {
		ho.c.close(websocket.StatusPolicyViolation, "replaced")
		ho.c.state = stateClosed
	}
	ho.c, ho.lastSeen = c, h.now()
	ho.report = proto.Report{}
	c.state, c.hostID = stateEnrolled, ho.ID
	h.log.Info("agent connected", "action", "connect", "host_id", ho.ID, "result", "ok")
	return nil
}

// admitCode enrols a host without the pending queue, using a single-use code.
func (h *Hub) admitCode(c *conn) error {
	h.mu.Lock()
	h.sweepLocked(h.now())
	if len(h.badHits[c.ip]) >= BadHelloPerIP {
		h.mu.Unlock()
		return ErrRateLimited
	}
	exp, ok := h.codes[c.hello.Code]
	delete(h.codes, c.hello.Code) // single use, valid or not
	if !ok || !h.now().Before(exp) {
		h.mu.Unlock()
		return ErrBadCode
	}
	id, token, err := h.mintLocked(c.hello, c)
	h.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.send(proto.TypeApproved, "", proto.Approved{Token: token}); err != nil {
		h.mu.Lock()
		h.forgetLocked(id)
		h.mu.Unlock()
		return err
	}
	h.log.Info("agent enrolled", "action", "enrol", "host_id", id, "host_name", c.hello.HostName, "os", c.hello.OS,
		"source_ip", c.ip, "result", "code")
	return nil
}
