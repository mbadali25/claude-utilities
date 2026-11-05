package agent

// Why this host has no signed-in Claude Code account, and keeping that answer current.
//
// A connected host that reports no identity used to say nothing at all, so a Linux host the agent
// cannot see a login on looked the same as one that was never signed in. The agent now reports a
// fixed code (proto.Reason*) alongside the empty identity, re-reads it every identityRefresh, and
// re-reads at once on a reload signal (SIGHUP, Linux only), so a sign-in after start is picked up
// without a restart.
//
// Nothing here logs or returns a path, a user name, an email or a token: a reason is a code.

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"claude-utilities/internal/proto"
)

// identityRefresh is how often the agent re-reads the signed-in identity.
const identityRefresh = 30 * time.Second

// claudeConfigDirEnv points Claude Code (and so the agent) at a config dir other than the home one.
const claudeConfigDirEnv = "CLAUDE_CONFIG_DIR"

// maxOtherHomes bounds the home_mismatch probe, so a host with thousands of home directories
// cannot turn one identity read into a directory walk.
const maxOtherHomes = 32

// identityProbe reads the signed-in identity and, when there is none, why. Every field is set
// from the environment in newIdentityProbe and replaced wholesale in tests, so no test needs the
// real home directory.
type identityProbe struct {
	// configDir is CLAUDE_CONFIG_DIR, empty when unset.
	configDir string
	// home is the home of the user the agent runs as, "" when it cannot be resolved.
	home string
	// otherHomeGlobs and otherHomeFiles are the cheap home_mismatch probe: a .claude.json that
	// belongs to another user on this host. Empty on Windows.
	otherHomeGlobs, otherHomeFiles []string
}

func newIdentityProbe() identityProbe {
	p := identityProbe{configDir: os.Getenv(claudeConfigDirEnv)}
	if home, err := os.UserHomeDir(); err == nil {
		p.home = home
	}
	if runtime.GOOS != "windows" {
		p.otherHomeGlobs = []string{"/home/*/.claude.json"}
		p.otherHomeFiles = []string{"/root/.claude.json"}
	}
	return p
}

// path returns the .claude.json to read and whether CLAUDE_CONFIG_DIR chose it.
func (p identityProbe) path() (string, bool) {
	if p.configDir != "" {
		return filepath.Join(p.configDir, ".claude.json"), true
	}
	if p.home == "" {
		return "", false
	}
	return filepath.Join(p.home, ".claude.json"), false
}

// run returns the signed-in identity, or "" with one proto.Reason* code. The identity may be an
// email address; the code never is.
func (p identityProbe) run() (string, string) {
	path, viaEnv := p.path()
	if path == "" { // no home directory and no CLAUDE_CONFIG_DIR: there is nowhere for a login to be
		return "", proto.ReasonNoHome
	}
	data, err := os.ReadFile(filepath.Clean(path))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", p.missing(viaEnv, proto.ReasonNoClaudeJSON)
	case err != nil:
		return "", proto.ReasonUnreadable
	}
	id, ok := parseIdentity(data)
	switch {
	case !ok:
		return "", proto.ReasonParseError
	case id == "":
		return "", p.missing(viaEnv, proto.ReasonNoOAuthAccount)
	}
	return id, ""
}

// missing upgrades "nothing is signed in here" to the more actionable code: the agent was pointed
// at another config dir, or another user on this host is the one who is signed in.
func (p identityProbe) missing(viaEnv bool, code string) string {
	if viaEnv {
		return proto.ReasonConfigDirElsewhere
	}
	if code == proto.ReasonNoClaudeJSON && p.otherHomeSignedIn() {
		return proto.ReasonHomeMismatch
	}
	return code
}

// candidates lists the other-user files the home_mismatch probe may look at, capped so a host
// with thousands of home directories cannot turn one identity read into a directory walk.
func (p identityProbe) candidates() []string {
	cands := make([]string, 0, len(p.otherHomeFiles)+maxOtherHomes)
	for _, g := range p.otherHomeGlobs {
		m, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		cands = append(cands, m...)
	}
	// The cap bounds the globbed part only: the named files are a fixed, short list, and a host
	// with more than maxOtherHomes home directories must not push /root off the end.
	if len(cands) > maxOtherHomes {
		cands = cands[:maxOtherHomes]
	}
	return append(cands, p.otherHomeFiles...)
}

// otherHomeSignedIn reports whether another user on this host has a .claude.json. It only stats:
// the other user's file is never read, and neither its path nor their name leaves this function.
func (p identityProbe) otherHomeSignedIn() bool {
	for _, c := range p.candidates() {
		if p.home != "" && filepath.Clean(filepath.Dir(c)) == filepath.Clean(p.home) {
			continue // our own home: that is the file run() already tried
		}
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
			return true
		}
	}
	return false
}

// parseIdentity returns the signed-in account's email, else its account uuid, from a .claude.json
// body. ok is false when the body is not the JSON the agent expects, or the value is absurdly
// long; an empty id with ok=true means the file names no account.
func parseIdentity(data []byte) (id string, ok bool) {
	var f struct {
		OAuthAccount struct {
			Email string `json:"emailAddress"`
			UUID  string `json:"accountUuid"`
		} `json:"oauthAccount"`
	}
	if json.Unmarshal(data, &f) != nil {
		return "", false
	}
	id = f.OAuthAccount.Email
	if id == "" {
		id = f.OAuthAccount.UUID
	}
	if len(id) > maxIdentity {
		return "", false
	}
	return id, true
}

// identityCache holds the last probe result, so every report says the same thing and a change is
// logged once: reports go out on every heartbeat, and a code repeated every 15 s is noise.
type identityCache struct {
	mu     sync.Mutex
	probe  func() (string, string)
	log    *slog.Logger
	set    bool
	id     string
	reason string
}

// current returns the cached identity and reason, probing once if nothing is cached yet.
func (c *identityCache) current() (string, string) {
	c.mu.Lock()
	if c.set {
		defer c.mu.Unlock()
		return c.id, c.reason
	}
	c.mu.Unlock()
	return c.refresh()
}

// refresh re-reads the identity and logs a change. Only the code is logged: an identity can be an
// email address.
func (c *identityCache) refresh() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, reason := c.probe()
	changed := !c.set || id != c.id || reason != c.reason
	c.set, c.id, c.reason = true, id, reason
	if !changed || c.log == nil {
		return id, reason
	}
	if id != "" {
		c.log.Info("signed-in identity found", "action", "identity", "result", "signed_in")
	} else {
		c.log.Warn("no signed-in identity", "action", "identity", "result", "missing", "reason", reason)
	}
	return id, reason
}

// realTicker is the production tick seam.
func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// watchIdentity keeps the cached identity current: every a.identityEvery, and at once on a reload
// signal where the platform has one. The next report carries any change, so a sign-in, a sign-out
// or a switch after start needs no restart.
func (a *agent) watchIdentity(ctx context.Context) {
	tick, stopTick := a.tick(a.identityEvery)
	defer stopTick()
	hup, stopHup := a.hup()
	defer stopHup()
	a.ident.refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			a.ident.refresh()
		case <-hup:
			a.log.Info("re-reading signed-in identity", "action", "identity", "result", "signalled")
			a.ident.refresh()
		}
	}
}
