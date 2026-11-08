package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/tunnel"
	"claude-utilities/internal/vault"
)

// The values no response, page or log may leak. A real tunnel.Manager is used behind the
// handler, with the supervisor never started, so no ssh child is ever spawned.
const (
	tunAddress = "host-9.estate.invalid"
	tunUser    = "someoperator"
)

// newTunnelRig is newRig plus a real tunnel.Manager over a real encrypted keyring.
func newTunnelRig(t *testing.T) *rig {
	t.Helper()
	t.Setenv("WEB_TEST_KEY", "test-passphrase")
	t.Setenv("WEB_TUNNEL_KEY", "test-passphrase")
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault.bin"), vault.EnvKey("WEB_TEST_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := vault.OpenKeyring(filepath.Join(dir, vault.KeyringFileName), vault.EnvKey("WEB_TUNNEL_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, fh: &fakeHub{}, v: v, usage: fakeUsage{}, pw: &fakePW{pw: adminPW}, now: fixedNow}
	// Start is deliberately never called, so the supervisor spawns nothing. The manager shares
	// the rig's clock, so a test that needs to get past a per-host rate limit moves r.now
	// instead of sleeping for a minute.
	m, err := tunnel.NewManager(tunnel.Options{DataDir: dir, Now: func() time.Time { return r.now }}, kr)
	if err != nil {
		t.Fatal(err)
	}
	r.tn = m
	r.h = newHandler(r.fh, v, r.usage, r.pw, r.tn, func() time.Time { return r.now })
	return r
}

// jsonBody marshals a body for r.do, which takes the raw string.
func jsonBody(t *testing.T, v any) string {
	t.Helper()
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// tunPost is a write with a session and the CSRF token.
func tunPost(t *testing.T, r *rig, s *session, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return r.do(http.MethodPost, path, jsonBody(t, body), s, s.csrf)
}

// addTunnel posts one tunnel and returns the created view.
func addTunnel(t *testing.T, r *rig, s *session, label string) map[string]any {
	t.Helper()
	res := tunPost(t, r, s, "/api/tunnels",
		map[string]any{"label": label, "address": tunAddress, "user": tunUser})
	if res.Code != http.StatusCreated {
		t.Fatalf("POST /api/tunnels = %d: %s", res.Code, res.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func tunnelIDOf(t *testing.T, v map[string]any) string {
	t.Helper()
	id, _ := v["id"].(string)
	if id == "" {
		t.Fatalf("no id in %v", v)
	}
	return id
}

// --- the flag ---------------------------------------------------------------------------------

// Without --tunnels the feature is not there at all: no routes and no tab. That is what makes
// shipping it a no-op for the default build.
func TestWithoutTheFlagEveryTunnelRouteIsAbsent(t *testing.T) {
	r := newRig(t)
	s := r.login()
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/tunnels"},
		{"POST", "/api/tunnels"},
		{"POST", "/api/tunnels/x/restart"},
		{"POST", "/api/tunnels/x/key/rotate"},
		{"DELETE", "/api/tunnels/x"},
	} {
		res := r.do(c.method, c.path, "{}", s, s.csrf)
		if res.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 with the flag off", c.method, c.path, res.Code)
		}
	}
	if p := page(r, s); strings.Contains(p, `id="tab-tunnels"`) || strings.Contains(p, `id="panel-tunnels"`) {
		t.Error("the Tunnels tab is in the page with the flag off")
	}
}

func TestWithTheFlagTheTabAndThePanelAreInThePage(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{`id="tab-tunnels"`, `id="panel-tunnels"`, `id="tab-tunnels-n"`,
		`aria-controls="panel-tunnels"`, `id="tunnels"`, `id="tun-add-form"`} {
		if !strings.Contains(p, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The third tab must follow the same pattern as the other two, or the existing roving
	// tabindex and panel toggling will not drive it.
	tab := element(t, p, `id="tab-tunnels"`, ">")
	for _, want := range []string{`role="tab"`, `aria-selected="false"`, `tabindex="-1"`} {
		if !strings.Contains(tab, want) {
			t.Errorf("the Tunnels tab lacks %q: %s", want, tab)
		}
	}
	panel := element(t, p, `id="panel-tunnels"`, ">")
	for _, want := range []string{`role="tabpanel"`, `aria-labelledby="tab-tunnels"`, "hidden"} {
		if !strings.Contains(panel, want) {
			t.Errorf("the Tunnels panel lacks %q: %s", want, panel)
		}
	}
}

// --- session, CSRF and rate limits ------------------------------------------------------------

func TestTunnelRoutesNeedASessionAndACSRFToken(t *testing.T) {
	r := newTunnelRig(t)
	// No session at all: 401 whatever the method, like every other /api/ route.
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/tunnels"},
		{"POST", "/api/tunnels"},
		{"POST", "/api/tunnels/x/restart"},
		{"POST", "/api/tunnels/x/key/revoke"},
		{"DELETE", "/api/tunnels/x"},
	} {
		if res := r.do(c.method, c.path, "{}", nil, ""); res.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d, want 401", c.method, c.path, res.Code)
		}
	}
	s := r.login()
	// A session but no CSRF header: 403 on every write, and the write must not happen.
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/tunnels"},
		{"POST", "/api/tunnels/import"},
		{"POST", "/api/tunnels/x"},
		{"POST", "/api/tunnels/x/enable"},
		{"POST", "/api/tunnels/x/disable"},
		{"POST", "/api/tunnels/x/restart"},
		{"POST", "/api/tunnels/x/hostkey"},
		{"POST", "/api/tunnels/x/key/generate"},
		{"POST", "/api/tunnels/x/key/rotate"},
		{"POST", "/api/tunnels/x/key/rotate/commit"},
		{"POST", "/api/tunnels/x/key/rotate/cancel"},
		{"POST", "/api/tunnels/x/key/revoke"},
		{"POST", "/api/tunnels/x/key/revoked"},
		{"DELETE", "/api/tunnels/x"},
	} {
		res := r.do(c.method, c.path, jsonBody(t, map[string]any{"label": "X"}), s, "")
		if res.Code != http.StatusForbidden {
			t.Errorf("%s %s without a CSRF token = %d, want 403", c.method, c.path, res.Code)
		}
	}
	if n := len(r.tn.List()); n != 0 {
		t.Fatalf("a CSRF-less request created %d tunnels", n)
	}
}

func TestRestartIsRateLimitedPerHost(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	id := tunnelIDOf(t, addTunnel(t, r, s, "SRL-LIN"))
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/restart", nil); res.Code != http.StatusOK {
		t.Fatalf("first restart = %d: %s", res.Code, res.Body.String())
	}
	res := tunPost(t, r, s, "/api/tunnels/"+id+"/restart", nil)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("second restart = %d, want 429", res.Code)
	}
}

func TestAddingTunnelsIsRateLimitedEstateWide(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	for i := 0; i < maxAddTunnel; i++ {
		res := tunPost(t, r, s, "/api/tunnels", map[string]any{
			"label": "H" + string(rune('A'+i)), "address": tunAddress, "user": tunUser})
		if res.Code != http.StatusCreated {
			t.Fatalf("add %d = %d: %s", i, res.Code, res.Body.String())
		}
	}
	res := tunPost(t, r, s, "/api/tunnels", map[string]any{"label": "ONEMORE", "address": tunAddress, "user": tunUser})
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("the %dth add = %d, want 429", maxAddTunnel+1, res.Code)
	}
}

func TestKeyActionsAreRateLimitedPerHost(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	id := tunnelIDOf(t, addTunnel(t, r, s, "SRL-LIN"))
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/key/rotate", nil); res.Code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", res.Code, res.Body.String())
	}
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/key/generate", nil); res.Code != http.StatusTooManyRequests {
		t.Fatalf("a key action inside a minute = %d, want 429", res.Code)
	}
}

// --- validation and shape ---------------------------------------------------------------------

func TestTunnelAddRefusesAnythingThatCouldReachAnSSHArgument(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	for name, body := range map[string]map[string]any{
		"space in address":   {"label": "A", "address": "a b", "user": tunUser},
		"flag as address":    {"label": "A", "address": "-oProxyCommand=calc", "user": tunUser},
		"quote in address":   {"label": "A", "address": `a"b`, "user": tunUser},
		"newline in address": {"label": "A", "address": "a\nb", "user": tunUser},
		"shell in address":   {"label": "A", "address": "a;calc", "user": tunUser},
		"bad user":           {"label": "A", "address": tunAddress, "user": "Root User"},
		"flag as user":       {"label": "A", "address": tunAddress, "user": "-oFoo"},
		"bad label":          {"label": "a b", "address": tunAddress, "user": tunUser},
		"missing label":      {"address": tunAddress, "user": tunUser},
		"bad port":           {"label": "A", "address": tunAddress, "user": tunUser, "port": 70000},
	} {
		res := tunPost(t, r, s, "/api/tunnels", body)
		if res.Code != http.StatusBadRequest {
			t.Errorf("%s: POST /api/tunnels = %d, want 400 (%s)", name, res.Code, res.Body.String())
		}
	}
	if n := len(r.tn.List()); n != 0 {
		t.Fatalf("a refused add created %d tunnels", n)
	}
}

func TestUnknownTunnelIsFourOhFour(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	for _, path := range []string{"/api/tunnels/nope/restart", "/api/tunnels/nope/key/rotate",
		"/api/tunnels/nope/enable", "/api/tunnels/nope/hostkey"} {
		res := tunPost(t, r, s, path, map[string]any{"hostKey": "x"})
		if res.Code != http.StatusNotFound && res.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 404 or 400", path, res.Code)
		}
	}
	if res := tunPost(t, r, s, "/api/tunnels/with%20space/restart", nil); res.Code != http.StatusNotFound {
		t.Errorf("an id with a space = %d, want 404", res.Code)
	}
}

// --- no private key ever leaves the server ----------------------------------------------------

// The strongest assertion in this file: generate, rotate, revoke and list, and prove no response
// anywhere carries private key material. The keyring's own test proves the seed is only on disk
// encrypted; this one covers the HTTP surface.
func TestNoTunnelResponseEverCarriesAPrivateKey(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	v := addTunnel(t, r, s, "SRL-LIN")
	id := tunnelIDOf(t, v)

	bodies := []string{r.do(http.MethodGet, "/api/tunnels", "", s, "").Body.String()}
	for _, path := range []string{
		"/api/tunnels/" + id + "/key/rotate",
		"/api/tunnels/" + id + "/key/rotate/cancel",
		"/api/tunnels/" + id + "/key/revoke",
		"/api/tunnels/" + id + "/key/revoked",
		"/api/tunnels/" + id + "/key/generate",
	} {
		// Each one is its own minute for the rate limit, which is why the clock moves.
		r.now = r.now.Add(2 * time.Minute)
		res := tunPost(t, r, s, path, nil)
		if res.Code != http.StatusOK {
			t.Fatalf("POST %s = %d: %s", path, res.Code, res.Body.String())
		}
		bodies = append(bodies, res.Body.String())
	}
	bodies = append(bodies, r.do(http.MethodGet, "/api/tunnels", "", s, "").Body.String())
	for i, b := range bodies {
		for _, never := range []string{"PRIVATE KEY", "openssh-key-v1", `"seed"`, `"prevSeed"`} {
			if strings.Contains(b, never) {
				t.Fatalf("response %d carries %q: %s", i, never, b)
			}
		}
		// A fingerprint and a public key in a command are fine; a 64-character hex seed is not.
		if strings.Contains(b, "BEGIN OPENSSH") {
			t.Fatalf("response %d carries a private key block", i)
		}
	}
}

// --- the generated commands -------------------------------------------------------------------

func TestTheResponseCarriesBothGeneratedCommandsAndTheTightenedOption(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	v := addTunnel(t, r, s, "SRL-LIN")

	install, _ := v["install"].(string)
	remove, _ := v["remove"].(string)
	tight, _ := v["installTight"].(string)
	if install == "" || remove == "" || tight == "" {
		t.Fatalf("a generated command is missing: %v", v)
	}
	if !strings.Contains(install, `command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:8443"`) {
		t.Fatalf("unexpected install command: %s", install)
	}
	if !strings.Contains(tight, `permitopen="127.0.0.1:1"`) {
		t.Fatalf("the tightened option is not offered: %s", tight)
	}
	if strings.Contains(install, "permitopen") {
		t.Fatal("the recommended command carries the unverified option")
	}
	if !strings.Contains(install, "claude-swap-tunnel-SRL-LIN") {
		t.Fatal("the install command does not name the host")
	}
	// The commands are what the operator pastes, so they must be one line each.
	for _, c := range []string{install, remove, tight} {
		if strings.Contains(c, "\n") {
			t.Fatalf("a generated command is not one line: %q", c)
		}
	}
}

// --- the Hosts tab join ------------------------------------------------------------------------

func TestHostsCarryTheirTunnelStateSeparatelyFromTheAgentState(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	// A tunnel keyed on an enrolled host's id, and a host with no tunnel at all.
	res := tunPost(t, r, s, "/api/tunnels", map[string]any{"label": "SRL-LIN", "address": tunAddress,
		"user": tunUser, "hostId": "h1"})
	if res.Code != http.StatusCreated {
		t.Fatalf("add = %d: %s", res.Code, res.Body.String())
	}
	r.fh.hosts = []hub.HostView{
		{HostID: "h1", Name: "box", OS: "linux", Online: false},
		{HostID: "h2", Name: "other", OS: "linux", Online: true},
	}
	var hosts []hostJSON
	if err := json.Unmarshal(r.do(http.MethodGet, "/api/hosts", "", s, "").Body.Bytes(), &hosts); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts", len(hosts))
	}
	if hosts[0].Tunnel == nil {
		t.Fatal("the host with a tunnel has no tunnel state")
	}
	if hosts[0].Tunnel.ID == "" || hosts[0].Tunnel.Short == "" {
		t.Fatalf("the tunnel summary is incomplete: %+v", hosts[0].Tunnel)
	}
	// Two indicators, never merged: this host is offline AND has a tunnel entry.
	if hosts[0].Online {
		t.Fatal("the fixture host should be offline")
	}
	if hosts[1].Tunnel != nil {
		t.Fatal("a host with no tunnel was given tunnel state")
	}
	// And the host row must not carry the address or the username.
	body := r.do(http.MethodGet, "/api/hosts", "", s, "").Body.String()
	for _, never := range []string{tunAddress, tunUser} {
		if strings.Contains(body, never) {
			t.Fatalf("/api/hosts leaked %q", never)
		}
	}
}

// --- host key seeding, enable, remove ---------------------------------------------------------

func TestEnablingNeedsASeededHostKeyFirst(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	id := tunnelIDOf(t, addTunnel(t, r, s, "SRL-LIN"))

	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/enable", nil); res.Code != http.StatusConflict {
		t.Fatalf("enable without a host key = %d, want 409: %s", res.Code, res.Body.String())
	}
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/hostkey", map[string]any{"hostKey": "rubbish"}); res.Code != http.StatusBadRequest {
		t.Fatalf("seeding rubbish = %d, want 400", res.Code)
	}
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/hostkey",
		map[string]any{"hostKey": strings.Repeat("a", maxHostKeyText+1)}); res.Code != http.StatusBadRequest {
		t.Fatalf("an oversized host key = %d, want 400", res.Code)
	}
	res := tunPost(t, r, s, "/api/tunnels/"+id+"/hostkey", map[string]any{"hostKey": sampleHostKey})
	if res.Code != http.StatusOK {
		t.Fatalf("seeding a real host key = %d: %s", res.Code, res.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fp, _ := v["hostKeyFingerprint"].(string); !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("no host key fingerprint: %v", v)
	}
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/enable", nil); res.Code != http.StatusOK {
		t.Fatalf("enable after seeding = %d: %s", res.Code, res.Body.String())
	}
	if res := tunPost(t, r, s, "/api/tunnels/"+id+"/disable", nil); res.Code != http.StatusOK {
		t.Fatalf("disable = %d", res.Code)
	}
}

// sampleHostKey is a valid ed25519 public key line, used as a stand-in host key. It is a public
// key and belongs to no real host.
const sampleHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7Zr1gkRlEb3qZ3Q2nEhKr9f3TRTZ0Rql7dP1xN0xZ1 fixture"

func TestRevokeIsReportedAsPendingAndKeepsOfferingTheRemoveCommand(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	id := tunnelIDOf(t, addTunnel(t, r, s, "SRL-LIN"))

	res := tunPost(t, r, s, "/api/tunnels/"+id+"/key/revoke", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", res.Code, res.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pending, _ := v["revokePending"].(bool); !pending {
		t.Fatalf("a revoke must be reported as pending, not clean: %v", v)
	}
	if state, _ := v["state"].(string); state != string(tunnel.StateRevokePending) {
		t.Fatalf("state = %q, want %q", state, tunnel.StateRevokePending)
	}
	if cmd, _ := v["remove"].(string); !strings.Contains(cmd, "grep -vF") {
		t.Fatalf("the remove command is no longer offered: %v", v)
	}
	// It survives a reload of the list, not just the one response.
	list := r.do(http.MethodGet, "/api/tunnels", "", s, "").Body.String()
	if !strings.Contains(list, `"revokePending":true`) {
		t.Fatalf("the pending revoke is not in the list: %s", list)
	}
}

func TestRemoveForgetsTheTunnelAndHandsBackTheRemoveCommand(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	id := tunnelIDOf(t, addTunnel(t, r, s, "SRL-LIN"))

	res := r.do("DELETE", "/api/tunnels/"+id, "{}", s, s.csrf)
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE = %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "grep -vF") {
		t.Fatalf("DELETE did not hand back the remove command: %s", res.Body.String())
	}
	if n := len(r.tn.List()); n != 0 {
		t.Fatalf("%d tunnels survived the delete", n)
	}
	if res := r.do("DELETE", "/api/tunnels/"+id, "{}", s, s.csrf); res.Code != http.StatusNotFound {
		t.Fatalf("deleting twice = %d, want 404", res.Code)
	}
}

func TestUpdateChangesTheAddressAndRefusesABadOne(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	id := tunnelIDOf(t, addTunnel(t, r, s, "SRL-LIN"))

	res := tunPost(t, r, s, "/api/tunnels/"+id, map[string]any{"address": "moved.estate.invalid", "user": "other", "port": 9443})
	if res.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "moved.estate.invalid") {
		t.Fatalf("the update did not take: %s", res.Body.String())
	}
	if res := tunPost(t, r, s, "/api/tunnels/"+id, map[string]any{"address": "-oProxyCommand=x", "user": "other"}); res.Code != http.StatusBadRequest {
		t.Fatalf("a flag-shaped address = %d, want 400", res.Code)
	}
}

// --- import -----------------------------------------------------------------------------------

// The import must never take a path from the request: that would be an arbitrary file read behind
// an admin session. It reads the fixed location and leaves the file in place, because that file
// is the rollback path for the interim scheduled task.
func TestImportReadsTheFixedPathAndLeavesTheFileInPlace(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	path := filepath.Join(t.TempDir(), "tunnels.json")
	body := `[{"name":"SRL-LIN","host":"` + tunAddress + `","user":"` + tunUser + `"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("CLAUDESWAP_TUNNELS_JSON", path)

	res := tunPost(t, r, s, "/api/tunnels/import", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", res.Code, res.Body.String())
	}
	var out struct {
		Added   int `json:"added"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Added != 1 || out.Skipped != 0 {
		t.Fatalf("added %d skipped %d", out.Added, out.Skipped)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the import consumed the rollback file: %v", err)
	}
	// Imported tunnels arrive disabled, with a key and an install command waiting.
	list := r.do(http.MethodGet, "/api/tunnels", "", s, "").Body.String()
	if strings.Contains(list, `"enabled":true`) {
		t.Fatal("an imported tunnel was enabled, which would clash with the interim task")
	}
	if !strings.Contains(list, "claude-swap-tunnel-SRL-LIN") {
		t.Fatalf("the imported tunnel has no install command: %s", list)
	}
}

func TestImportReportsAMissingFileWithoutEchoingThePath(t *testing.T) {
	r := newTunnelRig(t)
	s := r.login()
	missing := filepath.Join(t.TempDir(), "not-there.json")
	t.Setenv("CLAUDESWAP_TUNNELS_JSON", missing)
	res := tunPost(t, r, s, "/api/tunnels/import", nil)
	if res.Code == http.StatusOK {
		t.Fatal("importing a missing file succeeded")
	}
	if strings.Contains(res.Body.String(), missing) {
		t.Fatalf("the error echoes the path: %s", res.Body.String())
	}
}
