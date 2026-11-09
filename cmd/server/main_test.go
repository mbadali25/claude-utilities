package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"claude-utilities/internal/adminpw"
	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func refreshPoller(t *testing.T, id string, enabled bool, serverOwned bool, listed ...string) (hits *int32, persisted *[]byte, wired bool, p *usage.Poller) {
	t.Helper()
	return refreshPollerGate(t, id, enabled, listed, func(string) bool { return serverOwned })
}

// refreshPollerOwned wires the flag on with the given ownership gate and allowlist.
func refreshPollerOwned(t *testing.T, id string, listed []string, serverOwned func(string) bool) (hits *int32, persisted *[]byte, wired bool, p *usage.Poller) {
	t.Helper()
	return refreshPollerGate(t, id, true, listed, serverOwned)
}

func refreshPollerGate(t *testing.T, id string, enabled bool, listed []string, serverOwned func(string) bool) (hits *int32, persisted *[]byte, wired bool, p *usage.Poller) {
	t.Helper()
	var n int32
	var saved []byte
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		_, _ = io.WriteString(w, `{"access_token":"new-a","expires_in":60}`)
	}))
	t.Cleanup(tok.Close)
	api := doerFunc(func(r *http.Request) (*http.Response, error) {
		code := 401
		if r.Header.Get("Authorization") == "Bearer new-a" {
			code = 200
		}
		return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	p = usage.NewPoller(api, usage.Config{})
	blk := json.RawMessage(`{"accessToken":"old-a","refreshToken":"old-r","mcpOAuth":{"x":1}}`)
	p.SetAccounts(func() []vault.Account { return []vault.Account{{ID: id, Block: blk}} })
	r := usage.NewOAuthRefresher()
	r.URL = tok.URL
	wired = wireRefresher(p, enabled, r, logx.New(io.Discard), listed, serverOwned, func(_ string, b json.RawMessage) error {
		saved = append([]byte(nil), b...)
		return nil
	})
	return &n, &saved, wired, p
}

func TestRefreshFlagOffWiresNothing(t *testing.T) {
	hits, saved, wired, p := refreshPoller(t, "a", false, true, "a")
	p.RefreshNow(context.Background(), []string{"a"})
	if wired || *hits != 0 || *saved != nil {
		t.Fatalf("wired=%v hits=%d saved=%q", wired, *hits, *saved)
	}
}

func TestRefreshFlagOnRefreshesServerOwnedAndPersists(t *testing.T) {
	hits, saved, wired, p := refreshPoller(t, "a", true, true, "a")
	p.RefreshNow(context.Background(), []string{"a"})
	if !wired || *hits != 1 || !strings.Contains(string(*saved), `"new-a"`) || !strings.Contains(string(*saved), `"mcpOAuth":{"x":1}`) {
		t.Fatalf("wired=%v hits=%d saved=%q", wired, *hits, *saved)
	}
}

func TestRefreshFlagOnNeverRefreshesHeldAccount(t *testing.T) {
	hits, saved, _, p := refreshPoller(t, "a", true, false, "a")
	res := p.RefreshNow(context.Background(), []string{"a"})
	if *hits != 0 || *saved != nil || res[0].Usage.Err != "unauthorized" {
		t.Fatalf("hits=%d saved=%q res=%+v", *hits, *saved, res[0])
	}
}

// logRefresh runs one refresh through wireRefresher with a captured log; persist sees the log as it
// stands when the vault write happens.
func logRefresh(t *testing.T, persist func(id string, b json.RawMessage, logSoFar string) error) string {
	t.Helper()
	var buf bytes.Buffer
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"new-a","expires_in":60}`)
	}))
	t.Cleanup(tok.Close)
	api := doerFunc(func(r *http.Request) (*http.Response, error) {
		code := 401
		if r.Header.Get("Authorization") == "Bearer new-a" {
			code = 200
		}
		return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	p := usage.NewPoller(api, usage.Config{})
	blk := json.RawMessage(`{"accessToken":"old-a","refreshToken":"old-r"}`)
	p.SetAccounts(func() []vault.Account { return []vault.Account{{ID: "acct-1", Block: blk}} })
	r := usage.NewOAuthRefresher()
	r.URL = tok.URL
	wireRefresher(p, true, r, logx.New(&buf), []string{"acct-1"}, func(string) bool { return true },
		func(id string, b json.RawMessage) error { return persist(id, b, buf.String()) })
	p.RefreshNow(context.Background(), []string{"acct-1"})
	return buf.String()
}

func TestRefreshSuccessLogsOkOnlyAfterPersist(t *testing.T) {
	var before string
	out := logRefresh(t, func(_ string, _ json.RawMessage, soFar string) error { before = soFar; return nil })
	if strings.Contains(before, `"result":"ok"`) {
		t.Fatalf("ok logged before the vault write: %s", before)
	}
	for _, w := range []string{`"action":"refresh"`, `"result":"ok"`, `"account":"acct-1"`} {
		if !strings.Contains(out, w) {
			t.Fatalf("log lacks %s: %s", w, out)
		}
	}
	for _, bad := range []string{"new-a", "old-a", "old-r", "[dropped]"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log contains %q: %s", bad, out)
		}
	}
}

func TestRefreshPersistFailureLogsErrorAndNotOk(t *testing.T) {
	out := logRefresh(t, func(string, json.RawMessage, string) error { return os.ErrPermission })
	if strings.Contains(out, `"result":"ok"`) || !strings.Contains(out, `"level":"ERROR"`) ||
		!strings.Contains(out, `"result":"failed"`) || !strings.Contains(out, `"account":"acct-1"`) {
		t.Fatalf("log: %s", out)
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// noStdin stands in for a closed stdin: run must not read it unless set-password was asked for.
func noStdin() *strings.Reader { return strings.NewReader("") }

func TestListenRequiredRefusesStartWithoutFlag(t *testing.T) {
	var out bytes.Buffer
	full := map[string]string{keyEnv: "k", passwordEnv: "p"}
	if code := run(context.Background(), nil, env(full), noStdin(), &out); code == 0 || !strings.Contains(out.String(), "--listen") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func TestMissingSecretsRefuseStart(t *testing.T) {
	for _, m := range []map[string]string{{passwordEnv: "p"}, {keyEnv: "k"}} {
		var out bytes.Buffer
		code := run(context.Background(), []string{"--listen", "127.0.0.1:0", "--data-dir", t.TempDir()}, env(m), noStdin(), &out)
		if code == 0 || !strings.Contains(out.String(), "CLAUDESWAP_") {
			t.Fatalf("env %v: code %d out %q", m, code, out.String())
		}
	}
}

func TestBadListenAddressRefused(t *testing.T) {
	var out bytes.Buffer
	args := []string{"--listen", "nonsense", "--data-dir", t.TempDir()}
	if code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "p"}), noStdin(), &out); code == 0 {
		t.Fatalf("accepted %q", out.String())
	}
}

// --- set-password ---

// setPassword runs the subcommand against dir with stdin holding in.
func setPassword(t *testing.T, dir, in string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), []string{"set-password", "--data-dir", dir}, env(nil), strings.NewReader(in), &out)
	return code, out.String()
}

func TestSetPasswordReadsStdinAndStoresAHash(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, "a-long-enough-password\n"); code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	p := filepath.Join(dir, adminpw.FileName)
	data, err := os.ReadFile(p) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("hash file: %v", err)
	}
	if strings.Contains(string(data), "a-long-enough-password") {
		t.Fatal("the hash file holds the plaintext")
	}
	// A new store over the same dir authenticates it, and ignores a different bootstrap.
	s, err := adminpw.Open(p, "env-bootstrap-value")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Stored() || !s.Verify("a-long-enough-password") || s.Verify("env-bootstrap-value") {
		t.Fatalf("stored=%v stdin=%v env=%v", s.Stored(), s.Verify("a-long-enough-password"), s.Verify("env-bootstrap-value"))
	}
}

func TestSetPasswordAcceptsStdinWithoutATrailingNewline(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, "no-trailing-newline-pw"); code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	s, err := adminpw.Open(filepath.Join(dir, adminpw.FileName), "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Verify("no-trailing-newline-pw") {
		t.Fatal("password not stored as typed")
	}
}

func TestSetPasswordRefusesTooShortAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	code, out := setPassword(t, dir, strings.Repeat("x", adminpw.MinLength-1)+"\n")
	if code != 2 || !strings.Contains(out, "at least 12 characters") {
		t.Fatalf("code %d out %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, adminpw.FileName)); !os.IsNotExist(err) {
		t.Fatalf("hash file written for a short password: %v", err)
	}
}

func TestSetPasswordRefusesEmptyStdin(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, ""); code != 2 || !strings.Contains(out, "stdin") {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestSetPasswordHasNoPasswordFlagOrArgument(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	args := []string{"set-password", "--data-dir", dir, "--password", "a-long-enough-password"}
	if code := run(context.Background(), args, env(nil), noStdin(), &out); code == 0 {
		t.Fatalf("--password accepted: %q", out.String())
	}
	out.Reset()
	args = []string{"set-password", "--data-dir", dir, "a-long-enough-password"}
	if code := run(context.Background(), args, env(nil), noStdin(), &out); code == 0 {
		t.Fatalf("a positional password accepted: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, adminpw.FileName)); !os.IsNotExist(err) {
		t.Fatalf("a hash was written from argv: %v", err)
	}
}

func TestServerStartsWithAStoredHashAndNoEnvPassword(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, "a-long-enough-password\n"); code != 0 {
		t.Fatalf("set-password code %d out %q", code, out)
	}
	// With a hash on disk the admin password environment variable is no longer required, so the
	// only complaint left is the missing listen address.
	var out bytes.Buffer
	code := run(context.Background(), []string{"--data-dir", dir}, env(map[string]string{keyEnv: "k"}), noStdin(), &out)
	if code != 2 || !strings.Contains(out.String(), "--listen") {
		t.Fatalf("code %d out %q", code, out.String())
	}
	if strings.Contains(out.String(), passwordEnv) {
		t.Fatalf("still demands %s with a hash stored: %q", passwordEnv, out.String())
	}
}

// --- Task 2.2: exit 5 and a reason for a refused certificate ---

// certErrors is the exported refusal set of internal/hub; exit 5 covers all of it.
func certErrors() []error {
	return []error{
		hub.ErrCertPairIncomplete, hub.ErrCertUnreadable, hub.ErrCertCorrupt,
		hub.ErrCertMismatch, hub.ErrCertExpired,
	}
}

func TestCertExitCodeIsFiveForEveryCertError(t *testing.T) {
	for _, e := range certErrors() {
		if got := certExitCode(fmt.Errorf("serve: %w", e)); got != 5 {
			t.Errorf("%v: exit %d, want 5", e, got)
		}
	}
}

func TestCertExitCodeIsOneForAnUnrelatedError(t *testing.T) {
	if got := certExitCode(io.ErrUnexpectedEOF); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if got := exitCodeFor(io.ErrUnexpectedEOF); got != 1 {
		t.Fatalf("exitCodeFor %d, want 1", got)
	}
}

func TestCertReasonCarriesAReasonForEveryCertError(t *testing.T) {
	for _, e := range certErrors() {
		if got := certReason(fmt.Errorf("serve: %w", e)); got == "" {
			t.Errorf("%v: no reason", e)
		}
	}
}

func TestCertReasonIsEmptyForAnUnrelatedError(t *testing.T) {
	if got := certReason(io.ErrUnexpectedEOF); got != "" {
		t.Fatalf("reason %q invented for a non-certificate error", got)
	}
}

// halfPairDataDir makes a data dir whose tls/ holds only the certificate, which is the crash or
// half-copy case: the pin must not change.
func halfPairDataDir(t *testing.T) (dir, certFile string) {
	t.Helper()
	dir = t.TempDir()
	tls := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tls, 0o700); err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(tls, "server-cert.pem")
	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nnot-parsed-before-the-pair-check\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, certFile
}

func TestServeRefusesWithFiveOnIncompletePair(t *testing.T) {
	dir, certFile := halfPairDataDir(t)
	before, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"--listen", "127.0.0.1:0", "--data-dir", dir}
	code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "a-long-enough-password"}), noStdin(), &out)
	if code != 5 {
		t.Fatalf("code %d, want 5: %s", code, out.String())
	}
	after, err := os.ReadFile(certFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the certificate was rewritten: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls", "server-key.pem")); !os.IsNotExist(err) {
		t.Fatalf("a new pair was written: %v", err)
	}
}

func TestCertRefusedLogLineCarriesTheReason(t *testing.T) {
	dir, _ := halfPairDataDir(t)
	var out bytes.Buffer
	args := []string{"--listen", "127.0.0.1:0", "--data-dir", dir}
	if code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "a-long-enough-password"}), noStdin(), &out); code != 5 {
		t.Fatalf("code %d: %s", code, out.String())
	}
	var line map[string]any
	var found int
	for _, l := range strings.Split(out.String(), "\n") {
		if !strings.Contains(l, `"cert refused"`) {
			continue
		}
		found++
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatalf("not a JSON log line: %q: %v", l, err)
		}
		// The reason is the only cert detail a log line may carry: no path, no fingerprint, no key.
		for _, leak := range []string{dir, "server-cert.pem", "server-key.pem", "BEGIN"} {
			if strings.Contains(l, leak) {
				t.Fatalf("log line %q carries %q", l, leak)
			}
		}
	}
	if found != 1 {
		t.Fatalf("want exactly one `cert refused` line, got %d:\n%s", found, out.String())
	}
	if line["reason"] != "incomplete" {
		t.Fatalf("reason = %v, want incomplete", line["reason"])
	}
}

// --- Task 1.2, as Task 3a.2 left it: exit 4 for a vault this binary cannot read ---
//
// Two causes now share the code. A header written by a newer server is ErrNewerFormat; a header
// this binary can parse but not believe - every out-of-bounds number in a v2 header included - is
// ErrMalformed. Since CSV2 became the current format the committed 40-byte fixture is the second
// kind, not the first, so each cause gets a test of its own below rather than one test that passes
// for whichever reason happens to fire.

// unreadableVault makes a data dir whose vault.bin is the committed 40-byte CSV2 fixture: a
// malformed v2 header, whose 24-byte header claim leaves the file short of the minimum. It reads
// the committed fixture rather than rebuilding those bytes here, so this test and the deploy gate
// (which copies the same file to the server host) cannot disagree about what produces exit 4.
//
// It also sets the passphrase in the real environment: run's injected getenv gates the flag check,
// but internal/vault reads os.Getenv itself, so the env map alone never reaches vault.Open.
func unreadableVault(t *testing.T) (dir, vaultFile string) {
	t.Helper()
	return vaultDirWith(t, readFixture(t, "newer-v2-header.bin"))
}

// readFixture reads one of internal/vault's committed test fixtures.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "vault", "testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return data
}

// vaultDirWith drops data in a fresh data dir as vault.bin.
func vaultDirWith(t *testing.T, data []byte) (dir, vaultFile string) {
	t.Helper()
	t.Setenv(keyEnv, "a-test-passphrase")
	dir = t.TempDir()
	vaultFile = filepath.Join(dir, "vault.bin")
	if err := os.WriteFile(vaultFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, vaultFile
}

// vThreeVault builds a v2 file whose header differs from the committed golden header in `v` alone:
// the same magic, the same header length arithmetic, every member present and in bounds, a nonce
// and a tag-sized payload after it. Isolating `v` is the whole point - a header carrying `"v":3`
// and nothing else would be both a wrong version and a malformed header, and since both exit 4 it
// would pass whichever branch ran first and prove nothing.
//
// Built here rather than committed as a fixture: it is a few hundred bytes derived from a file that
// is already committed, and a second fixture would be one more thing to keep in step with it.
func vThreeVault(t *testing.T) (dir, vaultFile string) {
	t.Helper()
	golden := bytes.TrimSuffix(readFixture(t, "header-golden.json"), []byte("\n"))
	hdr := bytes.Replace(golden, []byte(`{"v":2,`), []byte(`{"v":3,`), 1)
	if bytes.Equal(hdr, golden) {
		t.Fatal("the golden header no longer starts with the version member")
	}
	var buf bytes.Buffer
	buf.WriteString("CSV2")
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(hdr)))
	buf.Write(n[:])
	buf.Write(hdr)
	buf.Write(make([]byte, 12+16)) // nonce, then a tag-sized payload
	return vaultDirWith(t, buf.Bytes())
}

func TestVaultExitCodeIsFourForNewerFormat(t *testing.T) {
	newer := fmt.Errorf("serve: %w", vault.ErrNewerFormat)
	if got := vaultExitCode(newer); got != 4 {
		t.Errorf("vaultExitCode %d, want 4", got)
	}
	if got := exitCodeFor(newer); got != 4 {
		t.Errorf("exitCodeFor %d, want 4", got)
	}
}

// A malformed vault is the same 4 and for the same reason - a restart cannot make it readable - and
// it must not be 3: pushing an operator towards rotating a correct passphrase over a crafted header
// is the one answer the format's bounds exist to prevent.
func TestVaultExitCodeIsFourForAMalformedVault(t *testing.T) {
	bad := fmt.Errorf("serve: %w", vault.ErrMalformed)
	if got := vaultExitCode(bad); got != 4 {
		t.Errorf("vaultExitCode %d, want 4", got)
	}
	if got := exitCodeFor(bad); got != 4 {
		t.Errorf("exitCodeFor %d, want 4", got)
	}
	if got := vaultReason(bad); got != "malformed" {
		t.Errorf("vaultReason %q, want malformed", got)
	}
}

func TestVaultExitCodeIsOneForAnUnrelatedError(t *testing.T) {
	if got := vaultExitCode(io.ErrUnexpectedEOF); got != 1 {
		t.Errorf("vaultExitCode %d, want 1", got)
	}
	// The order inside exitCodeFor is fixed rather than left to the reader: a certificate refusal
	// is the more specific answer, so it keeps 5 even once the vault rows exist.
	if got := exitCodeFor(fmt.Errorf("serve: %w", hub.ErrCertExpired)); got != 5 {
		t.Errorf("exitCodeFor %d for a cert refusal, want 5", got)
	}
}

// serveRefusedOnVault runs the server against dir, insists on the exit code, and insists that
// nothing in the data dir was written: not vault.bin, not a half-finished replacement. One helper
// for both causes, so neither can quietly stop checking the write half.
func serveRefusedOnVault(t *testing.T, dir, vaultFile string, want int) string {
	t.Helper()
	before, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"--listen", "127.0.0.1:0", "--data-dir", dir}
	code := run(context.Background(), args, env(map[string]string{keyEnv: "a-test-passphrase", passwordEnv: "a-long-enough-password"}), noStdin(), &out)
	if code != want {
		t.Fatalf("code %d, want %d: %s", code, want, out.String())
	}
	after, err := os.ReadFile(vaultFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("vault.bin was rewritten: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	return out.String()
}

// The fixture is a malformed v2 header since CSV2 became readable, so this is the malformed cause
// of exit 4, not the newer-server one. Renamed from TestServeOnANewerFormatVaultExitsFourAndWrites-
// Nothing so the name says which cause it covers; the newer-server cause is the v=3 test below.
func TestServeOnAnUnreadableVaultExitsFourAndWritesNothing(t *testing.T) {
	dir, vaultFile := unreadableVault(t)
	out := serveRefusedOnVault(t, dir, vaultFile, 4)
	if !strings.Contains(out, "malformed") {
		t.Fatalf("the operator is not told the file is unreadable: %s", out)
	}
	if strings.Contains(out, "newer server") {
		t.Fatalf("a malformed header is reported as a newer format: %s", out)
	}
}

// The newer-server cause keeps a test of its own, through the one header that differs from the
// golden in `v` alone, so Task 1.2's ErrNewerFormat -> 4 wiring is still pinned by a real run.
func TestServeOnAVThreeHeaderExitsFourAndWritesNothing(t *testing.T) {
	dir, vaultFile := vThreeVault(t)
	out := serveRefusedOnVault(t, dir, vaultFile, 4)
	if !strings.Contains(out, "newer server") || !strings.Contains(out, "server vault downgrade") {
		t.Fatalf("the operator is not told who wrote the file: %s", out)
	}
	if strings.Contains(out, "malformed") {
		t.Fatalf("a newer format is also reported as malformed: %s", out)
	}
}

// formatLine insists on exactly one `format` log line and returns it, having scanned the whole
// line for anything it may not carry: no path, no passphrase, no file bytes, in any field.
func formatLine(t *testing.T, out string, leaks []string) map[string]any {
	t.Helper()
	var line map[string]any
	var found int
	for _, l := range strings.Split(out, "\n") {
		// Matched on the message field, not a bare `"format"` token: a later log line that merely
		// mentions the word must not be counted as this one.
		if !strings.Contains(l, `"msg":"format"`) {
			continue
		}
		found++
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatalf("not a JSON log line: %q: %v", l, err)
		}
		for _, leak := range leaks {
			if strings.Contains(l, leak) {
				t.Fatalf("log line %q carries %q", l, leak)
			}
		}
	}
	if found != 1 {
		t.Fatalf("want exactly one `format` line, got %d:\n%s", found, out)
	}
	return line
}

func TestMalformedVaultLogLineCarriesTheReason(t *testing.T) {
	dir, vaultFile := unreadableVault(t)
	out := serveRefusedOnVault(t, dir, vaultFile, 4)
	line := formatLine(t, out, []string{dir, "vault.bin", "CSV2", "a-test-passphrase"})
	if line["reason"] != "malformed" {
		t.Fatalf("reason = %v, want malformed", line["reason"])
	}
}

func TestNewerFormatLogLineCarriesTheReason(t *testing.T) {
	dir, vaultFile := vThreeVault(t)
	out := serveRefusedOnVault(t, dir, vaultFile, 4)
	line := formatLine(t, out, []string{dir, "vault.bin", "CSV2", "a-test-passphrase"})
	if line["reason"] != "newer-format" {
		t.Fatalf("reason = %v, want newer-format", line["reason"])
	}
}

// reasonLines returns the structured lines in out whose msg field is msg, so a test can insist on
// exactly one of them rather than on a substring appearing somewhere.
func reasonLines(t *testing.T, out, msg string) []map[string]any {
	t.Helper()
	var found []map[string]any
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, `"msg":"`+msg+`"`) {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatalf("not a JSON log line: %q: %v", l, err)
		}
		found = append(found, line)
	}
	return found
}

// Both reason halves belong to the one reporting helper, not to run's serve branch: `cert renew`
// shares exitCodeFor, so a vault error arriving there would otherwise exit 4 with no reason line
// at all. hub.RenewCert cannot return a vault error today - this is the structure, not a reachable
// bug - and the helper is tested directly because there is no way to make the real command produce
// one.
func TestReportRefusalLogsTheVaultReason(t *testing.T) {
	var out bytes.Buffer
	reportRefusal(&out, "cert renew", fmt.Errorf("renew: %w", vault.ErrNewerFormat))
	lines := reasonLines(t, out.String(), "format")
	if len(lines) != 1 {
		t.Fatalf("want exactly one `format` line, got %d:\n%s", len(lines), out.String())
	}
	if lines[0]["reason"] != "newer-format" {
		t.Fatalf("reason = %v, want newer-format", lines[0]["reason"])
	}
	if len(reasonLines(t, out.String(), "cert refused")) != 0 {
		t.Fatalf("a vault error reported as a certificate refusal:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "cert renew: renew: vault: written by a newer server") {
		t.Fatalf("the prefixed message is gone:\n%s", out.String())
	}
}

func TestReportRefusalLogsTheCertReason(t *testing.T) {
	var out bytes.Buffer
	reportRefusal(&out, "server", fmt.Errorf("serve: %w", hub.ErrCertExpired))
	lines := reasonLines(t, out.String(), "cert refused")
	if len(lines) != 1 || lines[0]["reason"] == "" {
		t.Fatalf("want one `cert refused` line with a reason, got %d:\n%s", len(lines), out.String())
	}
	if len(reasonLines(t, out.String(), "format")) != 0 {
		t.Fatalf("a certificate refusal reported as a vault format:\n%s", out.String())
	}
}

func TestReportRefusalInventsNoReasonForAnUnrelatedError(t *testing.T) {
	var out bytes.Buffer
	reportRefusal(&out, "server", io.ErrUnexpectedEOF)
	for _, msg := range []string{"format", "cert refused"} {
		if len(reasonLines(t, out.String(), msg)) != 0 {
			t.Fatalf("invented a %q line:\n%s", msg, out.String())
		}
	}
	if !strings.Contains(out.String(), "server: "+io.ErrUnexpectedEOF.Error()) {
		t.Fatalf("the prefixed message is gone:\n%s", out.String())
	}
}

func TestServerRefusesACorruptPasswordFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, adminpw.FileName), []byte(`{"v":1,"algo":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"--listen", "127.0.0.1:0", "--data-dir", dir}
	code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "p"}), noStdin(), &out)
	if code == 0 || !strings.Contains(out.String(), "admin password file") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

// --- Task 4.3: `server run` holds the lock, refuses an interrupted vaultop, and reports readiness ---

// storeAdminPassword gives dir an admin password hash, so a run's only remaining input is the vault.
func storeAdminPassword(t *testing.T, dir string) {
	t.Helper()
	if code, out := setPassword(t, dir, "a-long-enough-password\n"); code != 0 {
		t.Fatalf("set-password code %d out %q", code, out)
	}
}

// seams swaps the entry point's seams for a recording set and restores them after the test. It
// returns the recorded order and the buffer the run logged into.
type seamRecorder struct {
	mu    sync.Mutex
	order []string
}

func (r *seamRecorder) note(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, step)
}

func (r *seamRecorder) steps() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// recordedRun runs a console server that stops the moment it reports readiness, and returns the
// exit code, everything it logged, and the order its seams fired in. Readiness is the right place
// to stop: it is sent after the last thing that can fail, so a run that reaches it has done
// everything the entry point does.
func recordedRun(t *testing.T, args []string, envm map[string]string) (int, string, []string) {
	t.Helper()
	// vault.EnvKey reads the process environment, not the injected getenv, so a run that is meant
	// to have a passphrase needs it in both places - and a run that is meant to have none needs the
	// real variable empty whatever the developer's shell holds.
	t.Setenv(keyEnv, envm[keyEnv])
	rec := &seamRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	origLock, origCert, origListen, origReady, origStopping := acquireLock, ensureCert, listenTCP, notifyReady, notifyStopping
	t.Cleanup(func() {
		acquireLock, ensureCert, listenTCP, notifyReady, notifyStopping = origLock, origCert, origListen, origReady, origStopping
	})
	acquireLock = func(dataDir, cmd string) (*vault.Lock, error) {
		rec.note("lock")
		return origLock(dataDir, cmd)
	}
	ensureCert = func(dir string) (string, string, string, error) {
		rec.note("cert")
		return origCert(dir)
	}
	listenTCP = func(network, address string) (net.Listener, error) {
		rec.note("listen")
		return origListen(network, address)
	}
	notifyReady = func() error {
		rec.note("ready")
		cancel() // the server is up; stop it so the test is not a long-running process
		return nil
	}
	notifyStopping = func() error {
		rec.note("stopping")
		return nil
	}
	var out bytes.Buffer
	code := run(ctx, args, env(envm), noStdin(), &out)
	return code, out.String(), rec.steps()
}

// workingDir is a data dir a console run can serve from: an admin password hash, and a passphrase
// in the environment for the vault the run creates.
func workingDir(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	storeAdminPassword(t, dir)
	return dir, map[string]string{keyEnv: "a-test-passphrase"}
}

func TestRunAcquiresTheLockBeforeEnsureCert(t *testing.T) {
	dir, envm := workingDir(t)
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	if len(order) < 2 || order[0] != "lock" || order[1] != "cert" {
		t.Fatalf("order %v: the data-dir lock is taken before EnsureCert, so a second server never writes a certificate", order)
	}
	if _, err := os.Stat(vault.LockPath(dir)); err != nil {
		t.Fatalf("no lock file in the data dir: %v", err)
	}
}

func TestRunSendsReadyAfterTheListenerIsBound(t *testing.T) {
	dir, envm := workingDir(t)
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	li, ri := indexOf(order, "listen"), indexOf(order, "ready")
	if li < 0 || ri < 0 || li > ri {
		t.Fatalf("order %v: READY=1 goes out after the listener is bound, or systemctl start reports a server that is about to exit", order)
	}
	if ci := indexOf(order, "cert"); ci < 0 || ci > li {
		t.Fatalf("order %v: the certificate is settled before the listener binds", order)
	}
	if si := indexOf(order, "stopping"); si < 0 || si < ri {
		t.Fatalf("order %v: STOPPING=1 goes out on the clean stop, after readiness", order)
	}
}

func indexOf(steps []string, want string) int {
	for i, s := range steps {
		if s == want {
			return i
		}
	}
	return -1
}

func TestBareFlagsStillRunTheConsoleServer(t *testing.T) {
	dir, envm := workingDir(t)
	// No subcommand: exactly what scripts/start-server.ps1 and the e2e start script pass.
	code, out, order := recordedRun(t, []string{"--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	for _, want := range []string{"lock", "cert", "listen", "ready"} {
		if indexOf(order, want) < 0 {
			t.Fatalf("the bare flag form skipped %s: %v", want, order)
		}
	}
	if !strings.Contains(out, "listening on https://") {
		t.Fatalf("no listening line: %q", out)
	}
}

func TestRunExitsTwoWhenTheLockIsHeld(t *testing.T) {
	dir, envm := workingDir(t)
	held, err := vault.AcquireLock(dir, "run")
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = held.Release() }()
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
	if code != exitUsage {
		t.Fatalf("code %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "pid") {
		t.Fatalf("the refusal does not name the holder's pid: %q", out)
	}
	if indexOf(order, "cert") >= 0 {
		t.Fatalf("EnsureCert ran while another process held the lock: %v", order)
	}
}

func TestRunRefusesWithExitThreeOnAnInterruptedVaultOp(t *testing.T) {
	dir, envm := workingDir(t)
	if err := vault.WriteVaultOp(dir, vault.VaultOp{
		Op: "rotate", Files: []string{"vault.bin", "tunnelkeys.bin"}, Stage: vault.StageBak,
	}); err != nil {
		t.Fatalf("WriteVaultOp: %v", err)
	}
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
	if code != exitVaultLocked {
		t.Fatalf("code %d, want %d: %s", code, exitVaultLocked, out)
	}
	if !strings.Contains(out, "server vault verify --all-slots") {
		t.Fatalf("the refusal does not name the verify to run: %q", out)
	}
	if indexOf(order, "cert") >= 0 || indexOf(order, "listen") >= 0 {
		t.Fatalf("the run carried on past an interrupted vaultop: %v", order)
	}
	// It settles nothing: the journal is still there for the mutator that owns it.
	if _, ok, err := vault.ReadVaultOp(dir); !ok || err != nil {
		t.Fatalf("the journal was consumed by a run: ok=%v err=%v", ok, err)
	}
	if lines := reasonLines(t, out, "vaultop interrupted"); len(lines) != 1 {
		t.Fatalf("%d structured lines for the interrupted vaultop, want one: %q", len(lines), out)
	}
}

func TestRunExitsTwoWithNoAdminHashAndNoBootstrap(t *testing.T) {
	dir := t.TempDir()
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir},
		map[string]string{keyEnv: "a-test-passphrase"})
	if code != exitUsage {
		t.Fatalf("code %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "server set-password") {
		t.Fatalf("the refusal does not name set-password: %q", out)
	}
	// Nothing is taken and nothing is written for an input this process will never have.
	if indexOf(order, "lock") >= 0 {
		t.Fatalf("the lock was taken for a run that cannot start: %v", order)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("data dir holds %d entries (err %v), want none", len(entries), err)
	}
}

// --- the service entry point: no passphrase, machine slots only ---

func TestRunExitsFourWithNoVaultAndNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	storeAdminPassword(t, dir)
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, nil)
	if code != exitNewerFormat {
		t.Fatalf("code %d, want %d: %s", code, exitNewerFormat, out)
	}
	for _, want := range []string{"no vault at", "server vault init"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the refusal does not say %q: %s", want, out)
		}
	}
	if indexOf(order, "cert") >= 0 || indexOf(order, "listen") >= 0 {
		t.Fatalf("a run with no vault and no passphrase got past the refusal: %v", order)
	}
	// Nothing written: no vault created under a key this process does not have, and no TLS pair.
	for _, name := range []string{"vault.bin", "tunnelkeys.bin", "tls"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s exists after the refusal (stat err %v)", name, err)
		}
	}
}

func TestRunExitsFourOnAV1VaultWithNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	storeAdminPassword(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "vault.bin"), readFixture(t, "vault-v1.bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, nil)
	if code != exitNewerFormat {
		t.Fatalf("code %d, want %d: %s", code, exitNewerFormat, out)
	}
	if !strings.Contains(out, "server vault migrate") {
		t.Fatalf("the refusal does not name the migrate to run: %s", out)
	}
}

func TestRunExitsFourOnAV2VaultWithAV1Keyring(t *testing.T) {
	dir := t.TempDir()
	storeAdminPassword(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "vault.bin"), readFixture(t, "vault-v2.bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A v1 keyring beside a v2 vault: what a crash between the two writes leaves.
	if err := os.WriteFile(filepath.Join(dir, vault.KeyringFileName), []byte("CSK1 not a real keyring"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir, "--tunnels"},
		map[string]string{keyEnv: "a-test-passphrase"})
	if code != exitNewerFormat {
		t.Fatalf("code %d, want %d: %s", code, exitNewerFormat, out)
	}
	if !strings.Contains(out, vault.KeyringFileName) {
		t.Fatalf("the refusal does not name the keyring: %s", out)
	}
	if indexOf(order, "listen") >= 0 {
		t.Fatalf("a --tunnels run started half-open: %v", order)
	}
}

// TestRunWithNoPassphraseOpensAV2VaultThroughTheMachineSlot pins the behaviour this slice changes
// on the console path, which is the same command as the service's. CLAUDESWAP_KEY is no longer
// required to start: a v2 vault whose machine slot this host can reach now opens with no passphrase
// in the environment, where before the run exited 2 asking for one. That is the service entry point
// by design - a service has no passphrase at all - and the three states it cannot act on are the
// exit-4 refusals above, so this is the one case that newly succeeds and it gets its own test.
func TestRunWithNoPassphraseOpensAV2VaultThroughTheMachineSlot(t *testing.T) {
	dir := t.TempDir()
	storeAdminPassword(t, dir)
	// A machine key this host resolves: the KEK file rung, which both OSes can take in a test.
	kek := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(kek, bytes.Repeat([]byte{0x7e}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDESWAP_KEK_FILE", kek)
	t.Setenv(keyEnv, "a-test-passphrase")
	var initOut bytes.Buffer
	// Not a skip: `vault init` takes the dpapi rung on windows-latest and the kek-file rung on
	// ubuntu-latest, and both CI runners were checked. A skip here would let the one test that pins
	// this slice's headline behaviour change go quietly green the day either rung stops working.
	if code := run(context.Background(), []string{"vault", "init", "--data-dir", dir},
		env(map[string]string{keyEnv: "a-test-passphrase"}), noStdin(), &initOut); code != 0 {
		t.Fatalf("no v2 vault to serve: `vault init` exited %d here: %s", code, initOut.String())
	}

	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, nil)
	if code != 0 {
		t.Fatalf("code %d, want 0: a v2 vault with a reachable machine slot serves with no passphrase: %s", code, out)
	}
	if indexOf(order, "ready") < 0 {
		t.Fatalf("the run never reported readiness: %v", order)
	}
	if strings.Contains(out, "set "+keyEnv) {
		t.Fatalf("the run still demands a passphrase: %s", out)
	}
}

// TestRunExitsThreeWhenNoSlotCanUnwrapWithNoPassphrase is the spec's exit-3 row - "vault locked: no
// slot could unwrap" - on the entry point this slice adds, and it is the failure half of the test
// above. The fixture's machine slot is a kek-file one and the KEK this host resolves holds the wrong
// key, so the slot is reachable, is tried, and does not unwrap: ErrBadKey, not ErrKEKUnreachable.
//
// With no passphrase there is no second way in, which is exactly "vault locked", so it must be 3 and
// out of the restart loop. Exit 1 here would be a restart storm on the one case the spec names by
// name - a restored data dir or a cleared machine key - because 1 is the only retried code.
func TestRunExitsThreeWhenNoSlotCanUnwrapWithNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	storeAdminPassword(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "vault.bin"), readFixture(t, "vault-v2.bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(kek, bytes.Repeat([]byte{0x11}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDESWAP_KEK_FILE", kek)
	code, out, order := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, nil)
	if code != exitVaultLocked {
		t.Fatalf("code %d, want %d (vault locked: no slot could unwrap, and 1 would be retried): %s",
			code, exitVaultLocked, out)
	}
	if indexOf(order, "listen") >= 0 {
		t.Fatalf("a run that could not open the vault bound a listener: %v", order)
	}
}

// TestServiceExitCodeLocksTheVaultOnlyWithoutAPassphrase pins both sides of the one row that depends
// on the entry point. With a passphrase in the environment ErrBadKey is a wrong CLAUDESWAP_KEY - an
// operator's typo at a console, exit 1 - and with none it is the locked vault, exit 3. ErrNoKey goes
// the same way: with no passphrase it is the answer recoverDEK gives when the only slots are ones
// this host has no opener for, which is a restored data dir and not a retryable fault.
func TestServiceExitCodeLocksTheVaultOnlyWithoutAPassphrase(t *testing.T) {
	for _, err := range []error{vault.ErrBadKey, vault.ErrNoKey,
		fmt.Errorf("no slot could unwrap the data key: %w", vault.ErrBadKey)} {
		if got := exitCodeForRun(err, false); got != exitVaultLocked {
			t.Fatalf("%v with no passphrase: exit %d, want %d", err, got, exitVaultLocked)
		}
		if got := exitCodeForRun(err, true); got != exitRuntime {
			t.Fatalf("%v with a passphrase: exit %d, want %d", err, got, exitRuntime)
		}
	}
	// The rows that do not depend on the entry point keep their codes either way.
	for _, c := range []struct {
		err  error
		want int
	}{
		{vault.ErrKEKUnreachable, exitVaultLocked},
		{vault.ErrNewerFormat, exitNewerFormat},
		{vault.ErrMalformed, exitNewerFormat},
		{hub.ErrCertExpired, exitCertRefused},
		{os.ErrPermission, exitRuntime},
	} {
		for _, hasPass := range []bool{false, true} {
			if got := exitCodeForRun(c.err, hasPass); got != c.want {
				t.Fatalf("%v (passphrase=%v): exit %d, want %d", c.err, hasPass, got, c.want)
			}
		}
	}
}

// --- Decision 10: one data dir, and a warning when two disagree ---

func TestRunLogsDataDirThroughTildePathOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, "data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	storeAdminPassword(t, dir)
	code, out, _ := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir},
		map[string]string{keyEnv: "a-test-passphrase"})
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	var seen []string
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, `"datadir"`) {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatalf("not a JSON log line: %q: %v", l, err)
		}
		seen = append(seen, fmt.Sprint(line["datadir"]))
	}
	if len(seen) != 1 {
		t.Fatalf("%d datadir lines (%v), want exactly one", len(seen), seen)
	}
	if want := logx.TildePath(dir); seen[0] != want {
		t.Fatalf("logged %q, want %q: the path goes through TildePath, so a home directory never carries a username into a log", seen[0], want)
	}
	if strings.Contains(seen[0], home) {
		t.Fatalf("the logged path still holds the home directory: %q", seen[0])
	}
}

func TestRunWarnsWhenAServiceIsRegisteredWithAnotherDataDir(t *testing.T) {
	dir, envm := workingDir(t)
	other := t.TempDir()
	orig := registeredDataDir
	t.Cleanup(func() { registeredDataDir = orig })

	registeredDataDir = func() (string, bool) { return other, true }
	code, out, _ := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	warn := reasonLines(t, out, "a service is registered with a different data dir")
	if len(warn) != 1 {
		t.Fatalf("%d warnings, want one: %q", len(warn), out)
	}
	if got := fmt.Sprint(warn[0]["datadir"]); got != logx.TildePath(other) {
		t.Fatalf("the warning names %q, want the registered dir %q", got, logx.TildePath(other))
	}

	// The same dir is not a disagreement, and neither is a host with no service registered.
	for _, reg := range []func() (string, bool){
		func() (string, bool) { return dir, true },
		func() (string, bool) { return "", false },
	} {
		registeredDataDir = reg
		code, out, _ := recordedRun(t, []string{"run", "--listen", "127.0.0.1:0", "--data-dir", dir}, envm)
		if code != 0 {
			t.Fatalf("code %d out %q", code, out)
		}
		if n := len(reasonLines(t, out, "a service is registered with a different data dir")); n != 0 {
			t.Fatalf("%d warnings for a dir that agrees: %q", n, out)
		}
	}
}
