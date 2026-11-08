package logx

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"
)

func logLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("log line is not JSON: %v: %s", err, buf.String())
	}
	return m
}

func TestAllowlistDropsUnknownKeys(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x",
		"accessKey", "leak1-AKIAFAKEFAKEFAKEFAKE",
		"sessionId", "leak2-sess",
		"passcode", "leak3-pc",
		"sid", "leak4-sid",
		"setCookie", "leak5-cookie",
		"authHeader", "leak6-auth",
		"maxToken", "leak7-mt",
		"tokenLen", "leak8-tl",
		"n", 5)
	out := buf.String()
	for i := 1; i <= 8; i++ {
		if strings.Contains(out, "leak"+string(rune('0'+i))) {
			t.Fatalf("leaked leak%d: %s", i, out)
		}
	}
	m := logLine(t, &buf)
	for _, k := range []string{"accessKey", "sessionId", "passcode", "sid", "setCookie", "authHeader", "maxToken", "tokenLen", "n"} {
		if m[k] != "[dropped]" {
			t.Fatalf("%s = %v, want [dropped]: %s", k, m[k], out)
		}
	}
}

func TestAllowlistKeepsKnownKeys(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).With("component", "agent").Info("hello",
		"host", "box1", "hostId", "h-1", "host_id", "h-2", "agent", "a1", "task", "swap", "taskId", "t-9",
		"account", "acct-A", "result", "ok", "reason", "all good", "code", "E42", "action", "swap",
		"event", "started", "attempt", 2, "count", 3, "durationMs", int64(12), "status", "done", "statusCode", 404,
		"pid", 42, "sessionCount", uint64(1), "version", "1.2.3", "err", "boom")
	out := buf.String()
	m := logLine(t, &buf)
	want := map[string]any{
		"msg": "hello", "level": "INFO", "component": "agent", "host": "box1", "hostId": "h-1", "host_id": "h-2",
		"agent": "a1", "task": "swap", "taskId": "t-9", "account": "acct-A", "result": "ok", "reason": "all good",
		"code": "E42", "action": "swap", "event": "started", "attempt": float64(2), "count": float64(3),
		"durationMs": float64(12), "status": "done", "statusCode": float64(404), "pid": float64(42),
		"sessionCount": float64(1), "version": "1.2.3", "err": "boom",
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %v, want %v: %s", k, m[k], v, out)
		}
	}
	if _, ok := m["time"]; !ok {
		t.Fatalf("time missing: %s", out)
	}
	if strings.Contains(out, "[dropped]") {
		t.Fatalf("known key dropped: %s", out)
	}
}

func TestAllowlistedStringValueIsRedactedAndCapped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x", "reason", "dial https://u:pass123@h/x failed")
	m := logLine(t, &buf)
	r, _ := m["reason"].(string)
	if strings.Contains(r, "pass123") || !strings.Contains(r, "dial") || !strings.Contains(r, "failed") {
		t.Fatalf("reason = %q", r)
	}

	buf.Reset()
	long := strings.Repeat("a", 300)
	New(&buf).Info(long, "reason", long)
	m = logLine(t, &buf)
	r, _ = m["reason"].(string)
	if len(r) > 256 || len(r) < 200 || !strings.HasPrefix(r, "aaaa") {
		t.Fatalf("reason not capped sensibly: len=%d %q", len(r), r)
	}
	msg, _ := m["msg"].(string)
	if len(msg) > 256 {
		t.Fatalf("msg not capped: len=%d", len(msg))
	}

	buf.Reset()
	New(&buf).Info("got Bearer msgtok9 from me@example.com", "reason", "x")
	if out := buf.String(); strings.Contains(out, "msgtok9") || strings.Contains(out, "me@example.com") {
		t.Fatalf("msg leaked: %s", out)
	}
}

type lv struct{}

func (lv) LogValue() slog.Value {
	return slog.GroupValue(slog.String("ok", "nonprim5"), slog.String("reason", "nonprim6"))
}

func TestNonPrimitiveUnderAllowedKeyDropped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x",
		"reason", errors.New("boom nonprim1"),
		"result", map[string]string{"a": "nonprim2"},
		"task", struct{ S string }{"nonprim3"},
		"host", []byte("nonprim4"),
		"result", lv{},
		"status", json.RawMessage(`"nonprim7"`),
		"count", []int{80808})
	out := buf.String()
	for _, leak := range []string{"nonprim1", "nonprim2", "nonprim3", "nonprim4", "nonprim5", "nonprim6", "nonprim7", "80808"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
	m := logLine(t, &buf)
	for _, k := range []string{"reason", "result", "task", "host", "status", "count"} {
		if m[k] != "[dropped]" {
			t.Fatalf("%s = %v, want [dropped]: %s", k, m[k], out)
		}
	}
}

// vaultKeys are the keys Task 3a.9 adds for the vault and the service. They are in the `allowed`
// map literal, beside the twenty-six that were there before, rather than registered through Allow:
// Allow is for a package registering its own field at init time, and a second place where the
// base list lives is a second place for it to drift. Slice 8 adds `statedir`, `mech`, `operator`
// and `setat` to the same literal, never a parallel list.
var vaultKeys = []string{"slot", "slottype", "slots", "format", "service", "op", "exit", "datadir"}

func TestNewKeysAreAllowed(t *testing.T) {
	for _, k := range vaultKeys {
		var buf bytes.Buffer
		New(&buf).Info("x", k, "v-"+k)
		m := logLine(t, &buf)
		if m[k] != "v-"+k {
			t.Errorf("%s = %v, want %q: %s", k, m[k], "v-"+k, buf.String())
		}
	}
}

// The new keys must also be registrable through Allow, because that is the check that says a key
// name cannot carry a secret. A key already in `allowed` returns from Allow before the check runs,
// so asserting Allow does not panic would prove nothing: the substrings are compared directly.
// This is what rules out `exitcode` and is why the exit status is logged as `exit`.
func TestNewKeysCarryNoForbiddenSubstring(t *testing.T) {
	for _, k := range vaultKeys {
		for _, p := range forbiddenKeyParts {
			if strings.Contains(normKey(k), p) {
				t.Errorf("key %q contains forbidden substring %q", k, p)
			}
		}
	}
}

func TestExitcodeStillPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal(`Allow("exitcode") did not panic: "code" is a forbidden substring`)
		}
	}()
	Allow("exitcode")
}

// A key naming key material is dropped by the allowlist whether or not anyone called Allow: Allow
// guards the registration, the allowlist guards the emission, and a caller that never registers
// still cannot log one.
func TestForbiddenKeyIsDroppedEvenWithoutAllow(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x",
		"kek", "leakkek", "dek", "leakdek", "wrapNonce", "leakwrap", "dpapiBlob", "leakblob",
		"passphrase", "leakpass", "nonce", "leaknonce")
	out := buf.String()
	for _, leak := range []string{"leakkek", "leakdek", "leakwrap", "leakblob", "leakpass", "leaknonce"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
	m := logLine(t, &buf)
	for _, k := range []string{"kek", "dek", "wrapNonce", "dpapiBlob", "passphrase", "nonce"} {
		if m[k] != "[dropped]" {
			t.Errorf("%s = %v, want [dropped]: %s", k, m[k], out)
		}
	}
}

// "path" is deliberately not an allowlisted key. A path is logged under `datadir` (or `statedir`
// in slice 8) after TildePath has taken the profile prefix off it; a general-purpose `path` would
// be the one key through which a credentials file's location, and with it a username, slips out.
func TestNoPathKeyExists(t *testing.T) {
	if isAllowed("path") {
		t.Fatal(`"path" is allowlisted: a path is logged as datadir, through TildePath`)
	}
}

func TestTildePathReplacesTheProfilePrefix(t *testing.T) {
	home := `C:\Users\swapper`
	env := "USERPROFILE"
	sep := `\`
	if runtime.GOOS != "windows" {
		home, env, sep = "/home/swapper", "HOME", "/"
	}
	t.Setenv(env, home)
	cases := []struct{ in, want string }{
		{home + sep + "AppData" + sep + "claude-swap", "~" + sep + "AppData" + sep + "claude-swap"},
		{home, "~"},
		{home + sep, "~" + sep},
		{"/var/lib/claude-swap/data", "/var/lib/claude-swap/data"},
		// A sibling whose name merely starts with the home's name keeps its own path.
		{home + "2" + sep + "data", home + "2" + sep + "data"},
		{"", ""},
	}
	for _, c := range cases {
		if got := TildePath(c.in); got != c.want {
			t.Errorf("TildePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if strings.Contains(TildePath(home+sep+"AppData"), "swapper") {
		t.Fatalf("TildePath left the username in the path")
	}
}

func TestAllowRejectsSecretNames(t *testing.T) {
	bad := []string{"accessToken", "clientSecret", "passWord", "passwd", "apiKey", "set_cookie", "sessionId",
		"Authorization", "authHeader", "userEmail", "oauthCode", "credentials", "bearer", "block", "",
		"kek", "dek", "wrapNonce", "dpapiBlob", "passphrase", "vaultKek", "slotNonce"}
	for _, k := range bad {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Allow(%q) did not panic", k)
				}
			}()
			Allow(k)
		}()
	}

	Allow("requestId") // safe: an opaque correlation id
	var buf bytes.Buffer
	New(&buf).Info("x", "requestId", "req-1", "sid", "nope1")
	m := logLine(t, &buf)
	if m["requestId"] != "req-1" || m["sid"] != "[dropped]" {
		t.Fatalf("Allow did not take effect: %s", buf.String())
	}
	Allow("code") // already allowed: no-op, no panic
}

func TestGroupedSecretDropped(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x", slog.Group("task", "token", "grp1", "host", "grp2"), slog.Group("creds", "pw", "grp3"))
	l.WithGroup("task").Info("y", "host", "grp4", "count", 5)
	l.WithGroup("task").With("host", "grp5").Info("z")
	out := buf.String()
	for _, leak := range []string{"grp1", "grp2", "grp3", "grp4", "grp5"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if !strings.Contains(first, `"task":"[dropped]"`) || !strings.Contains(first, `"creds":"[dropped]"`) {
		t.Fatalf("group not dropped as a whole: %s", first)
	}
}

func TestRedactURLUserinfoPEMAndVendorTokens(t *testing.T) {
	cases := map[string][]string{
		"dial https://alice:pass123@example.com/x ok": {"pass123", "alice"},
		"git remote ssh://u:s3cret@h:22/r":            {"s3cret"},
		"cert -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAfakebody\nmore\n-----END RSA PRIVATE KEY----- after": {"fakebody", "more"},
		"-----BEGIN PRIVATE KEY-----\nunterminatedbody":                                                             {"unterminatedbody"},
		"gh ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 pat github_pat_11ABCDEFG0123456789abcdefghij":                  {"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "11ABCDEFG0123456789"},
		"aws AKIAIOSFODNN7EXAMPLE and ASIAIOSFODNN7EXAMPLE":                                                         {"IOSFODNN7EXAMPLE"},
		"slack xoxb-1234567890-abcdefghij":                                                                          {"1234567890"},
	}
	for in, leaks := range cases {
		out := Redact(in)
		for _, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Errorf("Redact(%q) leaked %q: %s", in, leak, out)
			}
		}
	}
	if out := Redact("dial https://alice:pass123@example.com/x ok"); !strings.HasSuffix(out, "@example.com/x ok") || !strings.Contains(out, "https://") {
		t.Fatalf("over-masked: %s", out)
	}
	if out := Redact("cert -----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY----- after"); !strings.HasSuffix(out, " after") || !strings.HasPrefix(out, "cert ") {
		t.Fatalf("over-masked: %s", out)
	}
}
