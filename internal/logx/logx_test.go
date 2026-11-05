package logx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerRedactsSecretAttrs(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x", "accessToken", "sk-ant-oat01-abc", "refreshToken", "rrr-secret", "token", "ttt-secret",
		"oauthCode", "ccc-secret", "key", "kkk-secret", "password", "ppp-secret", "email", "me@example.com", "host", "box1", "code", "E42")
	out := buf.String()
	for _, leak := range []string{"abc", "rrr-secret", "ttt-secret", "ccc-secret", "kkk-secret", "ppp-secret", "me@example.com"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %s", leak, out)
		}
	}
	if !strings.Contains(out, "[dropped]") || !strings.Contains(out, "box1") || !strings.Contains(out, `"code":"E42"`) {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestLoggerRedactsNestedGroupAttr(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).With("g", "1").WithGroup("grp").Info("x", "password", "hunter2")
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("leaked: %s", buf.String())
	}
}

func TestLoggerRedactsErrorAndStringer(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Error("x", Err(fmt.Errorf("auth failed: Bearer abc123tok")), "s", stringer("sk-ant-oat01-zzz"), "count", 5,
		"reason", stringer("sk-ant-oat01-yyy"))
	out := buf.String()
	if strings.Contains(out, "abc123tok") || strings.Contains(out, "zzz") || strings.Contains(out, "yyy") {
		t.Fatalf("leaked: %s", out)
	}
	if !strings.Contains(out, `"err":"auth failed: Bearer [redacted]"`) || !strings.Contains(out, `"count":5`) {
		t.Fatalf("over-redacted: %s", out)
	}
	if Err(nil).Value.String() != "" || Err(nil).Key != "err" {
		t.Fatalf("Err(nil) = %v", Err(nil))
	}
}

type stringer string

func (s stringer) String() string { return string(s) }

func TestLoggerRedactsMessageAndMixedCaseGroupKey(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("got Bearer msgtoken1", slog.Group("g", "PassWord", "hunter2", "Access_Token", "at-secret"))
	out := buf.String()
	for _, leak := range []string{"msgtoken1", "hunter2", "at-secret"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
}

func TestLoggerRedactsKeyVariants(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x", "access_token", "v1", "api_key", "v2", "Authorization", "v3", "secret", "v4",
		"client_secret", "v5", "cookie", "v6", "credentials", "v7", "block", "v8", "apikey", "v9", "refresh_token", "v10")
	out := buf.String()
	for _, v := range []string{"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10"} {
		if strings.Contains(out, `"`+v+`"`) {
			t.Fatalf("leaked %s: %s", v, out)
		}
	}
}

func TestRedactExtraFormats(t *testing.T) {
	in := `GET /cb?code=abc123&token=def456&x=1 {"access_token":"ghi789"} eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigpart_1 end`
	out := Redact(in)
	for _, leak := range []string{"abc123", "def456", "ghi789", "eyJhbGci", "sigpart"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "x=1") || !strings.Contains(out, "end") {
		t.Fatalf("over-masked: %s", out)
	}
}

func TestRedactMasksBearer(t *testing.T) {
	in := "auth: Bearer abc123.def-456 and sk-ant-oat01-zzz9 done"
	out := Redact(in)
	if strings.Contains(out, "abc123") || strings.Contains(out, "zzz9") {
		t.Fatalf("not masked: %s", out)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("over-masked: %s", out)
	}
	if Redact("") != "" || Redact("plain text") != "plain text" {
		t.Fatal("should leave benign text alone")
	}
}

type nilStringer struct{ s string }

func (n *nilStringer) String() string { return n.s }

func TestLoggerNilStringerDoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	var p *nilStringer
	New(&buf).Info("x", "p", p)
	if buf.Len() == 0 {
		t.Fatal("log line dropped")
	}
}

func TestLoggerRedactsRawBytesMapsAndStructs(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	type wrap struct {
		Body json.RawMessage `json:"body"`
	}
	l.Info("x",
		"raw", json.RawMessage(`{"access_token":"rawsecret1"}`),
		"bytes", []byte(`token=bytesecret2`),
		"m", map[string]string{"auth": "Bearer mapsecret3", "block": "mapsecret4"},
		"w", wrap{Body: json.RawMessage(`{"block":{"a":"structsecret5"}}`)},
		"ptr", &wrap{Body: json.RawMessage(`{"password":"ptrsecret6"}`)},
		"ok", map[string]int{"n": 1})
	out := buf.String()
	for _, leak := range []string{"rawsecret1", "bytesecret2", "mapsecret3", "mapsecret4", "structsecret5", "ptrsecret6"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
}

func TestRedactEscapedJSONAndOtherForms(t *testing.T) {
	in := `err: {\"access_token\":\"esc1\",\"id_token\":\"esc2\"} token: colon3 Authorization: Basic basic4 refresh_token=r5 sessionKey=sess6 x=1`
	out := Redact(in)
	for _, leak := range []string{"esc1", "esc2", "colon3", "basic4", "r5", "sess6"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "x=1") {
		t.Fatalf("over-masked: %s", out)
	}
}

func TestRedactKeepsBenignCodeAndMasksOAuthCode(t *testing.T) {
	out := Redact("exit code=1 status code=500 GET /cb?state=s&code=oauthcode7")
	if !strings.Contains(out, "exit code=1") || !strings.Contains(out, "status code=500") {
		t.Fatalf("over-masked: %s", out)
	}
	if strings.Contains(out, "oauthcode7") {
		t.Fatalf("leaked: %s", out)
	}
}

func TestRedactEmail(t *testing.T) {
	if out := Redact("login failed for me@example.com now"); strings.Contains(out, "me@example.com") {
		t.Fatalf("leaked: %s", out)
	}
}

func TestLoggerRedactsKeyFamilies(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x", "authToken", "fam1", "idtoken", "fam2", "privateKey", "fam3", "sessionKey", "fam4",
		"creds", "fam5", "bearer", "fam6", "auth", "fam7", "hostToken", "fam8", "userPassword", "fam9", "status_code", 404)
	out := buf.String()
	for _, v := range []string{"fam1", "fam2", "fam3", "fam4", "fam5", "fam6", "fam7", "fam8", "fam9"} {
		if strings.Contains(out, v) {
			t.Fatalf("leaked %s: %s", v, out)
		}
	}
	if !strings.Contains(out, "404") {
		t.Fatalf("over-redacted status_code: %s", out)
	}
}
