package logx

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerRedactsSecretAttrs(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x", "accessToken", "sk-ant-oat01-abc", "refreshToken", "rrr-secret", "token", "ttt-secret",
		"code", "ccc-secret", "key", "kkk-secret", "password", "ppp-secret", "email", "me@example.com", "host", "box1")
	out := buf.String()
	for _, leak := range []string{"abc", "rrr-secret", "ttt-secret", "ccc-secret", "kkk-secret", "ppp-secret", "me@example.com"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %s", leak, out)
		}
	}
	if !strings.Contains(out, "[redacted]") || !strings.Contains(out, "box1") {
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
	l.Error("x", "err", fmt.Errorf("auth failed: Bearer abc123tok"), "s", stringer("sk-ant-oat01-zzz"), "n", 5)
	out := buf.String()
	if strings.Contains(out, "abc123tok") || strings.Contains(out, "zzz") {
		t.Fatalf("leaked: %s", out)
	}
	if !strings.Contains(out, "auth failed") || !strings.Contains(out, `"n":5`) {
		t.Fatalf("over-redacted: %s", out)
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
