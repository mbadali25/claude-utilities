package logx

import (
	"bytes"
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
