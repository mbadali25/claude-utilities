package logx

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// A bare code= with an OAuth-code-sized value is masked wherever it appears, while a short result
// code (exit code=1, status code=500) stays readable. The allowlisted "code" attribute follows
// the same rule so allowlisting it cannot leak a real authorization code.
func TestBareCodeValueMaskedOnlyWhenNotAShortResultCode(t *testing.T) {
	long := "4%2FP7q7W91a-oMsCeLvIaQm6bTrgtp7"
	for _, in := range []string{"code=" + long, "got code: " + long, `code="` + long + `"`} {
		if out := Redact(in); strings.Contains(out, long) || strings.Contains(out, "P7q7W91a") {
			t.Errorf("not masked: %q -> %q", in, out)
		}
	}
	if out := Redact("exit code=1 status code=500"); out != "exit code=1 status code=500" {
		t.Errorf("over-redacted: %q", out)
	}
	var buf bytes.Buffer
	New(&buf).Info("m", "code", long)
	if strings.Contains(buf.String(), "P7q7W91a") {
		t.Errorf("attr code leaked: %s", buf.String())
	}
	buf.Reset()
	New(&buf).Info("m", "code", "E42")
	if !strings.Contains(buf.String(), `"code":"E42"`) {
		t.Errorf("short result code lost: %s", buf.String())
	}
}

func TestRedactCamelCaseAndNestedJSON(t *testing.T) {
	cases := []string{
		`{"accessToken":"abc123secret"}`,
		`{"refreshToken":"zzz999secret"}`,
		`{"block":{"claudeAiOauth":{"accessToken":"abc123secret","refreshToken":"zzz999secret","scopes":["a"]}}}`,
		`{"claudeAiOauth":{"accessToken":"abc123secret","refreshToken":"zzz999secret"}}`,
		`{"cred":"abc123secret","pw":"zzz999secret"}`,
		`{"a":{"b":{"password":{"x":"abc123secret","y":["zzz999secret"]}}}}`,
		`{"s":"with } brace","token":{"v":"abc123\"secret}zzz999secret"}}`,
		`accessToken=abc123secret refreshToken: zzz999secret`,
		`wrapped: {\"accessToken\":\"abc123secret\",\"n\":{\"refreshToken\":\"zzz999secret\"}}`,
	}
	for _, in := range cases {
		out := Redact(in)
		for _, leak := range []string{"abc123", "zzz999"} {
			if strings.Contains(out, leak) {
				t.Errorf("Redact(%s) leaked %q: %s", in, leak, out)
			}
		}
	}
}

func TestRedactKeepsSurroundingJSONValid(t *testing.T) {
	out := Redact(`{"keep":1,"accessToken":{"a":[1,2]},"also":"ok"}`)
	if out != `{"keep":1,"accessToken":"[redacted]","also":"ok"}` {
		t.Fatalf("got %s", out)
	}
}

func TestRedactQuotedValuesWithSpaces(t *testing.T) {
	for _, in := range []string{`token: "abc def"`, `password = 'hunter two'`, `secret="a b c"`} {
		out := Redact(in)
		for _, leak := range []string{"abc", "def", "hunter", "two", "a b"} {
			if strings.Contains(out, leak) {
				t.Errorf("Redact(%q) leaked %q: %s", in, leak, out)
			}
		}
	}
}

func TestRedactDoesNotMaskCounters(t *testing.T) {
	in := `tokenCount=5 maxTokens=100 secretsCount: 3`
	if out := Redact(in); out != in {
		t.Fatalf("over-redacted: %s", out)
	}
	// Attribute keys are allowlisted, so counters that merely look secret are dropped, never masked as secrets.
	var buf bytes.Buffer
	New(&buf).Info("x", "tokenCount", 5, "maxTokens", 100, "count", 7)
	if out := buf.String(); strings.Contains(out, "redacted") || !strings.Contains(out, `"tokenCount":"[dropped]"`) || !strings.Contains(out, `"count":7`) {
		t.Fatalf("unexpected attrs: %s", out)
	}
}

func TestLoggerRedactsSecretNamedGroupChildren(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x", slog.Group("credentials", "foo", "bar-visible"))
	l.WithGroup("token").Info("y", "foo", "baz-visible")
	out := buf.String()
	if strings.Contains(out, "visible") {
		t.Fatalf("group children leaked: %s", out)
	}
}

func TestLoggerRedactsMapKeysAndNestedErrors(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x", "whatever", map[string]string{"cred": "SECRETVAL", "pw": "SECRETVAL2"})
	l.Error("y", "err", errors.New(`bad body {"a":{"accessToken":"SECRETVAL3"}}`))
	if strings.Contains(buf.String(), "SECRETVAL") {
		t.Fatalf("leaked: %s", buf.String())
	}
}
