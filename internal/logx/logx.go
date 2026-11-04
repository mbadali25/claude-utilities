// Package logx provides a JSON logger that redacts secrets.
//
// logx must never import proto: proto imports logx, so the reverse is an import cycle.
package logx

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const redacted = "[redacted]"

// secretKeys holds normalised attribute keys (lowercase, no "_" or "-") matched exactly.
var secretKeys = map[string]bool{
	"code": true, "key": true, "email": true, "authorization": true, "auth": true,
	"cookie": true, "credentials": true, "creds": true, "block": true,
	"bearer": true, "refresh": true,
}

// secretKeyParts are substrings of a normalised key that mark it secret.
var secretKeyParts = []string{
	"token", "secret", "password", "passwd", "credential", "apikey", "privatekey", "sessionkey",
}

const keyNames = `access_token|refresh_token|id_token|token|api_key|apikey|password|passwd|secret|client_secret|session_key|sessionkey|authorization|cookie|credentials|block|key`

var (
	bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|sk-ant-[A-Za-z0-9_-]+`)
	jwtRe    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	authRe   = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)(?:(?:basic|bearer|digest|token)\s+)?[^\s"',;]+`)
	// kvRe masks name=value and name: value. A bare "code" is excluded: it collides with
	// benign text such as "exit code=1"; OAuth codes are caught by codeRe.
	kvRe   = regexp.MustCompile(`(?i)\b((?:access_token|refresh_token|id_token|token|api_key|apikey|password|passwd|secret|client_secret|session_key|sessionkey)\s*[:=]\s*)[^&\s"',;]+`)
	codeRe = regexp.MustCompile(`(?i)([?&]code=)[^&\s"']+`)
	// jsonKvRe masks plain JSON members: string, flat object, flat array, or number values.
	jsonKvRe = regexp.MustCompile(`(?i)("(?:` + keyNames + `)"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|\{[^{}]*\}|\[[^\[\]]*\]|-?\d[\w.+-]*)`)
	// escJSONKvRe masks JSON that was backslash-escaped inside another string.
	escJSONKvRe = regexp.MustCompile(`(?i)(\\"(?:` + keyNames + `)\\"\s*:\s*)\\"[^"\\]*\\"`)
)

func normKey(k string) string {
	k = strings.ToLower(k)
	return strings.NewReplacer("_", "", "-", "").Replace(k)
}

func secretKey(k string) bool {
	n := normKey(k)
	if secretKeys[n] {
		return true
	}
	for _, p := range secretKeyParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// Redact masks bearer-token-looking substrings, JWTs, emails, and token-like key/value pairs.
func Redact(s string) string {
	s = authRe.ReplaceAllString(s, "${1}"+redacted)
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) >= 6 && strings.EqualFold(m[:6], "bearer") {
			return m[:6] + " " + redacted
		}
		return redacted
	})
	s = jwtRe.ReplaceAllString(s, redacted)
	s = kvRe.ReplaceAllString(s, "${1}"+redacted)
	s = codeRe.ReplaceAllString(s, "${1}"+redacted)
	s = jsonKvRe.ReplaceAllString(s, `${1}"`+redacted+`"`)
	s = escJSONKvRe.ReplaceAllString(s, `${1}\"`+redacted+`\"`)
	s = emailRe.ReplaceAllString(s, redacted)
	return s
}

// safe runs f and returns a placeholder if it panics (e.g. a typed-nil receiver).
func safe(f func() string) (s string) {
	defer func() {
		if recover() != nil {
			s = "[unprintable]"
		}
	}()
	return f()
}

func redactAny(v any) string {
	switch t := v.(type) {
	case error:
		return Redact(safe(t.Error))
	case fmt.Stringer:
		return Redact(safe(t.String))
	case json.RawMessage:
		return Redact(string(t))
	case []byte:
		return Redact(string(t))
	}
	return Redact(safe(func() string {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}))
}

// New returns a JSON logger that redacts secret attributes and token-like strings.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if secretKey(a.Key) {
				return slog.String(a.Key, redacted)
			}
			switch a.Value.Kind() {
			case slog.KindString:
				return slog.String(a.Key, Redact(a.Value.String()))
			case slog.KindAny:
				if v := a.Value.Any(); v != nil {
					return slog.String(a.Key, redactAny(v))
				}
			}
			return a
		},
	}))
}
