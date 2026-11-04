// Package logx provides a JSON logger that redacts secrets.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const redacted = "[redacted]"

// secretKeys holds normalised attribute keys (lowercase, no "_" or "-").
var secretKeys = map[string]bool{
	"accesstoken": true, "refreshtoken": true, "token": true, "code": true,
	"key": true, "password": true, "email": true,
	"authorization": true, "apikey": true, "secret": true, "clientsecret": true,
	"cookie": true, "credentials": true, "block": true,
}

var (
	bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|sk-ant-[A-Za-z0-9_-]+`)
	jwtRe    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	kvRe     = regexp.MustCompile(`(?i)\b((?:access_token|refresh_token|token|code|api_key|apikey|password|secret|client_secret)=)[^&\s"']+`)
	jsonKvRe = regexp.MustCompile(`(?i)("(?:access_token|refresh_token|token|code|api_key|apikey|password|secret|client_secret)"\s*:\s*")[^"]*`)
)

func normKey(k string) string {
	k = strings.ToLower(k)
	return strings.NewReplacer("_", "", "-", "").Replace(k)
}

// Redact masks bearer-token-looking substrings, JWTs, and token-like key=value pairs.
func Redact(s string) string {
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) >= 6 && strings.EqualFold(m[:6], "bearer") {
			return m[:6] + " " + redacted
		}
		return redacted
	})
	s = jwtRe.ReplaceAllString(s, redacted)
	s = kvRe.ReplaceAllString(s, "${1}"+redacted)
	s = jsonKvRe.ReplaceAllString(s, "${1}"+redacted)
	return s
}

// New returns a JSON logger that redacts secret attributes and token-like strings.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if secretKeys[normKey(a.Key)] {
				return slog.String(a.Key, redacted)
			}
			switch a.Value.Kind() {
			case slog.KindString:
				return slog.String(a.Key, Redact(a.Value.String()))
			case slog.KindAny:
				switch v := a.Value.Any().(type) {
				case error:
					return slog.String(a.Key, Redact(v.Error()))
				case fmt.Stringer:
					return slog.String(a.Key, Redact(v.String()))
				}
			}
			return a
		},
	}))
}
