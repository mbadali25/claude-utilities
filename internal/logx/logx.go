// Package logx provides a JSON logger that redacts secrets.
package logx

import (
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const redacted = "[redacted]"

var secretKeys = map[string]bool{
	"accesstoken": true, "refreshtoken": true, "token": true, "code": true,
	"key": true, "password": true, "email": true,
}

var bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|sk-ant-[A-Za-z0-9_-]+`)

// Redact masks bearer-token-looking substrings.
func Redact(s string) string {
	return bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) >= 6 && strings.EqualFold(m[:6], "bearer") {
			return m[:6] + " " + redacted
		}
		return redacted
	})
}

// New returns a JSON logger that redacts secret attributes and token-like strings.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if secretKeys[strings.ToLower(a.Key)] {
				return slog.String(a.Key, redacted)
			}
			if a.Value.Kind() == slog.KindString {
				return slog.String(a.Key, Redact(a.Value.String()))
			}
			return a
		},
	}))
}
