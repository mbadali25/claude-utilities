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
	"bearer": true, "refresh": true, "cred": true, "pw": true, "pwd": true, "pass": true,
}

// benignSuffixes mark counters and limits (tokenCount, maxTokens) that merely contain a secret word.
var benignSuffixes = []string{"count", "len", "length", "limit"}

// secretKeyParts are substrings of a normalised key that mark it secret.
var secretKeyParts = []string{
	"token", "secret", "password", "passwd", "credential", "apikey", "privatekey", "sessionkey",
}

var (
	bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|sk-ant-[A-Za-z0-9_-]+`)
	jwtRe    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	authRe   = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)(?:(?:basic|bearer|digest|token)\s+)?[^\s"',;]+`)
	// kvRe finds name=value and name: value pairs (any name, camelCase included); kvSecret
	// decides which are masked. A bare "code" is never masked here: it collides with benign
	// text such as "exit code=1"; OAuth codes are caught by codeRe. Quoted values are masked
	// whole; an unquoted value is masked up to the next whitespace or delimiter only, so
	// "password = hunter2 extra words" leaves "extra words" visible.
	kvRe   = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9_-]*)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^&\s"',;]+)`)
	codeRe = regexp.MustCompile(`(?i)([?&]code=)[^&\s"']+`)
	// jsonMemberRe / escJSONMemberRe find `"key":` in plain JSON and in JSON that was
	// backslash-escaped inside another string. redactJSON masks the whole value (string,
	// nested object or array, number) of every secret-named key.
	jsonMemberRe    = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*`)
	escJSONMemberRe = regexp.MustCompile(`\\"([A-Za-z0-9_.-]*)\\"\s*:\s*`)
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
	for _, b := range benignSuffixes {
		if strings.HasSuffix(n, b) || strings.HasPrefix(n, "max") {
			return false
		}
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
	s = kvRe.ReplaceAllStringFunc(s, func(m string) string {
		p := kvRe.FindStringSubmatch(m)
		if !kvSecret(p[1]) {
			return m
		}
		return p[1] + p[2] + redacted
	})
	s = codeRe.ReplaceAllString(s, "${1}"+redacted)
	s = redactJSON(s, jsonMemberRe, `"`)
	s = redactJSON(s, escJSONMemberRe, `\"`)
	s = emailRe.ReplaceAllString(s, redacted)
	return s
}

// kvSecret reports whether a free-text name=value key is secret. Bare exact names such as
// "code" or "key" are left alone in free text (see kvRe); keys containing a secret word match.
func kvSecret(k string) bool {
	switch normKey(k) {
	case "code", "key", "email", "auth", "block", "bearer", "refresh":
		return false
	}
	return secretKey(k)
}

// redactJSON replaces the whole value of every secret-named member found by memberRe.
// quote is the string delimiter in this encoding (`"` or `\"`).
func redactJSON(s string, memberRe *regexp.Regexp, quote string) string {
	var b strings.Builder
	last := 0
	for _, m := range memberRe.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < last { // inside a value that is already masked
			continue
		}
		if !secretKey(s[m[2]:m[3]]) {
			continue
		}
		end := jsonValueEnd(s, m[1], quote)
		b.WriteString(s[last:m[1]])
		b.WriteString(quote + redacted + quote)
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// jsonValueEnd returns the index just past the JSON value starting at i. On malformed input it
// returns len(s), masking to the end (the safe side).
func jsonValueEnd(s string, i int, quote string) int {
	if i >= len(s) {
		return len(s)
	}
	skipString := func(j int) int { // s[j:] starts with quote; return index past the closing quote
		j += len(quote)
		for j < len(s) {
			switch {
			case quote == `"` && s[j] == '\\' && j+1 < len(s):
				j += 2
			case quote == `\"` && strings.HasPrefix(s[j:], `\\`):
				j += 2
			case strings.HasPrefix(s[j:], quote):
				return j + len(quote)
			default:
				j++
			}
		}
		return len(s)
	}
	if strings.HasPrefix(s[i:], quote) {
		return skipString(i)
	}
	switch s[i] {
	case '{', '[':
		depth := 0
		for j := i; j < len(s); {
			if strings.HasPrefix(s[j:], quote) {
				j = skipString(j)
				continue
			}
			switch s[j] {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
			j++
		}
		return len(s)
	}
	j := i
	for j < len(s) && !strings.ContainsRune(",}] \t\r\n\\", rune(s[j])) {
		j++
	}
	return j
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
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if secretKey(a.Key) {
				return slog.String(a.Key, redacted)
			}
			for _, g := range groups { // children of a secret-named group are secret
				if secretKey(g) {
					return slog.String(a.Key, redacted)
				}
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
