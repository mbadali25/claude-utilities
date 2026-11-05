// Package logx provides a JSON logger that emits only allowlisted attribute keys and redacts
// secret-looking substrings from the free text it does emit.
//
// Attribute keys are an ALLOWLIST (see allowed): a key not on the list is written as
// "[dropped]" so a reader sees that a field was withheld, never its value. String values of
// allowlisted keys, and the message, still pass through Redact and are capped at
// maxValueBytes. Under an allowlisted key only primitive kinds (string, int, uint, float,
// bool, duration, time) are written; groups, structs, maps, errors and Any values are dropped
// as a whole. Attributes nested under a group are always dropped.
//
// logx must never import proto: proto imports logx, so the reverse is an import cycle.
package logx

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	redacted = "[redacted]"
	dropped  = "[dropped]"
	// maxValueBytes caps every emitted string (message included) so a leak that slips past
	// Redact is bounded and a log line cannot carry a whole credential file.
	maxValueBytes = 256
	truncMark     = "...[truncated]"
)

// allowed holds normalised (lowercase, no "_" or "-") attribute keys whose values may be
// written. Every key names an operational fact, never a credential, identity or payload.
// "account" is an opaque account label (never an email); "code" is a small result code.
var allowed = map[string]bool{
	"time": true, "level": true, "msg": true, "component": true, "host": true, "hostid": true,
	"agent": true, "task": true, "taskid": true, "account": true, "result": true, "reason": true,
	"code": true, "action": true, "event": true, "attempt": true, "count": true, "durationms": true,
	"status": true, "statuscode": true, "pid": true, "sessioncount": true, "version": true,
	"err": true, "error": true,
}

var allowedMu sync.RWMutex

// forbiddenKeyParts are substrings a key registered via Allow may never contain.
var forbiddenKeyParts = []string{
	"token", "secret", "password", "passwd", "pwd", "key", "cookie", "session", "authorization",
	"auth", "email", "credential", "cred", "bearer", "block", "code", "identity", "refresh",
}

// Allow registers extra attribute keys to be emitted. Call it at init time only. A key must
// never carry a secret, an email or a payload; Allow panics on an empty key or on one that
// contains an obvious secret word (token, secret, password, key, cookie, session,
// authorization, email, credential, code, ...). Keys already allowed are accepted unchanged.
func Allow(keys ...string) {
	allowedMu.Lock()
	defer allowedMu.Unlock()
	for _, k := range keys {
		n := normKey(k)
		if allowed[n] {
			continue
		}
		if n == "" {
			panic("logx.Allow: empty key")
		}
		for _, p := range forbiddenKeyParts {
			if strings.Contains(n, p) {
				panic("logx.Allow: key " + k + " looks secret-bearing (" + p + ")")
			}
		}
		allowed[n] = true
	}
}

func isAllowed(k string) bool {
	allowedMu.RLock()
	defer allowedMu.RUnlock()
	return allowed[normKey(k)]
}

// Err returns a string attribute "err" holding the redacted, capped error text, or "" for nil.
// Error values themselves are dropped by the logger (an error may wrap a struct or body that
// carries a secret), so this is the one way to log one.
func Err(err error) slog.Attr {
	if err == nil {
		return slog.String("err", "")
	}
	return slog.String("err", clean(safe(err.Error)))
}

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
	// pemRe masks a whole PEM block, or from an unterminated BEGIN line to the end of the text.
	pemRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|\z)`)
	// userinfoRe masks the user:password part of a URL (https://u:pass@host).
	userinfoRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@`)
	// vendorRe masks tokens with a vendor prefix: GitHub (ghp_/gho_/ghu_/ghs_/ghr_, github_pat_),
	// AWS access key ids (AKIA/ASIA), Slack (xox?-), GitLab (glpat-).
	vendorRe = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bglpat-[A-Za-z0-9_-]{20,}`)
	bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|sk-ant-[A-Za-z0-9_-]+`)
	jwtRe    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	authRe   = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*)(?:(?:basic|bearer|digest|token)\s+)?[^\s"',;]+`)
	// kvRe finds name=value and name: value pairs (any name, camelCase included); kvSecret
	// decides which are masked. A bare "code" is masked only when its value is longer than
	// maxResultCode: "exit code=1" stays readable, an OAuth code does not. Quoted values are masked
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

// Redact masks PEM blocks, URL userinfo, vendor-prefixed tokens, bearer-token-looking
// substrings, JWTs, emails, and token-like key/value pairs (free text, JSON, escaped JSON).
func Redact(s string) string {
	s = pemRe.ReplaceAllString(s, redacted)
	s = userinfoRe.ReplaceAllString(s, "${1}"+redacted+"@")
	s = vendorRe.ReplaceAllString(s, redacted)
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
		if normKey(p[1]) == "code" && !shortResultCode(p[3]) {
			return p[1] + p[2] + redacted
		}
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

// maxResultCode is the longest value a bare "code" may carry and still read as a result code
// (1, 500, E42); anything longer looks like an OAuth authorization code and is masked.
const maxResultCode = 8

func shortResultCode(v string) bool {
	return len(strings.Trim(v, `"'`)) <= maxResultCode
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

// clean redacts free text and caps it at maxValueBytes on a rune boundary.
func clean(s string) string {
	s = Redact(s)
	if len(s) <= maxValueBytes {
		return s
	}
	n := maxValueBytes - len(truncMark)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + truncMark
}

// handler sanitises every attribute before the JSON handler sees it. Doing this in a wrapper
// rather than ReplaceAttr lets a group be dropped as one value instead of leaf by leaf.
type handler struct {
	inner slog.Handler
	// grouped is set once WithGroup has been called: every later attribute is nested, so dropped.
	grouped bool
}

// New returns a JSON logger that writes only allowlisted attribute keys (others appear as
// "[dropped]"), redacts and caps the strings it does write, and drops non-primitive values.
func New(w io.Writer) *slog.Logger {
	return slog.New(&handler{inner: slog.NewJSONHandler(w, nil)})
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, clean(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.sanitize(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, h.sanitize(a))
	}
	return &handler{inner: h.inner.WithAttrs(out), grouped: h.grouped}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{inner: h.inner.WithGroup(name), grouped: true}
}

// sanitize returns the attribute as it may be written: dropped when nested or not allowlisted,
// cleaned when a string, as-is for other primitive kinds, dropped for everything else.
func (h *handler) sanitize(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()                         // LogValuer is resolved here, with slog's own panic recovery
	if a.Key == "" && v.Kind() == slog.KindGroup { // an inlined group: its children are top-level
		g := v.Group()
		out := make([]slog.Attr, 0, len(g))
		for _, c := range g {
			out = append(out, h.sanitize(c))
		}
		return slog.Attr{Value: slog.GroupValue(out...)}
	}
	if h.grouped || !isAllowed(a.Key) {
		return slog.String(a.Key, dropped)
	}
	switch v.Kind() {
	case slog.KindString:
		if normKey(a.Key) == "code" && !shortResultCode(v.String()) {
			return slog.String(a.Key, redacted) // "code" is allowlisted for result codes only
		}
		return slog.String(a.Key, clean(v.String()))
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool, slog.KindDuration, slog.KindTime:
		return slog.Attr{Key: a.Key, Value: v}
	}
	return slog.String(a.Key, dropped)
}
