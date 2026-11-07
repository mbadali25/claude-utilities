package usage

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// maxErrBody bounds how much of a 401/403 answer is read for classification.
const maxErrBody = 4 << 10

// Body classes: a small fixed set chosen here, the only thing derived from an error body that is
// ever logged. Never the body, a message, a token or an identity.
const (
	classNoBody      = "no_body"
	classUnparseable = "unparseable"
	classExpired     = "token_expired"
	classRevoked     = "token_revoked"
	classPermission  = "permission"
	classInvalid     = "invalid_credentials"
	classOther       = "other"
)

// classifyBody maps an error body to a class. The markers below are ASSUMPTIONS about Anthropic's
// error wording (no live sample was available): case-insensitive substrings of the usual error
// fields only (error.type, error.message, error / error_description / message / type / code as
// strings). Text elsewhere in the body is ignored, so an echoed token or email cannot steer it.
// First match wins in this order: expired, revoked, permission, invalid; anything else is other.
func classifyBody(b []byte) string {
	if len(strings.TrimSpace(string(b))) == 0 {
		return classNoBody
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil || top == nil {
		return classUnparseable
	}
	var parts []string
	add := func(raw json.RawMessage) {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			parts = append(parts, s)
		}
	}
	for _, k := range []string{"error_description", "message", "type", "code"} {
		if v, ok := top[k]; ok {
			add(v)
		}
	}
	if e, ok := top["error"]; ok {
		add(e)
		var inner map[string]json.RawMessage
		if json.Unmarshal(e, &inner) == nil {
			for _, k := range []string{"type", "message", "code"} {
				if v, ok := inner[k]; ok {
					add(v)
				}
			}
		}
	}
	text := strings.ToLower(strings.Join(parts, " "))
	switch {
	case strings.Contains(text, "expired"):
		return classExpired
	case strings.Contains(text, "revoked"):
		return classRevoked
	case strings.Contains(text, "permission"), strings.Contains(text, "forbidden"):
		return classPermission
	case strings.Contains(text, "invalid"), strings.Contains(text, "authentication_error"), strings.Contains(text, "unauthorized"):
		return classInvalid
	}
	return classOther
}

// readErrClass reads at most maxErrBody bytes of body and classifies them.
func readErrClass(body io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(body, maxErrBody))
	if err != nil && len(b) == 0 {
		return classNoBody
	}
	return classifyBody(b)
}

// BodyClass is the class of the 401/403 body behind a failed fetch, or "" when there was none
// to classify (other statuses, transport failures, a refresher failure).
func BodyClass(err error) string {
	var se *StatusError
	if errors.As(err, &se) {
		return se.BodyClass
	}
	return ""
}
