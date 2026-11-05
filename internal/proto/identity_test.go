package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKnownIdentityReason(t *testing.T) {
	for _, c := range []string{ReasonNoClaudeJSON, ReasonNoOAuthAccount, ReasonUnreadable,
		ReasonConfigDirElsewhere, ReasonHomeMismatch, ReasonParseError, ReasonNoCredentials} {
		if !KnownIdentityReason(c) {
			t.Errorf("KnownIdentityReason(%q) = false, want true", c)
		}
	}
	for _, c := range []string{"", "nope", "/home/matthew/.claude.json", "a@example.test", "NO_CLAUDE_JSON"} {
		if KnownIdentityReason(c) {
			t.Errorf("KnownIdentityReason(%q) = true, want false", c)
		}
	}
}

// A code must stay a code: no separators that could smuggle a path, an address or a token.
func TestIdentityReasonCodesAreOpaque(t *testing.T) {
	for _, c := range []string{ReasonNoClaudeJSON, ReasonNoOAuthAccount, ReasonUnreadable,
		ReasonConfigDirElsewhere, ReasonHomeMismatch, ReasonParseError, ReasonNoCredentials} {
		if strings.ContainsAny(c, `@/\:. `) || c != strings.ToLower(c) || len(c) > 32 {
			t.Errorf("code %q is not a plain lowercase code", c)
		}
	}
}

// The field is additive: an older agent that sends no reason still decodes, and a report that
// carries one round-trips.
func TestReportIdentityReasonAdditive(t *testing.T) {
	var old Report
	if err := json.Unmarshal([]byte(`{"hostId":"h1","activeIdentity":"a","credsPresent":true}`), &old); err != nil {
		t.Fatalf("decode old report: %v", err)
	}
	if old.IdentityReason != "" {
		t.Errorf("IdentityReason = %q, want empty", old.IdentityReason)
	}
	raw, err := json.Marshal(Report{HostID: "h1", IdentityReason: ReasonNoClaudeJSON})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(string(raw), `"identityReason":"no_claude_json"`) {
		t.Errorf("encoded report = %s", raw)
	}
	if raw2, err := json.Marshal(Report{HostID: "h1"}); err != nil || strings.Contains(string(raw2), "identityReason") {
		t.Errorf("empty reason must be omitted: %s (%v)", raw2, err)
	}
}
