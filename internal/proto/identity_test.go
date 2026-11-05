package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidIdentityReason(t *testing.T) {
	if !ValidIdentityReason(ReasonNoHome) {
		t.Fatalf("%q should be valid", ReasonNoHome)
	}
	for _, bad := range []string{"", "NO_HOME", "no_home ", "<script>", "whatever"} {
		if ValidIdentityReason(bad) {
			t.Fatalf("%q should not be valid", bad)
		}
	}
}

// The field is additive: a report without it still decodes, and one with it
// round-trips.
func TestReportIdentityReasonRoundTrip(t *testing.T) {
	b, err := json.Marshal(Report{IdentityReason: ReasonNoHome})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"identityReason":"no_home"`) {
		t.Fatalf("not on the wire: %s", b)
	}
	var out Report
	if err := json.Unmarshal(b, &out); err != nil || out.IdentityReason != ReasonNoHome {
		t.Fatalf("round trip = %q (%v)", out.IdentityReason, err)
	}
	// Omitted when empty, so an older hub sees the report shape it expects.
	b, err = json.Marshal(Report{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "identityReason") {
		t.Fatalf("empty reason should be omitted: %s", b)
	}
	var old Report
	if err := json.Unmarshal([]byte(`{"hostId":"h1"}`), &old); err != nil || old.IdentityReason != "" {
		t.Fatalf("legacy report = %+v (%v)", old, err)
	}
}
