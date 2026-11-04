package proto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Report{HostID: "h1", ActiveIdentity: "a", CredsPresent: true,
		Sessions: []Session{{PID: 7, ID: "s", Cwd: "/x", StartedAt: time.Unix(100, 0).UTC()}}}
	b, err := Encode(TypeReport, "id1", in)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if env.V != Version || env.Type != TypeReport || env.ID != "id1" {
		t.Fatalf("bad envelope: %+v", env)
	}
	var out Report
	if err := json.Unmarshal(env.Body, &out); err != nil {
		t.Fatal(err)
	}
	if out.HostID != "h1" || len(out.Sessions) != 1 || out.Sessions[0].PID != 7 || !out.Sessions[0].StartedAt.Equal(in.Sessions[0].StartedAt) {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestEncodeNilBody(t *testing.T) {
	b, err := Encode(TypeHeartbeat, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRejectsWrongVersion(t *testing.T) {
	for _, s := range []string{`{"v":2,"type":"hello"}`, `{"type":"hello"}`} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Fatalf("expected error for %s", s)
		}
	}
}

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	for _, s := range []string{``, `{`, `not json`} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

func TestSwapResNeverCarriesBlock(t *testing.T) {
	b, err := json.Marshal(SwapRes{OK: false, Reason: "denied"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "block") {
		t.Fatalf("SwapRes leaks block: %s", b)
	}
}
