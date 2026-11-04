package proto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
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
	rt := reflect.TypeOf(SwapRes{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if strings.Contains(strings.ToLower(f.Name+f.Tag.Get("json")), "block") {
			t.Fatalf("SwapRes has credential-like field %s", f.Name)
		}
	}
}

func TestDecodeRejectsEmptyType(t *testing.T) {
	if _, err := Decode([]byte(`{"v":1}`)); err == nil {
		t.Fatal("expected error for empty type")
	}
}

func TestEncodeUnmarshalableBody(t *testing.T) {
	if _, err := Encode(TypeReport, "", make(chan int)); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeBodyNullAndNonObject(t *testing.T) {
	env, err := Decode([]byte(`{"v":1,"type":"report","body":null}`))
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(env.Body, &r); err != nil {
		t.Fatalf("null body should unmarshal as zero: %v", err)
	}
	env, err = Decode([]byte(`{"v":1,"type":"report","body":"str"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env.Body, &r); err == nil {
		t.Fatal("non-object body must fail typed unmarshal")
	}
}

func TestReportNilSessionsMarshalsEmptyArray(t *testing.T) {
	b, err := json.Marshal(Report{HostID: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"sessions":[]`) {
		t.Fatalf("want empty array: %s", b)
	}
}

func TestCredentialTypesDoNotLeakWhenLogged(t *testing.T) {
	block := json.RawMessage(`{"tok":"blocksecret"}`)
	vals := []any{
		Hello{Token: "hellosecret", HostName: "box1"},
		&Hello{Token: "hellosecret", HostName: "box1"},
		SwapReq{Block: block, Account: "acct"},
		ExportRes{Block: block, Identity: "id", Err: "failed Bearer errsecret"},
	}
	for _, v := range vals {
		for _, s := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
			for _, leak := range []string{"hellosecret", "blocksecret", "errsecret"} {
				if strings.Contains(s, leak) {
					t.Fatalf("%T leaked %q: %s", v, leak, s)
				}
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
		for _, leak := range []string{"hellosecret", "blocksecret", "errsecret"} {
			if strings.Contains(buf.String(), leak) {
				t.Fatalf("%T leaked %q via slog: %s", v, leak, buf.String())
			}
		}
	}
}
