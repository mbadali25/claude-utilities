package proto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const (
	plantURL      = "https://claude.com/cai/oauth/authorize?state=PLANTED-STATE"
	plantCode     = "PLANTED-CODE-123456789"
	plantBlock    = "PLANTED-BLOCK-TOKEN"
	plantIdentity = "planted.person@example.com"
)

func TestLoginTypesMaskSecrets(t *testing.T) {
	vals := map[string]any{
		"url":  LoginURL{URL: plantURL},
		"code": LoginCode{Code: plantCode},
		"done": LoginDone{Block: json.RawMessage(`{"accessToken":"` + plantBlock + `"}`), Identity: plantIdentity, Err: "failed for " + plantIdentity},
	}
	for name, v := range vals {
		var buf bytes.Buffer
		lg := slog.New(slog.NewJSONHandler(&buf, nil))
		lg.Info("x", "v", v)
		for _, out := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v), buf.String()} {
			for _, secret := range []string{plantURL, "PLANTED-STATE", plantCode, plantBlock, plantIdentity} {
				if strings.Contains(out, secret) {
					t.Fatalf("%s leaks %q in %q", name, secret, out)
				}
			}
		}
	}
}

func TestLoginDoneRoundTrip(t *testing.T) {
	in := LoginDone{Block: json.RawMessage(`{"a":1}`), Identity: "id"}
	b, err := Encode(TypeLoginDone, "job1", in)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Decode(b)
	if err != nil || env.Type != TypeLoginDone || env.ID != "job1" {
		t.Fatalf("env %+v err %v", env, err)
	}
	var out LoginDone
	if err := json.Unmarshal(env.Body, &out); err != nil {
		t.Fatal(err)
	}
	if string(out.Block) != `{"a":1}` || out.Identity != "id" || out.Err != "" {
		t.Fatalf("out %+v", out)
	}
}

func TestValidateLoginURL(t *testing.T) {
	good := []string{
		"https://claude.com/cai/oauth/authorize?code=true&state=s",
		"https://claude.ai/oauth/authorize?x=1",
		"https://claude.com/oauth/authorize",
	}
	for _, u := range good {
		if err := ValidateLoginURL(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	bad := map[string]string{
		"evil host":       "https://evil.example/cai/oauth/authorize",
		"subdomain trick": "https://claude.com.evil.example/oauth/authorize",
		"userinfo":        "https://claude.com@evil.example/oauth/authorize",
		"http":            "http://claude.com/oauth/authorize",
		"wrong path":      "https://claude.com/login",
		"port":            "https://claude.com:8443/oauth/authorize",
		"too long":        "https://claude.com/oauth/authorize?" + strings.Repeat("a", MaxLoginURL),
		"control byte":    "https://claude.com/oauth/authorize?a=\x01",
		"empty":           "",
		"space":           "https://claude.com/oauth/authorize?a=b c",
	}
	for name, u := range bad {
		if err := ValidateLoginURL(u); err == nil {
			t.Errorf("%s: %q accepted", name, u)
		}
	}
}
