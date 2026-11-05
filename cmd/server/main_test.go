package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestListenRequiredRefusesStartWithoutFlag(t *testing.T) {
	var out bytes.Buffer
	full := map[string]string{keyEnv: "k", passwordEnv: "p"}
	if code := run(context.Background(), nil, env(full), &out); code == 0 || !strings.Contains(out.String(), "--listen") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func TestMissingSecretsRefuseStart(t *testing.T) {
	for _, m := range []map[string]string{{passwordEnv: "p"}, {keyEnv: "k"}} {
		var out bytes.Buffer
		code := run(context.Background(), []string{"--listen", "127.0.0.1:0", "--data-dir", t.TempDir()}, env(m), &out)
		if code == 0 || !strings.Contains(out.String(), "CLAUDESWAP_") {
			t.Fatalf("env %v: code %d out %q", m, code, out.String())
		}
	}
}

func TestBadListenAddressRefused(t *testing.T) {
	var out bytes.Buffer
	args := []string{"--listen", "nonsense", "--data-dir", t.TempDir()}
	if code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "p"}), &out); code == 0 {
		t.Fatalf("accepted %q", out.String())
	}
}
