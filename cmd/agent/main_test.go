package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/websocket"

	"claude-utilities/internal/agent"
	"claude-utilities/internal/install"
	"claude-utilities/internal/proto"
)

func run(t *testing.T, ctx context.Context, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := dispatch(ctx, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(install.StateDirEnv, filepath.Join(dir, "state"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(dir, "claude"))
	t.Setenv(codeEnv, "")
	return dir
}

func TestUsageAndUnknownCommandExit1(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}} {
		code, _, errOut := run(t, context.Background(), args...)
		if code != 1 || !strings.Contains(errOut, "usage: agent") {
			t.Fatalf("%v: code %d %q", args, code, errOut)
		}
	}
}

func TestEnrolArgumentErrorsExit1(t *testing.T) {
	isolate(t)
	pin := strings.Repeat("a", 64)
	for _, args := range [][]string{
		{"enrol"},
		{"enrol", "--server", "https://x"},
		{"enrol", "--server", "https://x", "--pin", "zz"},
		{"enrol", "--server", "https://x", "--pin", pin, "--code", "SECRET-CODE"}, // codes never travel on argv
		{"enrol", "--server", "http://x", "--pin", pin},
		{"enrol", "--server", "https://user:hunter2@127.0.0.1:1", "--pin", pin},
	} {
		code, _, errOut := run(t, context.Background(), args...)
		if code != 1 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if strings.Contains(errOut, "hunter2") {
			t.Fatalf("%v: password printed: %q", args, errOut)
		}
	}
}

func TestEnrolDeniedExits2AndReadsCodeFromEnv(t *testing.T) {
	isolate(t)
	t.Setenv(codeEnv, "ENV-CODE-123")
	gotCode := make(chan string, 1)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		_, data, err := ws.Read(r.Context())
		if err != nil {
			return
		}
		env, _ := proto.Decode(data)
		var h proto.Hello
		_ = json.Unmarshal(env.Body, &h)
		gotCode <- h.Code
		b, _ := proto.Encode(proto.TypeDenied, "", proto.Denied{Reason: "nope"})
		_ = ws.Write(r.Context(), websocket.MessageText, b)
		_, _, _ = ws.Read(r.Context())
	}))
	ts.StartTLS()
	defer ts.Close()
	sum := sha256.Sum256(ts.Certificate().Raw)

	code, out, errOut := run(t, context.Background(), "enrol", "--server", ts.URL, "--pin", hex.EncodeToString(sum[:]))
	if code != 2 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errOut)
	}
	if c := <-gotCode; c != "ENV-CODE-123" {
		t.Fatalf("hello code %q", c)
	}
	if !strings.Contains(errOut, "denied") {
		t.Fatalf("stderr: %q", errOut)
	}
}

func TestRunWithoutConfigExits1(t *testing.T) {
	isolate(t)
	code, _, errOut := run(t, context.Background(), "run")
	if code != 1 || !strings.HasPrefix(errOut, "run:") {
		t.Fatalf("code %d %q", code, errOut)
	}
}

func TestRunCancelledExits0(t *testing.T) {
	dir := isolate(t)
	state := filepath.Join(dir, "state")
	cfg := agent.Config{ServerURL: "https://127.0.0.1:1", Token: "tok-x", Pin: strings.Repeat("a", 64),
		CredsPath: filepath.Join(dir, "claude", ".credentials.json"), StateDir: state}
	if err := agent.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, _, errOut := run(t, ctx, "run"); code != 0 {
		t.Fatalf("code %d %q", code, errOut)
	}
}

func TestRunRedactsErrors(t *testing.T) {
	dir := isolate(t)
	cfg := agent.Config{ServerURL: "https://user:hunter2@127.0.0.1:1", Token: "tok-x", Pin: strings.Repeat("a", 64),
		CredsPath: filepath.Join(dir, "claude", ".credentials.json"), StateDir: filepath.Join(dir, "state")}
	if err := agent.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, context.Background(), "run")
	if code != 1 || strings.Contains(errOut, "hunter2") {
		t.Fatalf("code %d %q", code, errOut)
	}
}
