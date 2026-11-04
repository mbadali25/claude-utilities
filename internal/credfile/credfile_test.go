package credfile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const mcp = `{ "srv" : {"a": 1,  "b":[1, 2]} }`

func oauth(tag string, refreshExp int64) string {
	b, _ := json.Marshal(map[string]any{
		"accessToken": "at-" + tag, "refreshToken": "rt-" + tag, "expiresAt": 1,
		"refreshTokenExpiresAt": refreshExp, "scopes": []string{"user:inference"},
		"subscriptionType": "max", "subscriptionTypeSource": "x", "rateLimitTier": "t",
	})
	return string(b)
}

func write(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, ".credentials.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fileWith(old string) string {
	return `{"claudeAiOauth": ` + old + `, "mcpOAuth": ` + mcp + `}`
}

func TestReplaceKeepsMcpOAuthByteIdentical(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"x":1}`))
	if _, err := Replace(p, json.RawMessage(oauth("new", 1))); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), `"mcpOAuth":`+mcp) {
		t.Fatalf("mcpOAuth changed: %s", data)
	}
	b, err := ReadBlock(p)
	if err != nil || !strings.Contains(string(b), "at-new") {
		t.Fatalf("block not replaced: %v", err)
	}
}

func TestReplaceCreatesBackupFirst(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"old":true}`))
	renameFn = func(a, b string) error { return errors.New("boom") }
	defer func() { renameFn = os.Rename }()
	backup, err := Replace(p, json.RawMessage(oauth("n", 1)))
	if err == nil || backup == "" {
		t.Fatalf("want error with backup, got %q %v", backup, err)
	}
	data, _ := os.ReadFile(backup)
	if string(data) != `{"old":true}` {
		t.Fatalf("backup = %s", data)
	}
}

func TestReplaceKeepsMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes not meaningful on Windows")
	}
	p := write(t, t.TempDir(), fileWith(`{}`))
	backup, err := Replace(p, json.RawMessage(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, backup} {
		st, _ := os.Stat(f)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, st.Mode().Perm())
		}
	}
}

func TestReplaceFailureLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	orig := fileWith(`{"old":true}`)
	p := write(t, dir, orig)
	renameFn = func(a, b string) error { return errors.New("boom") }
	defer func() { renameFn = os.Rename }()
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err == nil {
		t.Fatal("want error")
	}
	data, _ := os.ReadFile(p)
	if string(data) != orig {
		t.Fatalf("original changed: %s", data)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.HasSuffix(e.Name(), lockSuffix) {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestRestoreRecoversPreviousBlock(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"old":true}`))
	backup, err := Replace(p, json.RawMessage(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(p, backup); err != nil {
		t.Fatal(err)
	}
	b, _ := ReadBlock(p)
	if string(b) != `{"old":true}` {
		t.Fatalf("block = %s", b)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), mcp) {
		t.Fatal("mcpOAuth lost")
	}
}

func TestRestoreWhenNoPreviousBlockRemovesKey(t *testing.T) {
	p := write(t, t.TempDir(), `{"mcpOAuth":`+mcp+`}`)
	backup, err := Replace(p, json.RawMessage(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(p, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBlock(p); !errors.Is(err, ErrNoBlock) {
		t.Fatalf("err = %v", err)
	}
}

func TestReplaceEmptyFile(t *testing.T) {
	p := write(t, t.TempDir(), "")
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBlock(p)
	if err != nil || string(b) != `{"n":1}` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestReplaceMissingFileCreatesIt(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".credentials.json")
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBlock(p); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceMalformedJSONRefusesAndKeepsFile(t *testing.T) {
	bad := `{"claudeAiOauth": {`
	p := write(t, t.TempDir(), bad)
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err == nil {
		t.Fatal("want error")
	}
	data, _ := os.ReadFile(p)
	if string(data) != bad {
		t.Fatal("file changed")
	}
}

func TestReplaceRejectsInvalidNewBlock(t *testing.T) {
	orig := fileWith(`{}`)
	p := write(t, t.TempDir(), orig)
	if _, err := Replace(p, json.RawMessage(`{nope`)); err == nil {
		t.Fatal("want error")
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
}

func TestReplaceMissingMcpOAuth(t *testing.T) {
	p := write(t, t.TempDir(), `{"claudeAiOauth":{"o":1}}`)
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), "mcpOAuth") {
		t.Fatalf("invented mcpOAuth: %s", data)
	}
}

func TestReplaceUnicodePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "用户 émoji ✓")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := write(t, dir, fileWith(`{"o":1}`))
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceConcurrentReturnsErrBusy(t *testing.T) {
	orig := fileWith(`{"o":1}`)
	p := write(t, t.TempDir(), orig)
	if err := os.WriteFile(p+lockSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v", err)
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
	if _, err := os.Stat(p + lockSuffix); err != nil {
		t.Fatal("foreign lock must not be removed")
	}
}

func TestReplaceAbortsIfFileChangedDuringSwap(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"o":1}`))
	other := fileWith(`{"claude":"refreshed"}`)
	beforeRenameFn = func() { os.WriteFile(p, []byte(other), 0o600) }
	defer func() { beforeRenameFn = func() {} }()
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); !errors.Is(err, ErrChangedDuringSwap) {
		t.Fatalf("err = %v", err)
	}
	if data, _ := os.ReadFile(p); string(data) != other {
		t.Fatal("concurrent write was clobbered")
	}
}

func TestBackupsPrunedToFive(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"o":1}`))
	for i := 0; i < 8; i++ {
		if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(dir, backupDir))
	if len(ents) != 5 {
		t.Fatalf("backups = %d", len(ents))
	}
}

func TestBackupNamesUniqueWithFrozenClock(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"o":1}`))
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return fixed }
	defer func() { nowFn = time.Now }()
	a, err1 := Replace(p, json.RawMessage(`{"n":1}`))
	b, err2 := Replace(p, json.RawMessage(`{"n":2}`))
	if err1 != nil || err2 != nil || a == b {
		t.Fatalf("%v %v %q %q", err1, err2, a, b)
	}
}

func TestValidateBlockRejectsExpiredRefresh(t *testing.T) {
	past := time.Now().Add(-time.Hour).UnixMilli()
	if err := ValidateBlock(json.RawMessage(oauth("x", past))); !errors.Is(err, ErrRefreshExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateBlock(t *testing.T) {
	future := time.Now().Add(time.Hour).UnixMilli()
	if err := ValidateBlock(json.RawMessage(oauth("x", future))); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBlock(json.RawMessage(`{"accessToken":"a"}`)); err == nil {
		t.Fatal("want missing keys error")
	}
	if err := ValidateBlock(json.RawMessage(`[1]`)); err == nil {
		t.Fatal("want error for non-object")
	}
	m := map[string]any{}
	_ = json.Unmarshal([]byte(oauth("x", future)), &m)
	m["refreshTokenExpiresAt"] = "soon"
	b, _ := json.Marshal(m)
	if err := ValidateBlock(b); err == nil {
		t.Fatal("want non-number error")
	}
}

func TestReadBlockNoBlock(t *testing.T) {
	p := write(t, t.TempDir(), `{"mcpOAuth":{}}`)
	if _, err := ReadBlock(p); !errors.Is(err, ErrNoBlock) {
		t.Fatalf("err = %v", err)
	}
}

func TestResolvePath(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join("x", "cfg"))
	p, err := ResolvePath()
	if err != nil || p != filepath.Join("x", "cfg", ".credentials.json") {
		t.Fatalf("%q %v", p, err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	p, err = ResolvePath()
	if err != nil || !strings.HasSuffix(p, filepath.Join(".claude", ".credentials.json")) {
		t.Fatalf("%q %v", p, err)
	}
}
