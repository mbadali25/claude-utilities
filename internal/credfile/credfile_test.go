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
	t.Cleanup(func() { renameFn = os.Rename })
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
	t.Cleanup(func() { renameFn = os.Rename })
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
	old := oauth("old", 1)
	p := write(t, t.TempDir(), fileWith(old))
	backup, err := Replace(p, json.RawMessage(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(p, backup); err != nil {
		t.Fatal(err)
	}
	b, _ := ReadBlock(p)
	if string(b) != old {
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
	t.Cleanup(func() { beforeRenameFn = func() {} })
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
	t.Cleanup(func() { nowFn = time.Now })
	a, err1 := Replace(p, json.RawMessage(`{"n":1}`))
	b, err2 := Replace(p, json.RawMessage(`{"n":2}`))
	if err1 != nil || err2 != nil || a == b {
		t.Fatalf("%v %v %q %q", err1, err2, a, b)
	}
}

func TestStaleLockIsReclaimed(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"o":1}`))
	if err := os.WriteFile(p+lockSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleLockAge)
	if err := os.Chtimes(p+lockSuffix, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatalf("stale lock not reclaimed: %v", err)
	}
	if _, err := os.Stat(p + lockSuffix); err == nil {
		t.Fatal("lock left behind")
	}
}

func TestNewestBackupSurvivesPruneWithFrozenClock(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"o":1}`))
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return fixed }
	t.Cleanup(func() { nowFn = time.Now })
	for i := 0; i < 14; i++ {
		b, err := Replace(p, json.RawMessage(`{"n":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, serr := os.Stat(b); serr != nil {
			t.Fatalf("iteration %d: returned backup %s was pruned", i, b)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(dir, backupDir))
	if len(ents) != backupKeep {
		t.Fatalf("backups = %d", len(ents))
	}
}

func TestReadBlockNullIsNoBlock(t *testing.T) {
	p := write(t, t.TempDir(), `{"claudeAiOauth": null}`)
	if _, err := ReadBlock(p); !errors.Is(err, ErrNoBlock) {
		t.Fatalf("err = %v", err)
	}
}

func TestReplaceRejectsNonObjectBlock(t *testing.T) {
	orig := fileWith(`{}`)
	p := write(t, t.TempDir(), orig)
	for _, b := range []string{`123`, `[]`, `null`, `"s"`, `true`} {
		if _, err := Replace(p, json.RawMessage(b)); err == nil {
			t.Fatalf("block %s accepted", b)
		}
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
}

func TestRestoreRejectsNonObjectBackup(t *testing.T) {
	dir := t.TempDir()
	orig := fileWith(`{}`)
	p := write(t, dir, orig)
	bdir := filepath.Join(dir, backupDir)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{`5`, `[1]`, `"x"`} {
		b := filepath.Join(bdir, "bad.json")
		os.WriteFile(b, []byte(c), 0o600)
		if err := Restore(p, b); err == nil {
			t.Fatalf("backup %s accepted", c)
		}
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
}

func TestRestoreRejectsPathOutsideBackupDir(t *testing.T) {
	dir := t.TempDir()
	orig := fileWith(`{}`)
	p := write(t, dir, orig)
	outside := filepath.Join(dir, "evil.json")
	os.WriteFile(outside, []byte(`{"x":1}`), 0o600)
	if err := Restore(p, outside); err == nil {
		t.Fatal("outside path accepted")
	}
	trav := filepath.Join(dir, backupDir, "..", "evil.json")
	if err := Restore(p, trav); err == nil {
		t.Fatal("traversal path accepted")
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
}

func TestReplaceTightensLooseMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes not meaningful on Windows")
	}
	p := write(t, t.TempDir(), fileWith(`{}`))
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Replace(p, json.RawMessage(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

func TestChangedDuringSwapLeavesNoOrphanBackup(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"o":1}`))
	beforeRenameFn = func() { os.WriteFile(p, []byte(fileWith(`{"z":1}`)), 0o600) }
	t.Cleanup(func() { beforeRenameFn = func() {} })
	b, err := Replace(p, json.RawMessage(`{"n":1}`))
	if !errors.Is(err, ErrChangedDuringSwap) {
		t.Fatalf("err = %v", err)
	}
	if b != "" {
		t.Fatalf("backup path returned for aborted swap: %s", b)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, backupDir))
	if len(ents) != 0 {
		t.Fatalf("orphan backups: %d", len(ents))
	}
}

func TestReplaceFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.MkdirAll(real, 0o700)
	target := write(t, real, fileWith(`{"o":1}`))
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Replace(link, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v", err)
	}
	b, _ := ReadBlock(target)
	if string(b) != `{"n":1}` {
		t.Fatalf("target block = %s", b)
	}
}

func TestReplaceMissingDirErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nodir", ".credentials.json")
	_, err := Replace(p, json.RawMessage(`{"n":1}`))
	if err == nil || !strings.Contains(err.Error(), "credfile: lock") {
		t.Fatalf("err = %v", err)
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

func TestBackupWrittenBeforeTempFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"o":1}`))
	called := false
	afterBackupFn = func(string) {
		called = true
		tmps, _ := filepath.Glob(filepath.Join(dir, ".credentials-*.tmp"))
		if len(tmps) != 0 {
			t.Errorf("temp file exists before backup completed: %v", tmps)
		}
	}
	t.Cleanup(func() { afterBackupFn = func(string) {} })
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("afterBackupFn not called")
	}
}

func TestValidateBlockRejectsNullRequiredValue(t *testing.T) {
	future := time.Now().Add(time.Hour).UnixMilli()
	m := map[string]any{}
	_ = json.Unmarshal([]byte(oauth("x", future)), &m)
	m["accessToken"] = nil
	b, _ := json.Marshal(m)
	if err := ValidateBlock(b); err == nil {
		t.Fatal("null accessToken accepted")
	}
}

func TestValidateBlockAcceptsFloatExpiry(t *testing.T) {
	future := float64(time.Now().Add(time.Hour).UnixMilli())
	m := map[string]any{}
	_ = json.Unmarshal([]byte(oauth("x", 1)), &m)
	m["refreshTokenExpiresAt"] = future
	b, _ := json.Marshal(m)
	if err := ValidateBlock(b); err != nil {
		t.Fatalf("float expiry rejected: %v", err)
	}
	exp := strings.Replace(oauth("x", 1), `"refreshTokenExpiresAt":1`, `"refreshTokenExpiresAt":4.1e12`, 1)
	if err := ValidateBlock(json.RawMessage(exp)); err != nil {
		t.Fatalf("4.1e12 rejected: %v", err)
	}
}

func TestRestoreRejectsBadShapeBackup(t *testing.T) {
	dir := t.TempDir()
	orig := fileWith(oauth("live", 1))
	p := write(t, dir, orig)
	bdir := filepath.Join(dir, backupDir)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{`{}`, `{"accessToken":"a"}`} {
		b := filepath.Join(bdir, "bad.json")
		os.WriteFile(b, []byte(c), 0o600)
		if err := Restore(p, b); err == nil {
			t.Fatalf("backup %s accepted", c)
		}
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
}

func TestRestoreRejectsSymlinkBackup(t *testing.T) {
	dir := t.TempDir()
	orig := fileWith(oauth("live", 1))
	p := write(t, dir, orig)
	bdir := filepath.Join(dir, backupDir)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	os.WriteFile(target, []byte(oauth("evil", 1)), 0o600)
	link := filepath.Join(bdir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Restore(p, link); err == nil {
		t.Fatal("symlink backup accepted")
	}
	if data, _ := os.ReadFile(p); string(data) != orig {
		t.Fatal("file changed")
	}
}

func TestBackupDirTightenedTo0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes not meaningful on Windows")
	}
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"o":1}`))
	bdir := filepath.Join(dir, backupDir)
	if err := os.MkdirAll(bdir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(bdir, 0o755)
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(bdir)
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
}

func TestReplaceDanglingSymlinkErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".credentials.json")
	if err := os.Symlink(filepath.Join(dir, "missing.json"), p); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err == nil {
		t.Fatal("dangling symlink accepted")
	}
	if st, err := os.Lstat(p); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced")
	}
}

func TestMalformedErrorDoesNotEchoContent(t *testing.T) {
	p := write(t, t.TempDir(), `{"claudeAiOauth": SECRETXYZ}`)
	_, err := ReadBlock(p)
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "'S'") {
		t.Fatalf("err = %v", err)
	}
}

func TestReplaceKeepsHTMLKeyBytes(t *testing.T) {
	p := write(t, t.TempDir(), `{"a<b&c>":1,"claudeAiOauth":{"o":1}}`)
	if _, err := Replace(p, json.RawMessage(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), `"a<b&c>":1`) {
		t.Fatalf("key rewritten: %s", data)
	}
}

func TestReleaseKeepsForeignLock(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"o":1}`))
	release, err := acquire(p)
	if err != nil {
		t.Fatal(err)
	}
	// Another process reclaimed the lock: content now carries a different owner.
	if err := os.WriteFile(p+lockSuffix, []byte("other-owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Stat(p + lockSuffix); err != nil {
		t.Fatal("release removed a lock it does not own")
	}
}

func TestStaleReclaimLeavesNoReclaimFile(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"o":1}`))
	os.WriteFile(p+lockSuffix, []byte("dead"), 0o600)
	old := time.Now().Add(-2 * staleLockAge)
	os.Chtimes(p+lockSuffix, old, old)
	release, err := acquire(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + lockSuffix + reclaimSuffix); err == nil {
		t.Fatal("reclaim guard left behind")
	}
	release()
	if _, err := os.Stat(p + lockSuffix); err == nil {
		t.Fatal("own lock not released")
	}
}

func TestReclaimGuardHeldReturnsBusy(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"o":1}`))
	os.WriteFile(p+lockSuffix, []byte("dead"), 0o600)
	old := time.Now().Add(-2 * staleLockAge)
	os.Chtimes(p+lockSuffix, old, old)
	os.WriteFile(p+lockSuffix+reclaimSuffix, nil, 0o600) // another reclaimer is active
	if _, err := acquire(p); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v", err)
	}
}
