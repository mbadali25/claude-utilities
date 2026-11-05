package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReplaceBlockSwapsOnlyTheBlockAndKeepsABackup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	v.Put(acct("b"))
	old, _ := v.Get("a")
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 5, 1, 2, 3, 0, time.UTC)

	if err := v.ReplaceBlock("a", json.RawMessage(`{"accessToken":"NEW"}`), at); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Get("a")
	if string(got.Block) != `{"accessToken":"NEW"}` || !got.Updated.Equal(at) {
		t.Fatalf("block %q updated %v", got.Block, got.Updated)
	}
	if got.Label != old.Label || got.Identity != old.Identity || got.ID != old.ID {
		t.Fatalf("label/identity/id changed: %+v vs %+v", got, old)
	}
	if b, _ := v.Get("b"); !bytes.Equal(b.Block, acct("b").Block) {
		t.Fatal("another account changed")
	}
	bak, err := os.ReadFile(p + bakSuffix)
	if err != nil || !bytes.Equal(bak, before) {
		t.Fatalf("backup is not the previous vault bytes (err %v)", err)
	}
	v2, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := v2.Get("a"); string(a.Block) != `{"accessToken":"NEW"}` {
		t.Fatal("replacement did not persist")
	}
}

func TestReplaceBlockUnknownIDWritesNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	if err := v.ReplaceBlock("zz", json.RawMessage(`{}`), time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(p + bakSuffix); !os.IsNotExist(err) {
		t.Fatal("a refused replace wrote a backup")
	}
}

func TestReplaceBlockFailedWriteKeepsOldBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	old, _ := v.Get("a")
	failRenameExceptBackup(t)
	if err := v.ReplaceBlock("a", json.RawMessage(`{"x":1}`), time.Now()); err == nil {
		t.Fatal("expected a write error")
	}
	if got, _ := v.Get("a"); !bytes.Equal(got.Block, old.Block) {
		t.Fatal("a failed write changed the in-memory login")
	}
}

func TestReplaceBlockRejectsEmptyBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	if err := v.ReplaceBlock("a", nil, time.Now()); err == nil {
		t.Fatal("an empty block must be refused")
	}
}
