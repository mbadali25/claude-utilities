package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const keyEnv = "VAULT_TEST_KEY"
const secret = "sk-ant-SECRETTOKENVALUE123"

func open(t *testing.T, path, key string) (*Vault, error) {
	t.Helper()
	t.Setenv(keyEnv, key)
	return Open(path, EnvKey(keyEnv))
}

func acct(id string) Account {
	return Account{ID: id, Label: "L" + id, Identity: "ident-" + id,
		Block: json.RawMessage(`{"accessToken":"` + secret + `"}`), Updated: time.Unix(1700000000, 0).UTC()}
}

func TestPutGetRoundTripAcrossReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatal(err)
	}
	v2, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := v2.Get("a")
	if !ok || got.Label != "La" || got.Identity != "ident-a" || !bytes.Contains(got.Block, []byte(secret)) || !got.Updated.Equal(acct("a").Updated) {
		t.Fatalf("round trip mismatch: %+v ok=%v", got, ok)
	}
	if _, ok := v2.Get("zzz"); ok {
		t.Fatal("unknown id found")
	}
}

func TestFileIsNotPlaintext(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	if err := v.Put(acct("a")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, s := range []string{secret, "ident-a", "accessToken"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("plaintext %q found in file", s)
		}
	}
}

func TestWrongKeyReturnsErrBadKeyAndDoesNotOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "right")
	if err := v.Put(acct("a")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	if _, err := open(t, p, "wrong"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("file changed after failed open")
	}
}

func TestMissingEnvReturnsErrNoKeyWithHint(t *testing.T) {
	t.Setenv(keyEnv, "")
	_, err := Open(filepath.Join(t.TempDir(), "v.bin"), EnvKey(keyEnv))
	if !errors.Is(err, ErrNoKey) || !strings.Contains(err.Error(), keyEnv) {
		t.Fatalf("want ErrNoKey naming %s, got %v", keyEnv, err)
	}
}

func TestTamperedFileFailsAuth(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	for _, idx := range []int{len(magic) + 1, headerLen + 1, -1} { // salt, nonce, ciphertext tail
		b, _ := os.ReadFile(p)
		i := idx
		if i < 0 {
			i = len(b) - 1
		}
		b[i] ^= 0xff
		os.WriteFile(p, b, 0o600)
		if _, err := open(t, p, "pw"); !errors.Is(err, ErrBadKey) {
			t.Fatalf("tamper at %d: want ErrBadKey, got %v", i, err)
		}
		b[i] ^= 0xff
		os.WriteFile(p, b, 0o600)
	}
}

func TestGarbageFileIsRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	os.WriteFile(p, []byte("not a vault at all, just text"), 0o600)
	if _, err := open(t, p, "pw"); err == nil {
		t.Fatal("expected error")
	}
	os.WriteFile(p, []byte("CSV1"), 0o600)
	if _, err := open(t, p, "pw"); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	before, _ := os.ReadFile(p)
	renameFn = func(a, b string) error { return errors.New("boom") }
	t.Cleanup(func() { renameFn = os.Rename })
	if err := v.Put(acct("b")); err == nil {
		t.Fatal("expected put error")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("old file damaged")
	}
	if _, ok := v.Get("b"); ok {
		t.Fatal("failed put leaked into memory")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp file left behind: %d entries", len(ents))
	}
}

func TestFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

func TestBadMagicWithValidLengthIsRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	b, _ := os.ReadFile(p)
	copy(b, "XXXX")
	os.WriteFile(p, b, 0o600)
	if _, err := open(t, p, "pw"); !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
}

func TestBlockIsDeepCopied(t *testing.T) {
	v, _ := open(t, filepath.Join(t.TempDir(), "v.bin"), "pw")
	in := acct("a")
	v.Put(in)
	in.Block[0] = 'X' // caller mutates its input after Put
	g, _ := v.Get("a")
	g.Block[0] = 'Y'
	v.List()[0].Block[0] = 'Z'
	g2, _ := v.Get("a")
	if g2.Block[0] != '{' {
		t.Fatalf("store aliased caller memory: %q", g2.Block[0])
	}
}

func TestFailedDeleteRollsBack(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	renameFn = func(a, b string) error { return errors.New("boom") }
	t.Cleanup(func() { renameFn = os.Rename })
	if err := v.Delete("a"); err == nil {
		t.Fatal("expected delete error")
	}
	if _, ok := v.Get("a"); !ok {
		t.Fatal("failed delete not rolled back")
	}
}

func TestEmptyVaultListsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.List()) != 0 || len(v.ListPublic()) != 0 {
		t.Fatal("expected empty")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("Open must not create the file")
	}
	// zero-byte file is treated as empty
	os.WriteFile(p, nil, 0o600)
	if _, err := open(t, p, "pw"); err != nil {
		t.Fatal(err)
	}
}

func TestListPublicStripsBlock(t *testing.T) {
	v, _ := open(t, filepath.Join(t.TempDir(), "v.bin"), "pw")
	v.Put(acct("b"))
	v.Put(acct("a"))
	pub := v.ListPublic()
	if len(pub) != 2 || pub[0].ID != "a" || pub[1].ID != "b" {
		t.Fatalf("order/len: %+v", pub)
	}
	for _, a := range pub {
		if a.Block != nil {
			t.Fatal("Block leaked")
		}
	}
	if l := v.List(); !bytes.Contains(l[0].Block, []byte(secret)) {
		t.Fatal("List must keep Block")
	}
	if g, _ := v.Get("a"); g.Block == nil {
		t.Fatal("ListPublic mutated store")
	}
}

func TestDeleteAndPutValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	if err := v.Put(Account{}); err == nil {
		t.Fatal("empty id accepted")
	}
	v.Put(acct("a"))
	if err := v.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting an unknown id: %v, want ErrNotFound", err)
	}
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	v2, _ := open(t, p, "pw")
	if len(v2.List()) != 0 {
		t.Fatal("delete not persisted")
	}
}

func TestPutReplacesAndUsesFreshNonce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	v.Put(acct("a"))
	b1, _ := os.ReadFile(p)
	v.Put(acct("a"))
	b2, _ := os.ReadFile(p)
	if bytes.Equal(b1[headerLen:headerLen+nonceLen], b2[headerLen:headerLen+nonceLen]) {
		t.Fatal("nonce reused")
	}
	if len(v.List()) != 1 {
		t.Fatal("duplicate id")
	}
}

func TestConcurrentPutSafe(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := v.Put(acct(fmt.Sprintf("a%02d", i))); err != nil {
				t.Error(err)
			}
			v.Get("a00")
			v.ListPublic()
		}(i)
	}
	wg.Wait()
	v2, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(v2.List()); n != 16 {
		t.Fatalf("want 16 accounts, got %d", n)
	}
}

func TestRelabelHappyPersistsAndKeepsBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	v, _ := open(t, p, "pw")
	a := acct("a")
	_ = v.Put(a)
	_ = v.Put(acct("b"))
	if err := v.Relabel("a", "  Renamed ünï 日本  "); err != nil {
		t.Fatal(err)
	}
	v2, err := open(t, p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := v2.Get("a")
	if got.Label != "Renamed ünï 日本" || got.Identity != a.Identity || got.Updated != a.Updated || string(got.Block) != string(a.Block) {
		t.Fatalf("after relabel: %+v", got)
	}
}

func TestRelabelValidation(t *testing.T) {
	v, _ := open(t, filepath.Join(t.TempDir(), "v.bin"), "pw")
	_ = v.Put(acct("a"))
	_ = v.Put(Account{ID: "b", Label: "Taken"})
	cases := map[string]struct {
		id, label string
		want      error
	}{
		"empty":      {"a", "", ErrLabelInvalid},
		"whitespace": {"a", " \t ", ErrLabelInvalid},
		"too long":   {"a", strings.Repeat("x", MaxLabel+1), ErrLabelInvalid},
		"duplicate":  {"a", "taken", ErrLabelTaken},
		"dup padded": {"a", "  TAKEN ", ErrLabelTaken},
		"unknown id": {"zz", "fresh", ErrNotFound},
	}
	for name, c := range cases {
		if err := v.Relabel(c.id, c.label); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
	}
	if g, _ := v.Get("a"); g.Label != "La" {
		t.Fatalf("label changed by a rejected rename: %q", g.Label)
	}
	if err := v.Relabel("a", strings.Repeat("x", MaxLabel)); err != nil {
		t.Fatalf("64-byte label rejected: %v", err)
	}
}

func TestRelabelSameAccountMayChangeCase(t *testing.T) {
	v, _ := open(t, filepath.Join(t.TempDir(), "v.bin"), "pw")
	_ = v.Put(Account{ID: "a", Label: "main"})
	if err := v.Relabel("a", "MAIN"); err != nil {
		t.Fatal(err)
	}
}

func TestFailedRelabelRollsBack(t *testing.T) {
	v, _ := open(t, filepath.Join(t.TempDir(), "v.bin"), "pw")
	_ = v.Put(acct("a"))
	renameFn = func(a, b string) error { return errors.New("boom") }
	t.Cleanup(func() { renameFn = os.Rename })
	if err := v.Relabel("a", "new"); err == nil {
		t.Fatal("expected write error")
	}
	if g, _ := v.Get("a"); g.Label != "La" {
		t.Fatalf("failed relabel not rolled back: %q", g.Label)
	}
}

func TestConcurrentRelabelToSameLabelHasOneWinner(t *testing.T) {
	v, _ := open(t, filepath.Join(t.TempDir(), "v.bin"), "pw")
	const n = 8
	for i := 0; i < n; i++ {
		_ = v.Put(Account{ID: fmt.Sprintf("a%d", i), Label: fmt.Sprintf("old%d", i)})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, taken := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := v.Relabel(fmt.Sprintf("a%d", i), "Same")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrLabelTaken):
				taken++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || taken != n-1 {
		t.Fatalf("wins %d taken %d", wins, taken)
	}
}
