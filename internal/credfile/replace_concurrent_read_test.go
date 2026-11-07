package credfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestReplaceSucceedsWhileAnotherProcessReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".credentials.json")
	mk := func(s string) json.RawMessage {
		return json.RawMessage(`{"accessToken":"` + s + `","refreshToken":"r","expiresAt":1,"refreshTokenExpiresAt":99999999999999,"scopes":["a"],"subscriptionType":"x","subscriptionTypeSource":"y","rateLimitTier":"z"}`)
	}
	if err := os.WriteFile(path, []byte(`{"claudeAiOauth":`+string(mk("a"))+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_, _ = ReadBlock(path)
		}
	}()
	fails := 0
	var first error
	for i := 0; i < 100; i++ {
		if _, err := Replace(path, mk(string(rune('b'+i%20)))); err != nil {
			fails++
			if first == nil {
				first = err
			}
		}
	}
	stop.Store(true)
	wg.Wait()
	if fails > 0 {
		t.Fatalf("%d/100 replaces failed; first: %v", fails, first)
	}
}
