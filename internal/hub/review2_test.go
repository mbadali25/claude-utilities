package hub

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/proto"
)

func TestPendingConnectionKeepsHelloReadLimit(t *testing.T) {
	f := newFixture(t)
	a := f.dial("10.0.0.9", proto.Hello{HostName: "pend", OS: "linux", Nonce: "n-pend"})
	a.recv(proto.TypePending)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = a.ws.Write(ctx, websocket.MessageText, []byte(strings.Repeat("x", helloMaxSize+1024)))
	for {
		_, _, err := a.ws.Read(ctx)
		if err == nil {
			continue
		}
		if got := websocket.CloseStatus(err); got != websocket.StatusMessageTooBig {
			t.Fatalf("close status %d, want MessageTooBig: %v", got, err)
		}
		return
	}
}

func TestCorruptHostsBackupIsOwnerOnlyAndReplacesLooseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on Windows")
	}
	f := newFixture(t)
	bak := f.h.tokensPath + ".corrupt"
	if err := os.WriteFile(bak, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.h.tokensPath, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2 := &Hub{tokensPath: f.h.tokensPath, hosts: map[string]*host{}, byHash: map[string]string{}}
	if err := h2.load(); err == nil {
		t.Fatal("want parse error")
	}
	fi, err := os.Stat(bak)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", fi.Mode().Perm())
	}
}
