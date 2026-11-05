package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

// pend dials a tokenless agent and waits until the server lists it.
func (f *fixture) pend(ip, name, nonce string) (*agent, string) {
	f.t.Helper()
	hello := proto.Hello{HostName: name, OS: "linux", Nonce: nonce}
	a := f.dial(ip, hello)
	var p proto.Pending
	if err := json.Unmarshal(a.recv(proto.TypePending).Body, &p); err != nil {
		f.t.Fatal(err)
	}
	if p.Fingerprint != proto.Fingerprint(hello) {
		f.t.Fatalf("fingerprint %q != %q", p.Fingerprint, proto.Fingerprint(hello))
	}
	return a, p.Fingerprint
}

func TestTokenlessHelloIsListedPendingWithFingerprint(t *testing.T) {
	f := newFixture(t)
	a, fp := f.pend("10.1.1.1", "box", "n1")
	got := f.h.Pending()
	if len(got) != 1 {
		t.Fatalf("pending: %+v", got)
	}
	p := got[0]
	if p.Fingerprint != fp || p.HostName != "box" || p.OS != "linux" || p.SourceIP != "10.1.1.1" ||
		!p.Since.Equal(f.clk.Now()) || !p.ExpiresAt.Equal(f.clk.Now().Add(PendingTTL)) {
		t.Fatalf("view: %+v", p)
	}
	if _, err := a.recvWithin(150 * time.Millisecond); err == nil {
		t.Fatal("agent received something besides Pending")
	}
	if types := a.types(); len(types) != 1 || types[0] != proto.TypePending {
		t.Fatalf("types: %v", types)
	}
}

func TestPendingQueueCapIs20(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < PendingCap; i++ {
		f.pend(fmt.Sprintf("10.2.0.%d", i), "box", fmt.Sprintf("n%d", i))
	}
	over := f.dial("10.2.9.9", proto.Hello{HostName: "box", OS: "linux", Nonce: "extra"})
	over.expectClosed("queue full")
	f.waitRejected(ErrPendingFull)
	if n := len(f.h.Pending()); n != PendingCap {
		t.Fatalf("queue length %d", n)
	}
}

func TestPendingPerIPLimit3Per10Min(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < PendingPerIP; i++ {
		f.pend("10.3.0.1", "box", fmt.Sprintf("n%d", i))
	}
	fourth := f.dial("10.3.0.1", proto.Hello{HostName: "box", OS: "linux", Nonce: "n9"})
	fourth.expectClosed("rate limited")
	f.waitRejected(ErrRateLimited)
	if n := len(f.h.Pending()); n != PendingPerIP {
		t.Fatalf("rate-limited hello was listed: %d", n)
	}
	f.pend("10.3.0.2", "other", "n1") // a different IP is unaffected
	f.clk.Advance(PendingPerIPWindow + time.Second)
	f.pend("10.3.0.1", "box", "n10") // window passed
}

func TestPendingExpiresAfter10Min(t *testing.T) {
	f := newFixture(t)
	a, fp := f.pend("", "box", "n1")
	f.clk.Advance(PendingTTL + time.Second)
	if n := len(f.h.Pending()); n != 0 {
		t.Fatalf("entry survived: %d", n)
	}
	if _, err := f.h.Allow(fp); err != ErrPendingExpired {
		t.Fatalf("Allow: %v", err)
	}
	a.expectClosed("expired")
}

func TestPendingConnectionSendingOtherMessageIsDropped(t *testing.T) {
	for _, typ := range []string{proto.TypeHeartbeat, proto.TypeReport, proto.TypeExportRes} {
		t.Run(typ, func(t *testing.T) {
			f := newFixture(t)
			a, fp := f.pend("", "box", "n1")
			a.send(typ, "id1", map[string]any{})
			a.expectClosed("unexpected message")
			eventually(t, func() bool { return len(f.h.Pending()) == 0 })
			if _, err := f.h.Allow(fp); err != ErrNotPending {
				t.Fatalf("Allow: %v", err)
			}
		})
	}
}

func TestPendingConnectionReceivesNoAccountData(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	allowed := map[string]bool{proto.TypePending: true, proto.TypeApproved: true, proto.TypeDenied: true}
	a, fpA := f.pend("10.4.0.1", "boxA", "n1")
	b, fpB := f.pend("10.4.0.2", "boxB", "n2")
	_, _ = f.h.Allow(fpA)
	if err := f.h.Deny(fpB); err != nil {
		t.Fatal(err)
	}
	a.recv(proto.TypeApproved)
	b.recv(proto.TypeDenied)
	for _, ag := range []*agent{a, b} {
		for _, typ := range ag.types() {
			if !allowed[typ] {
				t.Fatalf("pending socket got %s", typ)
			}
		}
	}
}

func TestAllowIssuesTokenOverSameConnectionAndEnrols(t *testing.T) {
	f := newFixture(t)
	a, fp := f.pend("", "box", "n1")
	id, err := f.h.Allow(fp)
	if err != nil || id == "" {
		t.Fatalf("Allow: %q %v", id, err)
	}
	var ap proto.Approved
	if err := json.Unmarshal(a.recv(proto.TypeApproved).Body, &ap); err != nil || ap.Token == "" {
		t.Fatalf("approved: %v", err)
	}
	raw, _ := os.ReadFile(f.tokens)
	sum := sha256.Sum256([]byte(ap.Token))
	if strings.Contains(string(raw), ap.Token) || !strings.Contains(string(raw), hex.EncodeToString(sum[:])) {
		t.Fatalf("stored value is not the SHA-256: %s", raw)
	}
	if len(f.h.Pending()) != 0 {
		t.Fatal("still pending after Allow")
	}
	// The promoted connection is a normal enrolled host.
	a.send(proto.TypeHeartbeat, "", nil)
	if v := f.h.Hosts(); len(v) != 1 || v[0].HostID != id || !v[0].Online {
		t.Fatalf("hosts: %+v", v)
	}
	// And a fresh dial with the token is a normal reconnect.
	c := f.dial("", proto.Hello{Token: ap.Token, HostName: "box", OS: "linux"})
	c.send(proto.TypeHeartbeat, "", nil)
	a.expectClosed("replaced")
	if types := a.types(); len(types) != 2 || types[1] != proto.TypeApproved {
		t.Fatalf("agent must see exactly Pending then one Approved: %v", types)
	}
}

func TestAllowUnknownFingerprintIsErrNotPending(t *testing.T) {
	f := newFixture(t)
	if _, err := f.h.Allow("zzzzzzzz"); err != ErrNotPending {
		t.Fatalf("got %v", err)
	}
	if err := f.h.Deny("zzzzzzzz"); err != ErrNotPending {
		t.Fatalf("got %v", err)
	}
}

func TestDenyClosesAndSuppressesForOneHour(t *testing.T) {
	f := newFixture(t)
	a, fp := f.pend("", "box", "n1")
	if err := f.h.Deny(fp); err != nil {
		t.Fatal(err)
	}
	env := a.recv(proto.TypeDenied)
	var d proto.Denied
	_ = json.Unmarshal(env.Body, &d)
	if d.RetryAfter != DenySuppress {
		t.Fatalf("RetryAfter %v", d.RetryAfter)
	}
	a.expectClosed("denied")

	again := f.dial("", proto.Hello{HostName: "box", OS: "linux", Nonce: "n1"})
	again.recv(proto.TypeDenied)
	again.expectClosed("suppressed")
	f.waitRejected(ErrSuppressed)
	if len(f.h.Pending()) != 0 {
		t.Fatal("suppressed hello was listed")
	}

	f.pend("", "box", "n2") // a fresh nonce is a new fingerprint
	f.clk.Advance(DenySuppress + time.Second)
	f.pend("", "box", "n1") // suppression over
}

func TestDeniedEntryCannotBeAllowed(t *testing.T) {
	f := newFixture(t)
	_, fp := f.pend("", "box", "n1")
	if err := f.h.Deny(fp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Allow(fp); err != ErrNotPending {
		t.Fatalf("got %v", err)
	}
	if len(f.h.Hosts()) != 0 {
		t.Fatal("denied host enrolled")
	}
}

func TestValidCodeBypassesQueue(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "n1"})
	a.recv(proto.TypeApproved)
	if types := a.types(); len(types) != 1 {
		t.Fatalf("types %v", types)
	}
	if len(f.h.Pending()) != 0 {
		t.Fatal("code hello was queued")
	}
}

func TestAllowAndDenyWriteAuditLineWithAllowlistedKeysOnly(t *testing.T) {
	f := newFixture(t)
	_, fpA := f.pend("10.5.0.1", "alice@example.com", "n1")
	a2, fpB := f.pend("10.5.0.2", "boxB", "n2")
	_ = a2
	if _, err := f.h.Allow(fpA); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Deny(fpB); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"time": true, "level": true, "msg": true, "component": true, "action": true,
		"fingerprint": true, "host_name": true, "os": true, "source_ip": true, "result": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q", line)
		}
		act, _ := m["action"].(string)
		if act != "allow" && act != "deny" {
			continue
		}
		seen[act] = true
		for k, v := range m {
			if !want[k] || v == "[dropped]" {
				t.Fatalf("key %q not allowlisted in %s", k, line)
			}
		}
		for _, k := range []string{"fingerprint", "host_name", "os", "source_ip", "result"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("audit line lacks %s: %s", k, line)
			}
		}
	}
	if !seen["allow"] || !seen["deny"] {
		t.Fatalf("missing audit lines: %v", seen)
	}
	out := f.logs.String()
	if strings.Contains(out, "@") || strings.Contains(out, "alice") {
		t.Fatalf("email in logs:\n%s", out)
	}
}

func TestConcurrentHellosRaceFree(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var agents []*agent
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := f.dialQuiet(fmt.Sprintf("10.6.0.%d", i%6), proto.Hello{HostName: "box", OS: "linux", Nonce: fmt.Sprintf("n%d", i)})
			if a == nil {
				return
			}
			mu.Lock()
			agents = append(agents, a)
			mu.Unlock()
			_, _ = a.recvWithin(time.Second)
		}()
	}
	for i := 0; i < 50; i++ {
		for _, p := range f.h.Pending() {
			if i%2 == 0 {
				_, _ = f.h.Allow(p.Fingerprint)
			} else {
				_ = f.h.Deny(p.Fingerprint)
			}
		}
		_ = f.h.Hosts()
		time.Sleep(2 * time.Millisecond)
	}
	wg.Wait()
	for _, a := range agents {
		_ = a.ws.CloseNow()
	}
}
