package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

func (f *fixture) vaultBlock(id string) string {
	f.t.Helper()
	a, ok := f.v.Get(id)
	if !ok {
		f.t.Fatalf("no account %s", id)
	}
	return string(a.Block)
}

func TestSwapWritebackOnlyFromHostsThatMaySpeakForTheAccount(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(f *fixture, me, other string)
		wantBlock string
	}{
		{"active owner writes back", func(f *fixture, me, other string) { f.reg.SwapIn("A", me) }, `{"tok":"A-live"}`},
		{"server owned, non-holder claim is skipped", func(f *fixture, me, other string) {}, `{"tok":"A-stored"}`},
		{"shared host is skipped", func(f *fixture, me, other string) {
			f.reg.SwapIn("A", me)
			f.reg.SwapIn("A", other)
		}, `{"tok":"A-stored"}`},
		{"stale host is skipped", func(f *fixture, me, other string) {
			f.reg.SwapIn("A", me)
			f.reg.SwapIn("A", other)
			f.reg.HostLost(other)
		}, `{"tok":"A-stored"}`},
		{"non-holder claiming another host's account is skipped", func(f *fixture, me, other string) {
			f.reg.SwapIn("A", other)
		}, `{"tok":"A-stored"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.seedAccounts()
			a, _, me := f.enrol("box")
			_, _, other := f.enrol("box2")
			tc.setup(f, me, other)
			f.newScript("id-a", `{"tok":"A-live"}`).serve(a)
			if _, err := f.h.Swap(context.Background(), me, "B"); err != nil {
				t.Fatal(err)
			}
			if got := f.vaultBlock("A"); got != tc.wantBlock {
				t.Fatalf("vault A = %s, want %s", got, tc.wantBlock)
			}
		})
	}
}

func TestSwapStoresOnlyTheClaudeAiOauthBlock(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	f.newScript("id-a", `{"claudeAiOauth":{"tok":"A-live"},"mcpOAuth":{"srv":"mcp-secret"}}`).serve(a)
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != `{"tok":"A-live"}` {
		t.Fatalf("vault A = %s", got)
	}
}

func TestSwapRejectsBadBlocks(t *testing.T) {
	for name, block := range map[string]string{
		"mcp only":    `{"mcpOAuth":{"srv":"x"}}`,
		"array":       `[1]`,
		"null":        `null`,
		"inner null":  `{"claudeAiOauth":null}`,
		"inner str":   `{"claudeAiOauth":"x"}`,
		"empty obj":   `{}`,
		"empty oauth": `{"claudeAiOauth":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.seedAccounts()
			a, _, id := f.enrol("box")
			s := f.newScript("id-a", block)
			s.serve(a)
			_, err := f.h.Swap(context.Background(), id, "B")
			if err == nil || errors.Is(err, ErrUnknownLiveAccount) {
				t.Fatalf("got %v", err)
			}
			if got := f.vaultBlock("A"); got != `{"tok":"A-stored"}` {
				t.Fatalf("vault A changed: %s", got)
			}
			if order, _ := s.snapshot(); len(order) != 1 {
				t.Fatalf("swap_req was sent: %v", order)
			}
		})
	}
}

func TestSwapNoOpRecordsHolderAndIdentity(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	if err := f.v.Put(vault.Account{ID: "A", Label: "a", Identity: "id-a", Block: json.RawMessage(`{"refreshToken":"rt-a"}`)}); err != nil {
		t.Fatal(err)
	}
	a, _, id := f.enrol("box")
	f.newScript("id-a", `{"refreshToken":"rt-a"}`).serve(a)
	if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
		t.Fatal(err)
	}
	if o := f.reg.OwnerOf("A"); o.HostID != id {
		t.Fatalf("owner of A: %+v", o)
	}
	if v := f.h.Hosts()[0]; v.ActiveAccount != "A" {
		t.Fatalf("view: %+v", v)
	}
}

func TestSwapTimeoutIsUnknownOutcome(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.h.reqTimeout = 200 * time.Millisecond
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"tok":"A-live"}`)
	s.stopSwapRes = true
	s.serve(a)
	_, err := f.h.Swap(context.Background(), id, "B")
	if !errors.Is(err, ErrSwapOutcomeUnknown) {
		t.Fatalf("got %v", err)
	}
	if f.reg.OwnerOf("A").HostID != id || !f.reg.OwnerOf("B").Server {
		t.Fatal("ownership must not move on an unknown outcome")
	}
	if !strings.Contains(f.logs.String(), "swap outcome unknown") {
		t.Fatal("unknown outcome not logged")
	}
	if v := f.h.Hosts()[0]; v.ActiveAccount != "" {
		t.Fatalf("identity must be cleared: %+v", v)
	}
}

func TestRevokeDuringSwapIsUnknownOutcome(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	s := f.newScript("id-a", `{"tok":"A-live"}`)
	s.swapDelay = 400 * time.Millisecond
	s.serve(a)
	res := make(chan error, 1)
	go func() { _, swerr := f.h.Swap(context.Background(), id, "B"); res <- swerr }()
	eventually(t, func() bool { order, _ := s.snapshot(); return len(order) == 2 })
	if err := f.h.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if err := <-res; !errors.Is(err, ErrSwapOutcomeUnknown) {
		t.Fatalf("got %v", err)
	}
	if !f.reg.OwnerOf("B").Server {
		t.Fatal("ownership moved")
	}
}

func TestReconnectDuringSwapIsUnknownOutcome(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, token, id := f.enrol("box")
	s := f.newScript("id-a", `{"tok":"A-live"}`)
	s.swapDelay = 400 * time.Millisecond
	s.serve(a)
	res := make(chan error, 1)
	go func() { _, swerr := f.h.Swap(context.Background(), id, "B"); res <- swerr }()
	eventually(t, func() bool { order, _ := s.snapshot(); return len(order) == 2 })
	f.dial("", proto.Hello{Token: token, HostName: "box", OS: "linux"})
	if err := <-res; !errors.Is(err, ErrSwapOutcomeUnknown) {
		t.Fatalf("got %v", err)
	}
}

func TestAllowPersistFailureKeepsEntryForRetry(t *testing.T) {
	f := newFixture(t)
	good := f.h.tokensPath
	blocker := filepath.Join(filepath.Dir(good), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil { // a file where the directory must go
		t.Fatal(err)
	}
	f.h.tokensPath = filepath.Join(blocker, "hosts.json")
	_, fp := f.pend("", "box", "n1")
	if _, err := f.h.Allow(fp); err == nil {
		t.Fatal("Allow must fail when persistence fails")
	}
	if n := len(f.h.Pending()); n != 1 {
		t.Fatalf("entry lost: %d", n)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Allow(fp); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestUnexpectedReplyDoesNotEchoRawAgentType(t *testing.T) {
	evil := "sk-ant-oat01-SECRETSECRETSECRET" + strings.Repeat("x", 500)
	err := unexpectedReply(evil, proto.TypeExportReq)
	if !errors.Is(err, ErrUnexpectedReply) {
		t.Fatalf("not ErrUnexpectedReply: %v", err)
	}
	if strings.Contains(err.Error(), "SECRETSECRET") || len(err.Error()) > 200 {
		t.Fatalf("raw agent type echoed: %v", err)
	}
}

func TestHostViewSurfacesSwapBlocked(t *testing.T) {
	f := newFixture(t)
	a, _, _ := f.enrol("box")
	a.send(proto.TypeReport, "", proto.Report{SwapBlocked: true})
	eventually(t, func() bool { return f.h.Hosts()[0].SwapBlocked })
	a.send(proto.TypeReport, "", proto.Report{})
	eventually(t, func() bool { return !f.h.Hosts()[0].SwapBlocked })
}

// A report is an agent-supplied claim; it must never make the reporter the owner of a server-owned account.
func TestReportedIdentityDoesNotPromoteToOwner(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a", CredsPresent: true})
	eventually(t, func() bool { return f.h.Hosts()[0].ActiveAccount == "A" })
	if o := f.reg.OwnerOf("A"); !o.Server {
		t.Fatalf("owner %+v, a report must not take ownership for %s", o, id)
	}
}

// Host B only claims alice's identity; its swap must leave alice's stored login intact.
func TestClaimedIdentityCannotOverwriteVaultBlock(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	b, _, id := f.enrol("boxB")
	f.newScript("id-a", `{"tok":"B-forged"}`).serve(b)
	b.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a", CredsPresent: true})
	eventually(t, func() bool { return f.h.Hosts()[0].ActiveAccount == "A" })
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != `{"tok":"A-stored"}` {
		t.Fatalf("vault A overwritten by a claimant: %s", got)
	}
}

// A no-op swap records a holder only when the exported login shares the stored refresh-token lineage.
func TestNoOpSwapRecordsHolderOnlyOnLineageMatch(t *testing.T) {
	for name, tc := range map[string]struct {
		block   string
		wantOwn bool
	}{
		"same lineage":      {`{"refreshToken":"rt-a","accessToken":"new"}`, true},
		"different lineage": {`{"refreshToken":"rt-forged"}`, false},
		"no refresh token":  {`{"tok":"A-live"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.seedAccounts()
			if err := f.v.Put(vault.Account{ID: "A", Label: "a", Identity: "id-a", Block: json.RawMessage(`{"refreshToken":"rt-a"}`)}); err != nil {
				t.Fatal(err)
			}
			a, _, id := f.enrol("box")
			f.newScript("id-a", tc.block).serve(a)
			if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
				t.Fatal(err)
			}
			if got := f.reg.OwnerOf("A").HostID == id; got != tc.wantOwn {
				t.Fatalf("owner recorded = %v, want %v", got, tc.wantOwn)
			}
		})
	}
}

func TestReportDoesNotStealAccountOwnedByAnotherHost(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	_, _, other := f.enrol("box2")
	f.reg.SwapIn("A", other)
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a"})
	eventually(t, func() bool { return f.h.Hosts()[0].ActiveAccount == "A" })
	if o := f.reg.OwnerOf("A"); o.HostID != other {
		t.Fatalf("owner %+v, host %s must not take it", o, id)
	}
}

func TestNeedsReloadIgnoresClockSkew(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.newScript("id-a", `{"tok":"A-live"}`).serve(a)
	skewed := f.clk.Now().Add(3 * time.Hour) // agent clock runs ahead of the server's
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a",
		Sessions: []proto.Session{{PID: 1, ID: "old", StartedAt: skewed}}})
	eventually(t, func() bool { return len(f.h.Hosts()[0].Sessions) == 1 })
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if !f.h.Hosts()[0].Sessions[0].NeedsReload {
		t.Fatal("session running at swap time must need a reload despite skew")
	}
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-b", Sessions: []proto.Session{
		{PID: 1, ID: "old", StartedAt: skewed}, {PID: 2, ID: "new", StartedAt: skewed.Add(-6 * time.Hour)}}})
	eventually(t, func() bool { return len(f.h.Hosts()[0].Sessions) == 2 })
	for _, s := range f.h.Hosts()[0].Sessions {
		if want := s.ID == "old"; s.NeedsReload != want {
			t.Fatalf("session %s NeedsReload=%v", s.ID, s.NeedsReload)
		}
	}
}

func TestPendingHelloWithoutNonceRejected(t *testing.T) {
	f := newFixture(t)
	a := f.dial("", proto.Hello{HostName: "box", OS: "linux"})
	a.expectClosed("nonce required")
	f.waitRejected(ErrEmptyNonce)
	if len(f.h.Pending()) != 0 {
		t.Fatal("listed")
	}
}

func TestPendingFingerprintCannotBeReplacedFromAnotherAddress(t *testing.T) {
	f := newFixture(t)
	first, fp := f.pend("10.4.0.1", "box", "n1")
	evil := f.dial("10.4.0.2", proto.Hello{HostName: "box", OS: "linux", Nonce: "n1"})
	evil.expectClosed("fingerprint in use")
	f.waitRejected(ErrFingerprintInUse)
	if got := f.h.Pending(); len(got) != 1 || got[0].SourceIP != "10.4.0.1" {
		t.Fatalf("pending: %+v", got)
	}
	_ = first
	if _, err := f.h.Allow(fp); err != nil {
		t.Fatal(err)
	}
}

func TestPendingFullDoesNotConsumeIPQuota(t *testing.T) {
	f := newFixture(t)
	var fp0 string
	for i := 0; i < PendingCap; i++ {
		_, fp := f.pend(fmt.Sprintf("10.7.1.%d", i), "box", fmt.Sprintf("n%d", i))
		if i == 0 {
			fp0 = fp
		}
	}
	for i := 0; i < PendingPerIP+2; i++ {
		over := f.dial("10.7.9.9", proto.Hello{HostName: "x", OS: "linux", Nonce: fmt.Sprintf("o%d", i)})
		over.expectClosed("queue full")
	}
	if err := f.h.Deny(fp0); err != nil {
		t.Fatal(err)
	}
	f.pend("10.7.9.9", "x", "ok") // would be "rate limited" if refused hellos had counted
}

func TestBadTokenFloodIsRateLimited(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < BadHelloPerIP; i++ {
		f.dial("10.8.0.1", proto.Hello{Token: fmt.Sprintf("bad-%d", i), HostName: "x", OS: "y"}).expectClosed("bad token")
	}
	f.dial("10.8.0.1", proto.Hello{Token: "bad-next", HostName: "x", OS: "y"}).expectClosed("rate limited")
	f.dial("10.8.0.2", proto.Hello{Token: "bad-other", HostName: "x", OS: "y"}).expectClosed("bad token")
	f.clk.Advance(PendingPerIPWindow + time.Second)
	f.dial("10.8.0.1", proto.Hello{Token: "bad-later", HostName: "x", OS: "y"}).expectClosed("bad token")
}

func TestEnsureCertLeavesOnlyTheTwoFilesAndHostsFileLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := EnsureCert(dir); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("cert dir holds %d entries", len(ents))
	}
	f := newFixture(t)
	f.enrol("box")
	ents, _ = os.ReadDir(filepath.Dir(f.tokens))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
	var hf hostFile
	raw, _ := os.ReadFile(f.tokens)
	if err := json.Unmarshal(raw, &hf); err != nil || len(hf.Hosts) != 1 {
		t.Fatalf("hosts file: %v %s", err, raw)
	}
}

func TestSwapAwayDoesNotPromotePreviousHolderOfOldAccount(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, me := f.enrol("box")
	_, _, other := f.enrol("box2")
	f.reg.SwapIn("A", other)
	f.reg.SwapIn("A", me) // me is Active, other holds a possibly stale copy
	f.newScript("id-a", `{"tok":"A-live"}`).serve(a)
	if _, err := f.h.Swap(context.Background(), me, "B"); err != nil {
		t.Fatal(err)
	}
	if o := f.reg.OwnerOf("A"); o.HostID == other {
		t.Fatalf("previous holder %s was promoted to owner of A", other)
	}
}

func TestPendingFingerprintMatchesAgentForLongAndControlFields(t *testing.T) {
	f := newFixture(t)
	hello := proto.Hello{HostName: strings.Repeat("h", 100) + "\x07", OS: "linux", Nonce: "n1"}
	a := f.dial("10.9.0.1", hello)
	var p proto.Pending
	if err := json.Unmarshal(a.recv(proto.TypePending).Body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Fingerprint != proto.Fingerprint(hello) {
		t.Fatalf("server fingerprint %q != agent %q", p.Fingerprint, proto.Fingerprint(hello))
	}
	if got := f.h.Pending(); len(got) != 1 || got[0].Fingerprint != p.Fingerprint || len([]rune(got[0].HostName)) > maxFieldLen {
		t.Fatalf("pending view: %+v", got)
	}
}

func TestOversizedUnauthenticatedHelloIsClosed(t *testing.T) {
	f := newFixture(t)
	a := f.dial("10.9.0.2", proto.Hello{HostName: strings.Repeat("h", helloMaxSize*2), OS: "linux", Nonce: "n"})
	a.expectClosed("")
	if len(f.h.Pending()) != 0 {
		t.Fatal("oversized hello was queued")
	}
}

func TestCorruptHostsFileIsKept(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.tokens, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.h = New(f.v, f.reg, f.tokens, f.h.log)
	got, err := os.ReadFile(f.tokens + ".corrupt")
	if err != nil || string(got) != "{not json" {
		t.Fatalf("corrupt copy: %q %v", got, err)
	}
}

func TestHostsFileDirectoryIsCreated(t *testing.T) {
	f := newFixture(t)
	f.h.tokensPath = filepath.Join(filepath.Dir(f.tokens), "sub", "hosts.json")
	f.enrol("box")
	if _, err := os.Stat(f.h.tokensPath); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureCertTightensLooseKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	dir := t.TempDir()
	_, key, _, err := EnsureCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := EnsureCert(dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode().Perm())
	}
}
