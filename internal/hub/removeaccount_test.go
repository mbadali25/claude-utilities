package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

// seedAccount stores one account with a login block, as an import would.
func (f *fixture) seedAccount(id, label, identity string) {
	f.t.Helper()
	err := f.v.Put(vault.Account{ID: id, Label: label, Identity: identity, Updated: f.clk.Now(),
		Block: json.RawMessage(`{"accessToken":"at-` + id + `","refreshToken":"rt-` + id + `"}`)})
	if err != nil {
		f.t.Fatal(err)
	}
}

// reportIdentity makes the host say it is signed in as identity and waits until the hub agrees,
// which is the same state Hosts() turns into ActiveAccount.
func (f *fixture) reportIdentity(a *agent, hostID, identity string) {
	f.t.Helper()
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: identity})
	eventually(f.t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.HostID == hostID && hv.Online && hv.ActiveAccount != "" {
				return true
			}
		}
		return false
	})
}

func TestRemoveAccountDeletesTheVaultEntryAndItsOwnership(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	f.seedAccount("acct-2", "spare", "spare@example.test")
	f.reg.SwapIn("acct-1", "h-old")
	f.reg.SwapIn("acct-2", "h-other")

	if err := f.h.RemoveAccount("acct-1", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.v.Get("acct-1"); ok {
		t.Fatal("the account is still in the vault")
	}
	if _, ok := f.v.Get("acct-2"); !ok {
		t.Fatal("another account was removed too")
	}
	if n := len(f.reg.HostsUsing("acct-1")); n != 0 {
		t.Fatalf("ownership still lists %d holders", n)
	}
	if !f.reg.OwnerOf("acct-1").Server {
		t.Fatal("ownership still names a host as the owner")
	}
	if f.reg.NeedsWritebackCheck("acct-1") {
		t.Fatal("ownership still wants a writeback to a deleted account")
	}
	if _, ok := f.reg.HostsUsing("acct-2")["h-other"]; !ok {
		t.Fatal("another account's ownership was dropped")
	}
}

// A lost sole owner leaves a writeback flag behind, which keeps the entry alive through SwapAway.
// Forget has to clear that too, or the server would later write a deleted login back into a vault
// slot that no longer exists.
func TestRemoveAccountClearsAPendingWriteback(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	f.reg.SwapIn("acct-1", "h-1")
	f.reg.HostLost("h-1")
	if !f.reg.NeedsWritebackCheck("acct-1") {
		t.Fatal("fixture: expected a pending writeback check")
	}

	if err := f.h.RemoveAccount("acct-1", false); err != nil {
		t.Fatal(err)
	}
	if f.reg.NeedsWritebackCheck("acct-1") {
		t.Fatal("the writeback flag survived the removal")
	}
}

func TestRemoveAccountUnknownID(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	for _, force := range []bool{false, true} {
		if err := f.h.RemoveAccount("nope", force); !errors.Is(err, ErrUnknownAccount) {
			t.Fatalf("force=%v: %v, want ErrUnknownAccount", force, err)
		}
	}
}

func TestRemoveAccountIsRefusedWhileAnOnlineHostHoldsItLive(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	a, _, hostID := f.enrol("oak")
	f.reportIdentity(a, hostID, "work@example.test")

	err := f.h.RemoveAccount("acct-1", false)
	if !errors.Is(err, ErrAccountHeldLive) {
		t.Fatalf("%v, want ErrAccountHeldLive", err)
	}
	held, ok := HeldBy(err)
	if !ok || held.HostName != "oak" || held.HostID != hostID {
		t.Fatalf("refusal names %+v, want oak/%s", held, hostID)
	}
	if _, ok := f.v.Get("acct-1"); !ok {
		t.Fatal("a refused removal deleted the account anyway")
	}
	// The host the hub names is the host the UI shows as holding the account.
	for _, hv := range f.h.Hosts() {
		if hv.HostID == hostID && hv.ActiveAccount != "acct-1" {
			t.Fatalf("Hosts() says %q holds %q, the refusal says acct-1", hv.Name, hv.ActiveAccount)
		}
	}
	// The host name never reaches the log; the opaque host id does.
	if logs := f.logs.String(); strings.Contains(logs, "work@example.test") {
		t.Fatal("the refusal logged the account identity")
	}
}

func TestForceRemovesAnAccountAnOnlineHostHolds(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	a, _, hostID := f.enrol("oak")
	f.reportIdentity(a, hostID, "work@example.test")

	if err := f.h.RemoveAccount("acct-1", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.v.Get("acct-1"); ok {
		t.Fatal("force did not remove the account")
	}
}

// Offline is not held: a host that is not connected cannot be signed out by a swap either, and the
// stored copy is exactly what the operator would otherwise be stuck keeping forever.
func TestRemoveAccountIgnoresAnOfflineHoldAndARevokedHost(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	a, _, hostID := f.enrol("pine")
	f.reportIdentity(a, hostID, "work@example.test")
	if err := f.h.Revoke(hostID); err != nil {
		t.Fatal(err)
	}
	f.reg.SwapIn("acct-1", hostID) // ownership still names it; online is what decides

	if err := f.h.RemoveAccount("acct-1", false); err != nil {
		t.Fatalf("a revoked host blocked the removal: %v", err)
	}
}

// After a swap the agent keeps reporting its old identity, and the hub corrects for that. The
// refusal has to follow the correction, or it fails open on the case it exists for: an account
// just swapped onto a host would be removable while that host is running it.
func TestRemoveAccountIsRefusedAfterASwapTheAgentHasNotNoticed(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-old", "old", "old@example.test")
	f.seedAccount("acct-new", "new", "new@example.test")
	a, _, hostID := f.enrol("oak")
	f.reportIdentity(a, hostID, "old@example.test")
	f.reg.SwapIn("acct-old", hostID)

	go func() {
		env, err := a.recvWithin(3 * time.Second)
		if err != nil || env.Type != proto.TypeExportReq {
			return
		}
		a.send(proto.TypeExportRes, env.ID, proto.ExportRes{Identity: "old@example.test",
			Block: json.RawMessage(`{"claudeAiOauth":{"accessToken":"at-acct-old","refreshToken":"rt-acct-old"}}`)})
		env, err = a.recvWithin(3 * time.Second)
		if err != nil || env.Type != proto.TypeSwapReq {
			return
		}
		a.send(proto.TypeSwapRes, env.ID, proto.SwapRes{OK: true})
	}()
	if _, err := f.h.Swap(context.Background(), hostID, "acct-new"); err != nil {
		t.Fatal(err)
	}
	// The agent heartbeats its stale identity, as a real one does after a swap.
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "old@example.test"})
	eventually(t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.HostID == hostID {
				return hv.ActiveAccount == "acct-new"
			}
		}
		return false
	})

	err := f.h.RemoveAccount("acct-new", false)
	if !errors.Is(err, ErrAccountHeldLive) {
		t.Fatalf("the swapped-in account was removable: %v", err)
	}
	if err := f.h.RemoveAccount("acct-old", false); err != nil {
		t.Fatalf("the swapped-away account should be removable: %v", err)
	}
}

// The safety property of the whole feature: removing the server's stored copy must never reach a
// host's credentials file. The only channel to a host is this websocket, so the proof is that the
// agent is sent nothing at all.
func TestRemoveAccountSendsNoFrameToAnyAgent(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "work", "work@example.test")
	f.seedAccount("acct-2", "spare", "spare@example.test")
	a, _, hostID := f.enrol("oak")
	f.reportIdentity(a, hostID, "work@example.test")
	f.reg.SwapIn("acct-2", hostID)
	before := a.types()

	// Both endings: the refused one and the forced one.
	if err := f.h.RemoveAccount("acct-1", false); !errors.Is(err, ErrAccountHeldLive) {
		t.Fatalf("expected a refusal: %v", err)
	}
	if err := f.h.RemoveAccount("acct-2", false); err != nil {
		t.Fatal(err)
	}
	if err := f.h.RemoveAccount("acct-1", true); err != nil {
		t.Fatal(err)
	}

	if _, err := a.recvWithin(300 * time.Millisecond); err == nil {
		t.Fatalf("the hub sent the agent a frame: %v", a.types())
	}
	if got := a.types(); len(got) != len(before) {
		t.Fatalf("agent received %v, want nothing beyond %v", got, before)
	}
	// Nothing swapped either: ownership is just dropped.
	if _, ok := f.reg.HostsUsing("acct-2")[hostID]; ok {
		t.Fatal("ownership still lists the host for the removed account")
	}
}

// The account id is an opaque handle and is logged; the label and the identity (which can be an
// email) are not. The host name is agent-supplied and stays out too.
func TestRemoveAccountAuditLineCarriesNoIdentityLabelOrToken(t *testing.T) {
	f := newFixture(t)
	f.seedAccount("acct-1", "the-label", "person@example.test")

	if err := f.h.RemoveAccount("acct-1", false); err != nil {
		t.Fatal(err)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, "remove_account") || !strings.Contains(logs, "acct-1") {
		t.Fatalf("no audit line for the removal: %s", logs)
	}
	for _, bad := range []string{"person@example.test", "the-label", "at-acct-1", "rt-acct-1"} {
		if strings.Contains(logs, bad) {
			t.Fatalf("the audit line leaked %q: %s", bad, logs)
		}
	}
}
