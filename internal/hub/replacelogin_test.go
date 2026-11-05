package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/ownership"
	"claude-utilities/internal/proto"
)

const (
	workIdentity = "work@example.test"
	replacedBody = `{"accessToken":"NEW-ACCESS","refreshToken":"NEW-REFRESH"}`
)

// replaceRig seeds one account whose login "expired", points the fake agent's sign-in at identity,
// and records the poller notification.
func replaceRig(t *testing.T, signedInAs string) (f *fixture, la *loginAgent, host string, told func() []string) {
	t.Helper()
	f = newFixture(t)
	f.seedAccount("T", "work", workIdentity)
	f.seedAccount("U", "other", "other@example.test")
	a, _, host := f.enrol("box")
	la = f.loginAgent(a)
	la.doneWith = proto.LoginDone{Block: json.RawMessage(newBlock), Identity: signedInAs}
	var mu sync.Mutex
	var got []string
	f.h.SetOnReplaced(func(id string) { mu.Lock(); got = append(got, id); mu.Unlock() })
	return f, la, host, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

func (f *fixture) signIn(host, account string) string {
	f.t.Helper()
	id, err := f.h.ReplaceLogin(context.Background(), host, account)
	if err != nil {
		f.t.Fatal(err)
	}
	f.waitState(id, AddAwaitingCode)
	if err := f.h.AddCode(id, addCodeVal); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestReplaceLoginSwapsTheStoredBlockOfTheSameAccount(t *testing.T) {
	f, la, host, told := replaceRig(t, workIdentity)
	other, _ := f.v.Get("U")
	f.reg.SwapIn("T", "h-old") // stale ownership from before the login expired
	id := f.signIn(host, "T")
	v := f.waitState(id, AddDone)

	if !v.Replace || v.Account == nil || v.Account.ID != "T" || v.Account.Label != "work" || len(v.Account.Block) != 0 {
		t.Fatalf("view %+v", v)
	}
	if n := len(f.v.List()); n != 2 {
		t.Fatalf("vault has %d accounts: a replace must not create one", n)
	}
	got, _ := f.v.Get("T")
	if string(got.Block) != replacedBody || got.Identity != workIdentity || got.Label != "work" {
		t.Fatalf("stored %+v", got)
	}
	if o, _ := f.v.Get("U"); string(o.Block) != string(other.Block) {
		t.Fatal("another account changed")
	}
	if o := f.reg.OwnerOf("T"); o != (ownership.Owner{Server: true}) || len(f.reg.HostsUsing("T")) != 0 {
		t.Fatalf("ownership not reset to the vault copy: %+v %v", o, f.reg.HostsUsing("T"))
	}
	if g := told(); len(g) != 1 || g[0] != "T" {
		t.Fatalf("poller told %v", g)
	}
	if la.saw(proto.TypeSwapReq) || la.saw(proto.TypeExportReq) {
		t.Fatal("a replace must not touch any host's live credentials")
	}
	if v.Warning != "" {
		t.Fatalf("no host holds it, yet a warning: %q", v.Warning)
	}
	logs := f.logs.String()
	for _, secret := range []string{workIdentity, "NEW-ACCESS", "NEW-REFRESH", addCodeVal, "PLANTED-STATE"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log leaks %q", secret)
		}
	}
	if !strings.Contains(logs, "login_replace") {
		t.Fatal("no audit line for the replace")
	}
}

func TestReplaceLoginRefusesADifferentIdentityAndStoresNothing(t *testing.T) {
	f, _, host, told := replaceRig(t, "stranger@example.test")
	before, _ := f.v.Get("T")
	id := f.signIn(host, "T")
	v := f.waitState(id, AddFailed)

	if !strings.Contains(v.Error, "different account") || v.Account != nil {
		t.Fatalf("view %+v", v)
	}
	if strings.Contains(v.Error, "stranger") || strings.Contains(v.Error, workIdentity) {
		t.Fatalf("error names an identity: %q", v.Error)
	}
	got, _ := f.v.Get("T")
	if string(got.Block) != string(before.Block) || len(f.v.List()) != 2 {
		t.Fatal("a refused replace changed the vault")
	}
	if len(told()) != 0 {
		t.Fatal("poller reset on a refused replace")
	}
	if strings.Contains(f.logs.String(), "stranger@example.test") {
		t.Fatal("log leaks the identity")
	}
}

func TestReplaceLoginUnknownAccount(t *testing.T) {
	f, la, host, _ := replaceRig(t, workIdentity)
	if _, err := f.h.ReplaceLogin(context.Background(), host, "nope"); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("err %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if la.saw(proto.TypeLoginStart) {
		t.Fatal("a sign-in started for an unknown account")
	}
}

func TestReplaceLoginAccountRemovedDuringSignIn(t *testing.T) {
	f, _, host, told := replaceRig(t, workIdentity)
	id, err := f.h.ReplaceLogin(context.Background(), host, "T")
	if err != nil {
		t.Fatal(err)
	}
	f.waitState(id, AddAwaitingCode)
	if err := f.v.Delete("T"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.AddCode(id, addCodeVal); err != nil {
		t.Fatal(err)
	}
	v := f.waitState(id, AddFailed)
	if !strings.Contains(v.Error, "no longer exists") {
		t.Fatalf("view %+v", v)
	}
	if _, ok := f.v.Get("T"); ok || len(told()) != 0 {
		t.Fatal("a removed account was recreated or the poller told")
	}
}

// Decision: replacing a login while a host holds the account live is allowed. The host's own login
// is a separate copy and is never touched; the finished job carries a warning saying so.
func TestReplaceLoginWhileAHostHoldsItLiveIsAllowedWithAWarning(t *testing.T) {
	f, la, host, _ := replaceRig(t, workIdentity)
	a2, _, host2 := f.enrol("holder")
	f.reportIdentity(a2, host2, workIdentity)
	id := f.signIn(host, "T")
	v := f.waitState(id, AddDone)
	if !strings.Contains(v.Warning, "still signed in") {
		t.Fatalf("warning %q", v.Warning)
	}
	if strings.Contains(v.Warning, "holder") {
		t.Fatalf("warning carries the agent-supplied host name: %q", v.Warning)
	}
	if got, _ := f.v.Get("T"); string(got.Block) != replacedBody {
		t.Fatal("not replaced")
	}
	if la.saw(proto.TypeSwapReq) || la.saw(proto.TypeExportReq) {
		t.Fatal("touched a host")
	}
}

func TestReplaceLoginSharesTheOneLiveJobLimit(t *testing.T) {
	f, _, host, _ := replaceRig(t, workIdentity)
	if _, err := f.h.ReplaceLogin(context.Background(), host, "T"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.AddAccount(context.Background(), host, "x"); !errors.Is(err, ErrAddBusy) {
		t.Fatalf("add during replace: %v", err)
	}
	if _, err := f.h.ReplaceLogin(context.Background(), host, "U"); !errors.Is(err, ErrAddBusy) {
		t.Fatalf("second replace: %v", err)
	}
}
