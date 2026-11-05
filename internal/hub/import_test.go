package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"claude-utilities/internal/ownership"
	"claude-utilities/internal/vault"
)

func TestImportStoresLiveBlockAsNewAccountOwnedByHost(t *testing.T) {
	f := newFixture(t)
	a, _, id := f.enrol("box")
	s := f.newScript("id-new", `{"claudeAiOauth":{"accessToken":"live-tok"},"mcpOAuth":{"x":1}}`)
	s.serve(a)
	acct, err := f.h.Import(context.Background(), id, "work")
	if err != nil {
		t.Fatal(err)
	}
	if acct.Label != "work" || acct.Identity != "id-new" || acct.ID == "" {
		t.Fatalf("account: %+v", acct)
	}
	got, ok := f.v.Get(acct.ID)
	if !ok || string(got.Block) != `{"accessToken":"live-tok"}` {
		t.Fatalf("vault block %q ok=%v (must be the claudeAiOauth block only)", got.Block, ok)
	}
	if o := f.reg.OwnerOf(acct.ID); o != (ownership.Owner{HostID: id}) {
		t.Fatalf("owner %+v", o)
	}
	var active string
	for _, hv := range f.h.Hosts() {
		active = hv.ActiveAccount
	}
	if active != acct.ID {
		t.Fatalf("host active account %q, want %q", active, acct.ID)
	}
}

func TestImportRefusesIdentityAlreadyStored(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.newScript("id-a", `{"tok":"x"}`).serve(a)
	if _, err := f.h.Import(context.Background(), id, "dup"); !errors.Is(err, ErrAlreadyStored) {
		t.Fatalf("err %v", err)
	}
	if n := len(f.v.List()); n != 3 {
		t.Fatalf("vault has %d accounts", n)
	}
}

func TestImportRefusesEmptyIdentityOrLabelAndOfflineHost(t *testing.T) {
	f := newFixture(t)
	a, _, id := f.enrol("box")
	f.newScript("", `{"tok":"x"}`).serve(a)
	if _, err := f.h.Import(context.Background(), id, "l"); err == nil {
		t.Fatal("empty identity accepted")
	}
	if _, err := f.h.Import(context.Background(), id, ""); err == nil {
		t.Fatal("empty label accepted")
	}
	if _, err := f.h.Import(context.Background(), "nope", "l"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("err %v", err)
	}
}

func TestRelabelRenamesLogsIdAndMapsErrors(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	if err := f.h.Relabel("A", "  Work  "); err != nil {
		t.Fatal(err)
	}
	if a, _ := f.v.Get("A"); a.Label != "Work" || string(a.Block) != `{"tok":"A-stored"}` {
		t.Fatalf("account after relabel: %+v", a)
	}
	out := f.logs.String()
	if !strings.Contains(out, "account relabelled") || !strings.Contains(out, `"account":"A"`) || strings.Contains(out, "Work") || strings.Contains(out, "[dropped]") {
		t.Fatalf("log: %s", out)
	}
	if err := f.h.Relabel("nope", "x"); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("unknown: %v", err)
	}
	if err := f.h.Relabel("B", "WORK"); !errors.Is(err, vault.ErrLabelTaken) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := f.h.Relabel("B", " "); !errors.Is(err, vault.ErrLabelInvalid) {
		t.Fatalf("empty: %v", err)
	}
}
