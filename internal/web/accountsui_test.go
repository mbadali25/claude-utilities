package web

import (
	"strings"
	"testing"
)

// accountsPanel returns the Accounts tab panel's markup, so a test cannot pass on a string that
// lives somewhere else on the page.
func accountsPanel(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, `id="panel-accounts"`)
	if i < 0 {
		t.Fatal("no accounts panel")
	}
	j := strings.Index(page[i:], "</section>")
	if j < 0 {
		t.Fatal("accounts panel never closes")
	}
	return page[i : i+j]
}

func TestAccountsPanelHasTheExpandCollapseAndRefreshControls(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	panel := accountsPanel(t, page(r, r.login()))
	for _, want := range []string{
		`id="acc-expand-all"`, `id="acc-collapse-all"`, `id="acc-refresh-all"`,
		`id="acc-refresh-status"`, `role="status"`, `aria-atomic="true"`,
		`class="spin"`, `id="acc-count"`, `id="accounts"`,
		// The cards' h3 headings need a section heading above them, not the page title.
		`<h2 class="sr" id="acc-panel-h">Accounts</h2>`,
	} {
		if !strings.Contains(panel, want) {
			t.Fatalf("accounts panel is missing %s", want)
		}
	}
}

func TestAccountCardsAreADisclosureClosedByDefault(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	// The card's header is a real button carrying both disclosure attributes, and a card is built
	// closed unless the remembered state says otherwise.
	for _, want := range []string{
		`'acct-dis'`, `dis.type = 'button'`,
		`dis.setAttribute('aria-expanded', open ? 'true' : 'false')`,
		`dis.setAttribute('aria-controls', bodyID)`,
		`function isOpen(id) { return editing === id || pref(openKey(id), false) === true; }`,
		`function openKey(id) { return 'acc.' + id; }`,
		`body.hidden = !open`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing the disclosure code %q", want)
		}
	}
	// No keydown handler on the disclosure: a native button already answers Enter and Space, and a
	// handler beside it would fire twice.
	if strings.Contains(p, "dis.addEventListener('keydown'") {
		t.Fatal("the disclosure button must rely on the browser for Enter and Space")
	}
}

func TestClosedCardShowsTheSevenDayWindowAndTheFreshnessChip(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	// The 7-day meter and the status chip are built outside the hidden body; the 5-hour meter, the
	// holder, the rename and the per-card Refresh are inside it.
	for _, want := range []string{
		`brief.appendChild(meter('7-day window', a.sevenDay))`,
		`top.appendChild(statusChip(a))`,
		`ms.appendChild(meter('5-hour window', a.fiveHour))`,
		`body.appendChild(nameRow(c, a))`,
		`foot.appendChild(refreshBtn(a))`,
		`.card.acct:not(.open) .acct-brief .reset { display:none; }`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
}

func TestRefreshUIPostsToTheRefreshRouteAndReportsPerAccount(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	for _, want := range []string{
		`call('POST', '/api/usage/refresh', { account: id || '' })`,
		`'rate_limited'`, `'unknown_id'`,
		`b.setAttribute('aria-busy', 'true')`,
		`'acct-note'`, `.acct-note.bad { color:var(--bad); }`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing the refresh code %q", want)
		}
	}
	// The spinner is decoration: reduced motion hides it and the button's own word carries the state.
	if !strings.Contains(p, `@media (prefers-reduced-motion: reduce) { .spin { display:none !important; } }`) {
		t.Fatal("the spinner must be hidden under reduced motion")
	}
	if !strings.Contains(p, `'Refreshing all...'`) || !strings.Contains(p, `'Refreshing...'`) {
		t.Fatal("a busy control must say so in words")
	}
	// A card's note outlives the wait it would name - nothing re-renders it on a timer - so it
	// must not carry the server's retryAfterSec as a countdown.
	if strings.Contains(p, "try again in ' + ") {
		t.Fatal("the refusal note must not name a wait that cannot tick down")
	}
}

func TestOpenCardStateIsRememberedInTheExistingPrefsKey(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	if strings.Count(p, "'cs.ui.v1'") != 1 {
		t.Fatal("the page must keep exactly one layout-preference key")
	}
	// Writing goes through the same guarded helper as every other preference.
	if !strings.Contains(p, "if (open) prefs[k] = true; else delete prefs[k];") || !strings.Contains(p, "savePrefs();") {
		t.Fatal("the open state must be stored through savePrefs")
	}
}

func TestAutomaticPollDefersToARunningRefresh(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())
	if !strings.Contains(p, "!ctlDialogOpen() && !refreshBusy()) refresh();") {
		t.Fatal("the 30s poll must not re-render the cards during a refresh")
	}
}
