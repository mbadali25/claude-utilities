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
		`acts.appendChild(refreshBtn(a))`,
		`.card.acct:not(.open) .acct-brief .reset { display:none; }`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
}

// Remove is a destructive control, so it lives in the card's body: an operator scans ten collapsed
// faces and must not be able to hit it from one.
func TestRemoveButtonIsBuiltIntoTheCardBodyNotItsCollapsedFace(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	for _, want := range []string{
		`acts.appendChild(removeBtn(a))`, `foot.appendChild(acts)`, `body.appendChild(foot)`,
		`b.id = 'acct-rm-' + a.id;`,
		`b.setAttribute('aria-label', 'Remove the account ' + a.label)`,
		`.acct-acts { display:flex;`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	// The button must not be appended to the card's header or its always-visible brief.
	for _, bad := range []string{
		`top.appendChild(removeBtn(a))`, `brief.appendChild(removeBtn(a))`, `c.appendChild(removeBtn(a))`,
	} {
		if strings.Contains(p, bad) {
			t.Fatalf("Remove is on the collapsed face: %q", bad)
		}
	}
}

func TestRemoveUsesTheNativeDialogAndADeliberateConfirm(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	for _, want := range []string{
		// A native <dialog>, like every other modal on the page.
		`<dialog class="modal" id="acct-rm-dialog" aria-labelledby="acct-rm-h" aria-describedby="acct-rm-body">`,
		`id="acct-rm-body"`, `id="acct-rm-note"`, `id="acct-rm-msg" role="alert"`,
		`id="acct-rm-go"`, `data-close="acct-rm-dialog"`,
		// The dialog names the account rather than asking about "this item".
		`'Remove the stored account "' + a.label + '" from claude-swap?'`,
		// The confirm is its own click, and only it posts.
		`$('#acct-rm-go').addEventListener('click', doRemove);`,
		`call('POST', '/api/accounts/remove', { account: id, force: false })`,
		// Opening and closing go through the shared modal helpers, so focus returns to the opener.
		`openModal('#acct-rm-dialog');`,
		`$('#acct-rm-dialog').addEventListener('close', function () { removing = null; });`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	// No window.confirm anywhere, and no inline handler: the CSP allows only the nonced script.
	if strings.Contains(p, "window.confirm") || strings.Contains(p, " confirm(") {
		t.Fatal("the removal must not use window.confirm")
	}
	if strings.Contains(p, "onclick=") {
		t.Fatal("no inline handlers: the CSP is script-src 'nonce-...' only")
	}
}

// The 409 is the only refusal with a fact behind it. The UI says which host and what to do first,
// and offers no way past it: a second "Remove anyway" button beside a destructive action is how an
// operator deletes the only stored copy of a login a host is still running.
func TestHeldLiveRefusalNamesTheHostAndOffersNoForce(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	for _, want := range []string{
		`if (e.status === 409 && e.data && e.data.heldBy) {`,
		`'Held by ' + e.data.heldBy + ', swap that host to another account first.'`,
		// The status and the body ride along on the error, or the host name never reaches here.
		`err.status = r.status; err.data = j;`,
		// A spent confirm must not keep the focus: a disabled button drops it to the body.
		`$('#acct-rm-cancel').focus();`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	if strings.Contains(p, "force: true") || strings.Contains(p, "Remove anyway") {
		t.Fatal("the UI must not offer a force path")
	}
}

// Feedback goes into the live region that was already in the page's shell. A region created in the
// same pass as its text is not reliably announced, and the removed account's card is gone.
func TestRemovalFeedbackUsesTheExistingLiveRegion(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	p := page(r, r.login())
	if !strings.Contains(p, `sayAcc('Removed the account ' + label + '.')`) {
		t.Fatal("a successful removal must say so in the panel's live region")
	}
	if !strings.Contains(p, `<span class="say" id="acc-refresh-status" role="status" aria-atomic="true">`) {
		t.Fatal("the live region must be the one already in the shell")
	}
	// The error path writes into the dialog's own role="alert" line, not into the card subtree.
	if !strings.Contains(p, `msg.textContent = e.message;`) {
		t.Fatal("a failed removal must report into the dialog")
	}
	// A busy confirm says so in words, as every other busy control on the page does.
	if !strings.Contains(p, `setBusy(go, true, 'Remove account', 'Removing...', null)`) {
		t.Fatal("the confirm must show a busy state")
	}
	// The dialog hands focus back to the button that opened it, and that button was on the card
	// that has just gone. Without this, focus lands on the body.
	if !strings.Contains(p, `$('#acc-expand-all').focus();`) {
		t.Fatal("focus must land on a surviving control after the card is removed")
	}
}

// The poll must not rebuild the cards while the dialog is open: it would replace the button the
// dialog returns focus to.
func TestAutomaticPollDefersToAnOpenRemoveDialog(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())
	for _, want := range []string{
		`if (removing && $('#acct-rm-dialog').open) return;`,
		`!confirming && !removing && !ctlWorking()`,
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
