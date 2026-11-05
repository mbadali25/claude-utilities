# Removing a stored account

Use it when an account should no longer be swappable from this server: a login that was retired, one
imported by mistake, or one whose label was a duplicate.

## What removal does, and what it does not

It deletes the account from `vault.bin`, drops its ownership record and drops its usage-poller
state. That is all of it, and all of it is on the server.

**It never touches a host's credentials file.** No frame is sent to any agent, before or after. A
host that is signed in as the account keeps running that login exactly as it was; this server has no
way to sign a host out, and removing the stored copy does not become one.

## In the UI

Expand the account's card (the Remove button is inside the card, not on its collapsed face), click
**Remove**, read the dialog, and click **Remove account**. The panel's status line says
`Removed the account <label>.` on success.

## "Held by &lt;host&gt;, swap that host to another account first"

The server answers `409` while an **online** host is signed in as the account, and names the host.
That is the default and the UI offers no way past it: once the stored copy is gone there is nothing
left to swap that host onto, and this server cannot put the login back on it.

The fix is the normal one: swap that host to another account on the Hosts tab, then remove.

An **offline** or revoked host does not block a removal. Neither does ownership alone: the refusal
follows what the Hosts tab shows as `Online` plus the account it is signed in as, including a host
that still reports its pre-swap identity.

## force, and when it is right

`POST /api/accounts/remove` takes `{"account":"<id>","force":true}`, which skips the held-live check.
It exists for one case: the hub's view of the host is wrong - a host reporting an identity it no
longer has - so the refusal names a host that is not really holding the account. Confirm that on the
host first. There is no button for this; it is a deliberate curl against the admin session.

## Recovering a removal

The vault's previous bytes are kept beside it as `<data-dir>/vault.bin.bak`, in the same sealed
envelope, so `CLAUDESWAP_KEY` opens it. To undo a removal: stop the server, copy `vault.bin.bak`
over `vault.bin`, start it again.

The backup is **one generation deep**. A second removal overwrites it, so recover before removing
anything else. A removal whose backup cannot be written is refused rather than performed.

## Rate limit

Ten removals per source address per minute; over that the route answers `429`. Every attempt, refused
or not, writes an audit line carrying the account id, the action and the result - never the label,
the identity or the host name.
