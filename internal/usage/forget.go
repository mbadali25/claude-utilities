package usage

// Forget is deliberately in its own file and deliberately tiny. The poller's scheduling internals
// are being rewritten (tiered polling, a serialized queue); callers that need to drop one account's
// state go through Forgetter so that rewrite can reimplement this one method without touching them.

// Forgetter drops every trace of one account from a poller. Removing a stored account is the only
// caller: once the vault no longer has the account, the poller must not keep its windows, its
// failure count or its backoff, or a later account reusing the id would inherit them.
type Forgetter interface {
	Forget(accountID string)
}

// Forget drops the account's last answer, failure count, backoff and manual-poll floor. It is a
// no-op for an id the poller never saw, and it never cancels or waits for anything.
//
// A poll already in flight for this account is left alone: it finishes and records its answer, so
// one stale entry can survive this call. That is harmless - the account is gone from the vault, so
// the schedule never visits it again and nothing reads Last for an account the page cannot show -
// and the alternative (a tombstone the in-flight poll has to check) is exactly the kind of state
// the poller rewrite would have to merge.
func (p *Poller) Forget(accountID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.last, accountID)
	delete(p.fails, accountID)
	delete(p.nextAt, accountID)
	delete(p.manualAt, accountID)
}
