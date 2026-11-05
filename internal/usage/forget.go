package usage

// Forgetter drops every trace of one account from a poller. Removing a stored account is the only
// caller: once the vault no longer has the account, the poller must not keep its windows, its
// failure count or its backoff, or a later account reusing the id would inherit them. A poll of
// that account already in flight is silenced: its answer is neither stored nor reported.
type Forgetter interface {
	Forget(accountID string)
}

var _ Forgetter = (*Poller)(nil)
