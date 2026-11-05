// Package ownership tracks which party holds the authoritative copy of each
// account's tokens. It is pure in-memory state with no I/O.
package ownership

import "sync"

// Owner is the party that owns an account's live token.
type Owner struct {
	Server bool
	HostID string
}

// HostState is a host's relationship to an account it uses.
type HostState int

const (
	// Active: the host owns the account's live token.
	Active HostState = iota
	// Shared: the host uses the account but another host owns it.
	Shared
	// Stale: the owning host was lost; remaining users hold a possibly outdated copy.
	Stale
)

type account struct {
	holders        []string // oldest first; most recent holder last
	stale          bool
	needsWriteback bool
}

func (a *account) indexOf(host string) int {
	for i, h := range a.holders {
		if h == host {
			return i
		}
	}
	return -1
}

// Registry is a concurrency-safe ownership table.
type Registry struct {
	mu       sync.Mutex
	accounts map[string]*account
}

// New returns an empty Registry; every account starts owned by the server.
func New() *Registry {
	return &Registry{accounts: map[string]*account{}}
}

// SwapIn makes host the owner of account; previous holders become Shared.
func (r *Registry) SwapIn(acct, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.accounts[acct]
	if a == nil {
		a = &account{}
		r.accounts[acct] = a
	}
	if i := a.indexOf(host); i >= 0 {
		a.holders = append(a.holders[:i], a.holders[i+1:]...)
	}
	a.holders = append(a.holders, host)
	a.stale = false
	a.needsWriteback = false
}

// SwapAway records that host stopped using account.
func (r *Registry) SwapAway(acct, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remove(acct, host)
}

func (r *Registry) remove(acct, host string) {
	a := r.accounts[acct]
	if a == nil {
		return
	}
	i := a.indexOf(host)
	if i < 0 {
		return
	}
	a.holders = append(a.holders[:i], a.holders[i+1:]...)
	if len(a.holders) == 0 && !a.needsWriteback {
		delete(r.accounts, acct)
	}
}

// HostLost handles a host disappearing. A lost owner with remaining sharers
// marks the account Stale; a lost sole owner returns it to the server flagged
// for a writeback check.
func (r *Registry) HostLost(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, a := range r.accounts {
		i := a.indexOf(host)
		if i < 0 {
			continue
		}
		wasOwner := i == len(a.holders)-1
		a.holders = append(a.holders[:i], a.holders[i+1:]...)
		switch {
		case wasOwner && len(a.holders) > 0:
			a.stale = true
		case wasOwner:
			a.needsWriteback = true
		}
		if len(a.holders) == 0 && !a.needsWriteback {
			delete(r.accounts, name)
		}
	}
}

// OwnerOf returns the current owner of account.
func (r *Registry) OwnerOf(acct string) Owner {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.accounts[acct]
	if a == nil || len(a.holders) == 0 || a.stale {
		return Owner{Server: true}
	}
	return Owner{HostID: a.holders[len(a.holders)-1]}
}

// NeedsWritebackCheck reports whether the server must verify the token of an
// account whose owning host was lost.
func (r *Registry) NeedsWritebackCheck(acct string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.accounts[acct]
	return a != nil && a.needsWriteback
}

// HostsUsing returns a copy of host -> state for account.
func (r *Registry) HostsUsing(acct string) map[string]HostState {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]HostState{}
	a := r.accounts[acct]
	if a == nil {
		return out
	}
	for i, h := range a.holders {
		switch {
		case a.stale:
			out[h] = Stale
		case i == len(a.holders)-1:
			out[h] = Active
		default:
			out[h] = Shared
		}
	}
	return out
}
