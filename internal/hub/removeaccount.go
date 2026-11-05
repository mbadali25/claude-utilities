package hub

import (
	"errors"
	"sort"

	"claude-utilities/internal/vault"
)

// This is the one destructive account operation, and the whole of it is local: the vault, the
// ownership table and (through the caller) the usage poller. It sends NO frame to any agent and
// reads no host's credentials file. Removing the server's stored copy of a login is not the same
// as signing a host out, and claude-swap deliberately cannot do the second: a host keeps whatever
// login it is holding, and the operator swaps it away first if that is what they want.

// ErrAccountHeldLive means an online host is signed in as the account, so removing the server's
// copy would leave that login running on a host with no stored copy to swap back to.
var ErrAccountHeldLive = errors.New("hub: an online host is signed in as this account")

// HeldLiveError names the host that holds the account. The name is agent-supplied text, so a UI
// must escape it; it is never logged (host_id is).
type HeldLiveError struct {
	HostID   string
	HostName string
}

func (e *HeldLiveError) Error() string {
	return ErrAccountHeldLive.Error() + ": " + e.HostName
}

func (e *HeldLiveError) Is(target error) bool { return target == ErrAccountHeldLive }

// HeldBy returns the host that refused a removal, or false when err is not a held-live refusal.
func HeldBy(err error) (*HeldLiveError, bool) {
	var e *HeldLiveError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// RemoveAccount deletes a stored account: its vault entry, its ownership record, and nothing else.
// An unknown id is ErrUnknownAccount.
//
// Unless force is set, it is refused with a *HeldLiveError when an online host is signed in as the
// account, naming that host. force exists for the case where the hub's view is wrong - a host that
// reports an identity it no longer has - and is not offered in the UI; see the runbook.
//
// No agent is contacted, before or after. A host already holding this login keeps it, which is why
// the refusal is the default: without the stored copy there is nothing left to swap that host onto.
func (h *Hub) RemoveAccount(accountID string, force bool) error {
	acct, ok := h.vault.Get(accountID)
	if !ok {
		return ErrUnknownAccount
	}
	if !force {
		if held := h.heldLive(acct.Identity); held != nil {
			h.log.Warn("account removal refused", "action", "remove_account", "account", accountID,
				"host_id", held.HostID, "result", "refused", "reason", "an online host is signed in as it")
			return held
		}
	}
	if err := h.vault.Delete(accountID); err != nil {
		// Only a racing second removal gets here: Get above already found the account.
		if errors.Is(err, vault.ErrNotFound) {
			return ErrUnknownAccount
		}
		return err
	}
	h.reg.Forget(accountID)
	result := "ok"
	if force {
		result = "ok, forced"
	}
	h.log.Warn("account removed", "action", "remove_account", "account", accountID, "result", result)
	return nil
}

// heldLive returns the online host signed in as identity, or nil. It reads the same state Hosts()
// reports as Online and ActiveAccount, so the refusal and the card the operator is looking at can
// never disagree. An account with no identity can match no host.
//
// Lowest host name wins, then lowest id: map order is random, and a refusal that names a different
// host on each attempt is not something an operator can act on.
func (h *Hub) heldLive(identity string) *HeldLiveError {
	if identity == "" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(h.now())
	var found []*HeldLiveError
	for _, ho := range h.hosts {
		if ho.Revoked || ho.c == nil || ho.identity != identity {
			continue
		}
		found = append(found, &HeldLiveError{HostID: ho.ID, HostName: ho.Name})
	}
	if len(found) == 0 {
		return nil
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].HostName != found[j].HostName {
			return found[i].HostName < found[j].HostName
		}
		return found[i].HostID < found[j].HostID
	})
	return found[0]
}
