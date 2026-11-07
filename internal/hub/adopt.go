package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

// adoptEvery is how often Run asks each online host for its live login.
const adoptEvery = 2 * time.Minute

// adoptDueLocked returns the online hosts not asked within adoptEvery and marks them asked.
// Callers hold h.mu.
func (h *Hub) adoptDueLocked(now time.Time) []string {
	var due []string
	for id, ho := range h.hosts {
		if ho.c == nil || ho.Revoked || now.Sub(ho.lastAdopt) < adoptEvery {
			continue
		}
		ho.lastAdopt = now
		due = append(due, id)
	}
	sort.Strings(due)
	return due
}

// adoptSweep adopts rotated logins from the hosts that are due, each in its own goroutine so a slow
// host cannot hold up the sweep. Failures are logged without the error text of the agent.
func (h *Hub) adoptSweep(ctx context.Context, ids []string) {
	for _, id := range ids {
		go func() {
			cctx, cancel := context.WithTimeout(ctx, h.reqTimeout)
			defer cancel()
			if err := h.AdoptHeld(cctx, id); err != nil && ctx.Err() == nil {
				h.log.Warn("adopt failed", "action", "adopt", "host_id", id, "result", "error", logx.Err(err))
			}
		}()
	}
}

// AdoptHeld asks one host for its live login (the existing export channel) and, when that host is
// the Active holder of a stored account and the login is demonstrably the same line as the stored
// one, stores the rotated claudeAiOauth block in the vault. Claude Code rotates the refresh token on
// use, so without this the vault copy of a held account goes "unauthorized".
//
// The proof of continuity is the host's recorded lineage (hash of the refresh token it last held,
// set by an export or an accepted swap): it must equal the stored block's hash. A rotated token no
// longer matches the stored one directly, so plain sameLineage cannot be the test; the host's
// previous token is. Nothing is written for a host that is not the Active holder, for a lineage the
// hub cannot vouch for, or for an identical block. No token or identity is logged.
func (h *Hub) AdoptHeld(ctx context.Context, hostID string) error {
	h.mu.Lock()
	ho := h.hosts[hostID]
	known := ho != nil && !ho.Revoked
	h.mu.Unlock()
	if !known {
		return ErrUnknownHost
	}
	ho.swapMu.Lock() // serialise with swaps and imports on this host
	defer ho.swapMu.Unlock()

	h.mu.Lock()
	c := ho.c
	h.mu.Unlock()
	if c == nil {
		return ErrAgentOffline
	}
	raw, err := h.request(ctx, c, proto.TypeExportReq, proto.TypeExportRes, nil)
	if err != nil {
		return err
	}
	var exp proto.ExportRes
	if err := json.Unmarshal(raw, &exp); err != nil {
		return fmt.Errorf("hub: bad export reply: %w", err)
	}
	if exp.Err != "" {
		return fmt.Errorf("hub: export failed: %s", logx.Redact(exp.Err))
	}
	block, err := oauthBlock(exp.Block)
	if err != nil {
		return err
	}
	newLineage := lineageHash(block)

	h.mu.Lock()
	prevLineage := ho.lineage
	h.mu.Unlock()

	accts := h.vault.List()
	for _, acct := range accts {
		if st, holds := h.reg.HostsUsing(acct.ID)[hostID]; !holds || st != ownership.Active {
			continue
		}
		storedLineage := lineageHash(acct.Block)
		if storedLineage == "" {
			continue
		}
		if sameLineage(block, acct.Block) {
			// Same refresh token: nothing rotated. Record the proof so the next rotation is adoptable.
			h.mu.Lock()
			ho.lineage = newLineage
			h.mu.Unlock()
			if string(block) == string(acct.Block) {
				return nil
			}
			return h.adopt(hostID, ho, acct.ID, block, newLineage)
		}
		if otherStoredLineage(accts, acct.ID, block) {
			// The login is demonstrably another stored account's, not a rotation of this one.
			h.log.Warn("adopt skipped", "action", "adopt", "host_id", hostID, "account", acct.ID,
				"result", "skipped", "reason", "other_account_lineage")
			continue
		}
		if prevLineage != storedLineage || newLineage == "" {
			h.log.Warn("adopt skipped", "action", "adopt", "host_id", hostID, "account", acct.ID,
				"result", "skipped", "reason", "lineage_unproven")
			continue
		}
		return h.adopt(hostID, ho, acct.ID, block, newLineage)
	}
	return nil
}

// otherStoredLineage reports whether block's refresh token is the stored login of an account other
// than self, which proves the host holds that account and not a rotation of self.
func otherStoredLineage(accts []vault.Account, self string, block json.RawMessage) bool {
	for _, a := range accts {
		if a.ID != self && sameLineage(block, a.Block) {
			return true
		}
	}
	return false
}

// adopt writes the rotated block through the vault's backed-up replace, moves the host's lineage
// with it, and tells the poller (the SetOnReplaced hook) so the account is polled with its new token.
func (h *Hub) adopt(hostID string, ho *host, accountID string, block json.RawMessage, lineage string) error {
	if err := h.vault.ReplaceBlock(accountID, block, h.now()); err != nil {
		return fmt.Errorf("hub: adopt rotated login: %w", err)
	}
	h.mu.Lock()
	ho.lineage = lineage
	fn := h.onReplaced
	h.mu.Unlock()
	h.log.Info("adopted rotated login", "action", "adopt", "host_id", hostID, "account", accountID, "result", "adopted")
	if fn != nil {
		fn(accountID)
	}
	return nil
}
