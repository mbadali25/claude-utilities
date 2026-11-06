package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

// Relabel renames a stored account. It maps an unknown id to ErrUnknownAccount and passes
// vault.ErrLabelInvalid / vault.ErrLabelTaken through. Credentials are never touched.
func (h *Hub) Relabel(accountID, label string) error {
	if err := h.vault.Relabel(accountID, label); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return ErrUnknownAccount
		}
		return err
	}
	h.log.Info("account relabelled", "action", "relabel", "account", accountID, "result", "ok")
	return nil
}

// Import pulls the live login from a host and stores it as a new account named label. Only the
// claudeAiOauth block is kept. A login whose identity is already stored is refused (Swap's
// write-back is what refreshes an existing account). The importing host becomes the owner.
func (h *Hub) Import(ctx context.Context, hostID, label string) (vault.Account, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > maxFieldLen {
		return vault.Account{}, errors.New("hub: label must be 1-64 characters")
	}
	h.mu.Lock()
	h.sweepLocked(h.now())
	ho := h.hosts[hostID]
	known := ho != nil && !ho.Revoked
	h.mu.Unlock()
	if !known {
		return vault.Account{}, ErrUnknownHost
	}
	// Serialise with swaps: a swap mid-import would change the live login under us.
	ho.swapMu.Lock()
	defer ho.swapMu.Unlock()
	h.mu.Lock()
	c := ho.c
	h.mu.Unlock()
	if c == nil {
		return vault.Account{}, ErrAgentOffline
	}
	raw, err := h.request(ctx, c, proto.TypeExportReq, proto.TypeExportRes, nil)
	if err != nil {
		return vault.Account{}, err
	}
	var exp proto.ExportRes
	if err := json.Unmarshal(raw, &exp); err != nil {
		return vault.Account{}, fmt.Errorf("hub: bad export reply: %w", err)
	}
	if exp.Err != "" {
		return vault.Account{}, fmt.Errorf("hub: export failed: %s", logx.Redact(exp.Err))
	}
	acct, err := h.storeLogin(label, exp.Identity, exp.Block)
	if err != nil {
		return vault.Account{}, err
	}
	h.reg.SwapIn(acct.ID, hostID)
	h.mu.Lock()
	ho.identity = exp.Identity
	if b, berr := oauthBlock(exp.Block); berr == nil { // the imported account is now live on this host
		ho.lineage = lineageHash(b)
	}
	h.mu.Unlock()
	h.log.Info("login imported", "action", "import", "host_id", hostID, "account", acct.ID, "result", "ok")
	return acct, nil
}

// storeLogin validates a login an agent produced and stores it as a new account: an identity is
// required and must not already be stored, the label must still be free, and only the claudeAiOauth
// block is kept. It claims no ownership. The returned account has no Block.
//
// The label is re-checked here, not only by the caller: an add-account sign-in waits for the owner
// for up to 10 minutes, and an import or a rename can take the label in that window.
func (h *Hub) storeLogin(label, identity string, raw json.RawMessage) (vault.Account, error) {
	if identity == "" {
		return vault.Account{}, errors.New("hub: the host reports no signed-in account")
	}
	stored := h.vault.List()
	for _, a := range stored {
		if a.Identity == identity {
			return vault.Account{}, ErrAlreadyStored
		}
	}
	for _, a := range stored {
		if strings.EqualFold(a.Label, label) {
			return vault.Account{}, vault.ErrLabelTaken
		}
	}
	block, err := oauthBlock(raw)
	if err != nil {
		return vault.Account{}, err
	}
	id, err := randHex(8)
	if err != nil {
		return vault.Account{}, err
	}
	acct := vault.Account{ID: id, Label: label, Identity: identity, Block: block, Updated: h.now()}
	if err := h.vault.Put(acct); err != nil {
		return vault.Account{}, fmt.Errorf("hub: store login: %w", err)
	}
	acct.Block = nil
	return acct, nil
}
