package usage

import (
	"context"

	"claude-utilities/internal/vault"
)

// pollOnce polls every account that is due, one after another and with the global spacing turned
// off, so a test sees one round of the schedule without simulating the gaps between requests.
func (p *Poller) pollOnce(ctx context.Context, accounts func() []vault.Account, onUpdate func(string, Usage)) {
	p.SetAccounts(accounts)
	p.mu.Lock()
	saved := p.cfg.MinSpacing
	p.cfg.MinSpacing = 0
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.cfg.MinSpacing = saved
		p.mu.Unlock()
	}()
	for {
		if polled, _ := p.step(ctx, onUpdate); !polled {
			return
		}
	}
}
