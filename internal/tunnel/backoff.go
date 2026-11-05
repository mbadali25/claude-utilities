package tunnel

import (
	"math/rand/v2"
	"time"
)

const (
	baseDelay = time.Second
	// MaxDelay caps the wait between respawns. The interim PowerShell supervisor waited a flat
	// 15 s before every restart; starting at 1 s cuts the supervisor half of kill-to-connected
	// from ~18 s to ~3 s, while the cap still keeps a dead host from being hammered.
	MaxDelay = 30 * time.Second
	// jitterFloor is the lowest fraction of the nominal delay a jittered wait can be.
	jitterFloor = 0.8
	// graceWindow is how long a child must stay alive before the state becomes up. It deliberately
	// means "the process survived", not "the forward is established": proving the latter needs an
	// `ssh -v` stderr parse, and that text carries addresses.
	graceWindow = 3 * time.Second
	// stableAfter is how long a child must stay up before the attempt counter resets.
	stableAfter = 60 * time.Second
)

// NextDelay returns the wait before respawn attempt number attempt (0 is the first retry):
// 1 s doubling to MaxDelay, then reduced by up to 20% so a fleet does not redial in step.
// The result never exceeds the cap, and a negative attempt is treated as 0.
func NextDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := MaxDelay
	// 1s << 5 = 32s already passes the cap, so larger shifts need no computing (and cannot overflow).
	if attempt < 5 {
		d = min(baseDelay<<uint(attempt), MaxDelay)
	}
	f := jitterFloor + rand.Float64()*(1-jitterFloor) // #nosec G404 -- respawn jitter, not a security value
	return time.Duration(float64(d) * f)
}
