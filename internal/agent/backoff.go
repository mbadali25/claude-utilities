package agent

import (
	"math/rand/v2"
	"time"
)

const (
	baseDelay = time.Second
	maxDelay  = 60 * time.Second
	// jitterFloor is the lowest fraction of the nominal delay a jittered wait can be.
	jitterFloor = 0.8
)

// NextDelay returns the wait before reconnect attempt number attempt (0 is the first
// retry): 1 s doubling to a 60 s cap, then reduced by up to 20% so a fleet of agents does
// not redial in step. The result never exceeds the cap.
func NextDelay(attempt int) time.Duration {
	d := maxDelay
	if attempt < 0 {
		attempt = 0
	}
	// 1s << 6 = 64s already passes the cap, so larger shifts need no computing (and cannot overflow).
	if attempt < 6 {
		d = min(baseDelay<<uint(attempt), maxDelay)
	}
	f := jitterFloor + rand.Float64()*(1-jitterFloor)
	return time.Duration(float64(d) * f)
}
