package agent

import (
	"math/rand/v2"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	baseDelay = time.Second
	maxDelay  = 60 * time.Second
	// LoopbackMaxDelay is the cap used when the configured server URL is loopback. The agent then
	// dials through a reverse SSH tunnel on this host, so a failed dial costs nothing remote and
	// returns at once: a 60 s cap would only lengthen the wait after the tunnel comes back.
	LoopbackMaxDelay = 15 * time.Second
	// jitterFloor is the lowest fraction of the nominal delay a jittered wait can be.
	jitterFloor = 0.8
)

// NextDelay returns the wait before reconnect attempt number attempt (0 is the first
// retry): 1 s doubling to a 60 s cap, then reduced by up to 20% so a fleet of agents does
// not redial in step. The result never exceeds the cap.
func NextDelay(attempt int) time.Duration { return nextDelay(attempt, maxDelay) }

// NextDelayLoopback is NextDelay with the LoopbackMaxDelay cap.
func NextDelayLoopback(attempt int) time.Duration { return nextDelay(attempt, LoopbackMaxDelay) }

func nextDelay(attempt int, cap time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := cap
	// 1s << 6 = 64s already passes any cap here, so larger shifts need no computing (and cannot overflow).
	if attempt < 6 {
		d = min(baseDelay<<uint(attempt), cap)
	}
	f := jitterFloor + rand.Float64()*(1-jitterFloor) // #nosec G404 -- reconnect jitter, not a security value
	return time.Duration(float64(d) * f)
}

// delayFor returns the backoff this agent should redial with: the loopback cap for a loopback
// server URL, the default otherwise. A URL that cannot be parsed keeps the default - the safe
// side is the longer wait.
func delayFor(serverURL string) func(int) time.Duration {
	if loopbackServerURL(serverURL) {
		return NextDelayLoopback
	}
	return NextDelay
}

// loopbackServerURL reports whether the URL's host is a loopback address or the name "localhost".
// Only those two: a name that merely contains "localhost" or starts with "127." is not resolved
// here, and anything unresolvable counts as remote.
func loopbackServerURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
