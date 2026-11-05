package agent

import (
	"testing"
	"time"

	"claude-utilities/internal/logx"
)

// The agent dials the server through a reverse SSH tunnel to 127.0.0.1, so while the tunnel is
// down the dial fails instantly and locally: no remote server is spared by a 60 s cap, and the
// cap is what pins kill-to-connected near 78 s. A loopback server URL therefore gets a much
// lower cap. Any other deployment keeps 60 s.

func TestLoopbackDelayCapsAtFifteenSeconds(t *testing.T) {
	for attempt := 0; attempt < 40; attempt++ {
		nominal := time.Duration(1<<min(attempt, 10)) * time.Second
		if nominal > LoopbackMaxDelay {
			nominal = LoopbackMaxDelay
		}
		for i := 0; i < 20; i++ {
			d := NextDelayLoopback(attempt)
			if d > nominal || d < nominal*8/10 {
				t.Fatalf("attempt %d: %v outside [%v, %v]", attempt, d, nominal*8/10, nominal)
			}
		}
	}
	for _, a := range []int{-5, 1 << 30} {
		if d := NextDelayLoopback(a); d <= 0 || d > LoopbackMaxDelay {
			t.Fatalf("attempt %d: %v", a, d)
		}
	}
}

// The loopback cap must be a genuine improvement on the default, not a cosmetic one: the whole
// point is cutting the agent half of kill-to-connected.
func TestLoopbackCapIsLowerThanTheDefault(t *testing.T) {
	if LoopbackMaxDelay >= 60*time.Second || LoopbackMaxDelay < 10*time.Second {
		t.Fatalf("LoopbackMaxDelay = %v, want 10-15 s", LoopbackMaxDelay)
	}
}

func TestLoopbackServerURL(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://127.0.0.1:8443", true},
		{"https://127.0.0.1:8443/", true},
		{"https://127.0.0.2:8443", true},
		{"https://localhost:8443", true},
		{"https://LOCALHOST:8443", true},
		{"https://[::1]:8443", true},
		{"https://10.0.0.5:8443", false},
		{"https://host.example.internal:8443", false},
		{"https://192.168.1.10:8443", false},
		{"", false},
		{"://nonsense", false},
		{"https://127.0.0.1.example.com:8443", false},
	} {
		if got := loopbackServerURL(tc.url); got != tc.want {
			t.Errorf("loopbackServerURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// The wiring, not just the helper: an agent configured with a loopback server URL must actually
// use the lower cap, and one configured with a routable address must not.
func TestNewAgentPicksTheDelayFromTheServerURL(t *testing.T) {
	loop := newAgent(Config{ServerURL: "https://127.0.0.1:8443", Token: "t"}, logx.New(&syncBuf{}))
	for i := 0; i < 20; i++ {
		if d := loop.delay(30); d > LoopbackMaxDelay {
			t.Fatalf("loopback agent waited %v, want <= %v", d, LoopbackMaxDelay)
		}
	}
	remote := newAgent(Config{ServerURL: "https://host.example.internal:8443", Token: "t"}, logx.New(&syncBuf{}))
	var sawAboveLoopback bool
	for i := 0; i < 50; i++ {
		d := remote.delay(30)
		if d > 60*time.Second {
			t.Fatalf("remote agent waited %v, want <= 60s", d)
		}
		if d > LoopbackMaxDelay {
			sawAboveLoopback = true
		}
	}
	if !sawAboveLoopback {
		t.Fatal("a non-loopback server URL must keep the 60 s cap")
	}
}
