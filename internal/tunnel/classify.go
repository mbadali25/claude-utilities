package tunnel

import (
	"fmt"
	"regexp"
	"strings"
)

// Reason is the fixed vocabulary for why a tunnel child exited. It is what the UI shows and what
// the log records: ssh's own stderr is never kept, because it carries the host address and the
// username and logx.Redact knows nothing about either.
type Reason string

const (
	ReasonAuthDenied       Reason = "auth_denied"
	ReasonHostkeyMismatch  Reason = "hostkey_mismatch"
	ReasonHostkeyUnknown   Reason = "hostkey_unknown"
	ReasonForwardRefused   Reason = "forward_refused"
	ReasonUnreachable      Reason = "unreachable"
	ReasonExecFailed       Reason = "exec_failed"
	ReasonKilled           Reason = "killed"
	ReasonStopped          Reason = "stopped"
	ReasonNoKey            Reason = "no_key"
	ReasonHostkeyNotSeeded Reason = "hostkey_not_seeded"
)

// terminal reasons stop the retry loop: nothing changes by dialling again, and a restart loop on
// a denied key is just noise. The UI shows the code and offers Restart.
var terminal = map[Reason]bool{
	ReasonAuthDenied:       true,
	ReasonHostkeyMismatch:  true,
	ReasonHostkeyUnknown:   true,
	ReasonExecFailed:       true,
	ReasonNoKey:            true,
	ReasonHostkeyNotSeeded: true,
}

// Retryable reports whether the supervisor should respawn after this reason.
func (r Reason) Retryable() bool { return !terminal[r] }

// sentences are the operator-facing text for each reason. They are fixed strings, never derived
// from ssh output, so no address or username can reach the UI through them.
var sentences = map[Reason]string{
	ReasonAuthDenied:       "the host refused the key; run the install command on it",
	ReasonHostkeyMismatch:  "the host's key changed; confirm the new one before retrying",
	ReasonHostkeyUnknown:   "the host's key is not in the managed known_hosts file",
	ReasonForwardRefused:   "the host already has that port bound; retrying",
	ReasonUnreachable:      "the host did not answer; retrying",
	ReasonExecFailed:       "ssh could not be started on this machine",
	ReasonKilled:           "the tunnel process was killed",
	ReasonStopped:          "stopped by the server",
	ReasonNoKey:            "no tunnel key for this host; generate one",
	ReasonHostkeyNotSeeded: "paste the host's own key fingerprint before enabling the tunnel",
}

// Sentence returns the canned, address-free explanation for a reason.
func (r Reason) Sentence() string {
	if s, ok := sentences[r]; ok {
		return s
	}
	return "the tunnel exited; retrying"
}

// patterns maps ssh stderr to a reason. Order matters: the mismatch banner also contains "host
// key", so it is tested before the generic verification failure.
var patterns = []struct {
	match  string
	reason Reason
}{
	{"remote host identification has changed", ReasonHostkeyMismatch},
	{"host key verification failed", ReasonHostkeyUnknown},
	{"no matching host key", ReasonHostkeyUnknown},
	{"permission denied", ReasonAuthDenied},
	{"too many authentication failures", ReasonAuthDenied},
	{"remote port forwarding failed", ReasonForwardRefused},
	{"administratively prohibited", ReasonForwardRefused},
	{"cannot listen to port", ReasonForwardRefused},
	{"connection refused", ReasonUnreachable},
	{"connection timed out", ReasonUnreachable},
	{"connection closed by remote host", ReasonUnreachable},
	{"operation timed out", ReasonUnreachable},
	{"no route to host", ReasonUnreachable},
	{"network is unreachable", ReasonUnreachable},
	{"could not resolve hostname", ReasonUnreachable},
	{"name or service not known", ReasonUnreachable},
	{"broken pipe", ReasonUnreachable},
	{"timed out", ReasonUnreachable},
}

// Classify maps a child's stderr and exit code to a reason code. The stderr itself is read and
// discarded here and nowhere else: only the returned Reason leaves this function, so the caller
// cannot accidentally keep the text.
func Classify(stderr string, exitCode int) Reason {
	low := strings.ToLower(stderr)
	for _, p := range patterns {
		if strings.Contains(low, p.match) {
			return p.reason
		}
	}
	switch {
	case exitCode == 0:
		// ssh -N exiting 0 means the server closed the session cleanly; dial again.
		return ReasonUnreachable
	case exitCode < 0:
		return ReasonKilled
	}
	return Reason(fmt.Sprintf("exit_%d", exitCode))
}

// ipLiteralRe matches a dotted-quad other than loopback. Loopback is part of the forward spec and
// carries no information about the estate; every other literal is masked.
var ipLiteralRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// maxScrub caps scrubbed text so a surprise error cannot carry a wall of output into a log line.
const maxScrub = 120

// Scrub removes a Spec's address and username, and every non-loopback IP literal, from free text,
// then collapses whitespace and caps the result. It is used on errors raised by this machine (a
// failed exec, a failed key file write), whose text can contain the address or a path. ssh's own
// stderr never goes through here - it is classified and dropped.
func Scrub(text, address, user string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	out := text
	if address != "" {
		out = strings.ReplaceAll(out, address, "<host>")
	}
	if user != "" {
		out = strings.ReplaceAll(out, user, "<user>")
	}
	out = ipLiteralRe.ReplaceAllStringFunc(out, func(m string) string {
		if m == "127.0.0.1" {
			return m
		}
		return "<ip>"
	})
	out = strings.Join(strings.Fields(out), " ")
	if len(out) > maxScrub {
		out = out[:maxScrub]
	}
	return out
}
