// Package tunnel supervises the reverse SSH tunnels that let a Linux host reach a
// loopback-bound claude-swap server, and owns the ed25519 keys they authenticate with.
//
// The server dials out: one `ssh -R 127.0.0.1:P:127.0.0.1:P` child per host, restarted with
// backoff, so the hosts open no inbound port. That `-R` is the only forward a child may carry -
// no -L, no -D, and the user's ssh_config is ignored entirely (see spawn.go).
//
// Nothing here logs a host address, a username, a private key or raw ssh stderr: the address and
// the username are scrubbed before any text is kept (classify.go), and an exit is recorded as one
// of a fixed set of reason codes with a canned sentence.
package tunnel

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Spec is one host's tunnel configuration. Address and User are operator-supplied and
// non-secret, but they identify the estate, so they never reach a log or an API response.
type Spec struct {
	// ID is the stable identifier the UI and the keyring use. It is the enrolled host's id when
	// there is one, else a generated id: a tunnel may exist before its agent is enrolled.
	ID string `json:"id"`
	// Label is the only part of a Spec that may be logged, under the "host" key.
	Label string `json:"label"`
	// Address is a DNS name or an IP literal. Never logged.
	Address string `json:"address"`
	// User is the login on the host. Never logged.
	User string `json:"user"`
	// Port is forwarded on both ends and must match the host's permitlisten option.
	Port int `json:"port"`
	// Enabled is false for a configured tunnel that is switched off in the UI.
	Enabled bool `json:"enabled"`
	// HostKey is the host's own public key in authorized_keys form, used to seed known_hosts.
	// Empty until the operator pastes it back.
	HostKey string `json:"hostKey,omitempty"`
	// RevokedKey is the PUBLIC key body of a key that has been revoked here but whose
	// authorized_keys line is probably still on the host. It is kept so the UI can keep offering
	// the remove command and keep saying so; a cleared field means the operator confirmed.
	RevokedKey string `json:"revokedKey,omitempty"`
}

// DefaultPort is the port the agent dials on the host's loopback and the server listens on.
const DefaultPort = 8443

const (
	maxAddress = 253
	maxLabel   = 32
)

var (
	// ErrBadLabel and friends are validation failures. The web layer maps them to 400.
	ErrBadLabel   = errors.New("tunnel: label must be 1-32 characters of A-Z a-z 0-9 . _ -")
	ErrBadAddress = errors.New("tunnel: address must be a DNS name or an IP literal, 253 characters or fewer")
	ErrBadUser    = errors.New("tunnel: user must match ^[a-z_][a-z0-9_-]{0,31}$")
	ErrBadPort    = errors.New("tunnel: port must be 1-65535")
	ErrUnknown    = errors.New("tunnel: unknown tunnel")
	// ErrRateLimited means the caller is over its budget for this action.
	ErrRateLimited = errors.New("tunnel: too many requests for this host; wait and try again")
)

var (
	labelRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	userRe  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// hostnameRe is deliberately strict: labels of letters, digits and hyphens, no leading or
	// trailing hyphen, an optional trailing dot. Anything else is refused rather than quoted.
	hostnameRe = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$`)
)

// unsafeArg reports whether a value may never reach an ssh argument list, a generated command or
// an authorized_keys line: whitespace, a quote, a backslash, a shell metacharacter, a newline, or
// a leading "-" that ssh would read as a flag.
func unsafeArg(v string) bool {
	if v == "" || strings.HasPrefix(v, "-") {
		return true
	}
	return strings.ContainsAny(v, " \t\r\n\v\f\"'`\\$;&|<>()*?!#~[]{}")
}

// Validate checks every operator-supplied field. It is the only gate between the admin UI and an
// exec.Command argv, so it refuses rather than escapes.
func Validate(s Spec) error {
	if !labelRe.MatchString(s.Label) || unsafeArg(s.Label) {
		return ErrBadLabel
	}
	if !userRe.MatchString(s.User) || unsafeArg(s.User) {
		return ErrBadUser
	}
	if s.Port < 1 || s.Port > 65535 {
		return ErrBadPort
	}
	if len(s.Address) == 0 || len(s.Address) > maxAddress || unsafeArg(s.Address) {
		return ErrBadAddress
	}
	if net.ParseIP(s.Address) == nil && !hostnameRe.MatchString(s.Address) {
		return ErrBadAddress
	}
	return nil
}

// target is the user@address argument. Both parts are validated, so it needs no quoting.
func (s Spec) target() string { return fmt.Sprintf("%s@%s", s.User, s.Address) }
