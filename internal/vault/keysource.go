package vault

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// A KeySource is how a process says which keys it may use to open a sealed file, and it replaced
// the environment-variable *name* that Open and OpenKeyring used to take.
//
// The name had to go because a service has no passphrase in its environment by design: handing it
// one would put the vault's passphrase in a unit file or a registry value, which is the mistake the
// machine-held key slots exist to avoid. A signature that can only say "read variable X" leaves no
// way to express "this process has no passphrase and must succeed on a machine slot", and keeping
// the old signature as a second way in is exactly how that mistake comes back. Decided by Matthew
// on 2026-11-08 (decision O1): replace the signatures, do not wrap them.
//
// EnvKey is the adapter that keeps every console run and every test on the behaviour it had,
// including the error text.
type KeySource interface {
	// Passphrase returns the passphrase, or an error wrapping ErrNoKey when this process has none.
	// It is called at most once per Open: argon2id is deliberately expensive, and a prompting
	// source asked twice would ask an operator twice for one open.
	Passphrase() (string, error)
	// Machine returns the machine-held unwrappers available on this host, in try order. A v1 file
	// has no key slots, so nothing reaches these until the v2 header lands (Task 3a.2).
	Machine() []SlotOpener
}

// A SlotOpener recovers the data encryption key from one machine-held key slot: DPAPI on Windows,
// a KEK file under a credentials directory on Linux. The openers themselves are Tasks 3a.5 and
// 3a.6; this file declares the interface so the KeySource contract is complete.
type SlotOpener interface {
	// Type names the slot kind this opener handles ("dpapi", "kek-file"). It is the only thing
	// about a slot that may be logged or printed: never a value, never a wrapped key.
	Type() string
	// Unwrap returns the data encryption key held in slot, or an error wrapping ErrBadKey when
	// this opener cannot recover it and the next slot should be tried.
	Unwrap(slot Slot, aad []byte) ([]byte, error)
}

// Slot is one key slot from a v2 header. Task 3a.2 owns its fields and is the authority on them;
// it is declared here, opaque, because SlotOpener names it and nothing in this binary parses or
// writes a v2 header yet.
type Slot struct{}

// envKey reads a passphrase from a named environment variable. The zero machine openers are the
// point: a console run has a passphrase and needs no machine slot, so the fall-through to the
// passphrase is the only path it ever takes.
type envKey struct{ name string }

// EnvKey keeps the behaviour Open had before it took a KeySource: Passphrase is the value of the
// named environment variable, an unset or empty variable is ErrNoKey with the variable's name in
// the message, and Machine is nil. Every existing call site passes this and nothing about it
// changes - the error text included, which is what the vault and keyring tests assert.
func EnvKey(name string) KeySource { return envKey{name: name} }

func (e envKey) Passphrase() (string, error) {
	pass := os.Getenv(e.name)
	if pass == "" {
		return "", fmt.Errorf("%w: set environment variable %s", ErrNoKey, e.name)
	}
	return pass, nil
}

func (e envKey) Machine() []SlotOpener { return nil }

// promptKey reads the passphrase from a terminal with no echo, or one line of stdin when stdin is
// not a terminal, exactly as `server set-password` reads a password. It has no machine openers for
// the same reason EnvKey has none: an operator at a console has the passphrase.
type promptKey struct{ in io.Reader }

// PromptKey returns a KeySource that asks for the passphrase interactively. It is for the operator
// CLI; a service must never be given one, because a service has no terminal and a prompt there
// would either block or silently read whatever stdin happens to be.
func PromptKey(in io.Reader) KeySource { return promptKey{in: in} }

// maxStdinPassphrase bounds a piped passphrase so a stuck or hostile producer cannot be read
// forever. Same bound, same reason, as cmd/server's piped password.
const maxStdinPassphrase = 4 << 10

func (p promptKey) Passphrase() (string, error) {
	if f, ok := p.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		// The prompt goes to stderr, not stdout: stdout may be a pipe a caller is parsing.
		_, _ = fmt.Fprint(os.Stderr, "Vault passphrase (not echoed): ")
		line, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("%w: read passphrase: %w", ErrNoKey, err)
		}
		if len(line) == 0 {
			return "", fmt.Errorf("%w: no passphrase entered", ErrNoKey)
		}
		return string(line), nil
	}
	// Not a terminal: exactly one line, so a trailing newline from `echo` is not part of it.
	br := bufio.NewReader(io.LimitReader(p.in, maxStdinPassphrase))
	line, err := br.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", fmt.Errorf("%w: no passphrase on stdin", ErrNoKey)
	}
	pass := strings.TrimRight(line, "\r\n")
	if pass == "" {
		return "", fmt.Errorf("%w: no passphrase on stdin", ErrNoKey)
	}
	return pass, nil
}

func (p promptKey) Machine() []SlotOpener { return nil }

// HostKeyOptions says where this host's machine-held key material may be found. CredentialName is
// the file name to look for under $CREDENTIALS_DIRECTORY (systemd's LoadCredentialEncrypted),
// KEKFile is an explicit path from --kek-file, and AllowRootCredsDecrypt opts into the root-only
// `systemd-creds decrypt` route.
type HostKeyOptions struct {
	CredentialName        string
	KEKFile               string
	AllowRootCredsDecrypt bool
}

// HostKeys returns the machine openers for this host, in try order, or nil when this host has
// none. nil is what makes the passphrase fall-through work, and it is what this binary always
// returns: the dpapi opener is Task 3a.5 and the kek-file opener is Task 3a.6, and a v1 header has
// no slots for either of them to unwrap. The signature is here so the entry points of slice 4 can
// be written against it without another public-interface change.
func HostKeys(_ HostKeyOptions) []SlotOpener { return nil }
