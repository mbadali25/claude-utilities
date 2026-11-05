package tunnel

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// This file builds strings only. The server never logs in to a host and holds no host
// credential: the operator pastes the generated one-liner on the host themselves (addendum
// section 3, option C). Nothing here can touch a host, and nothing here sees a private key.

// comment is the authorized_keys comment field, so a line says which host it is for.
func comment(label string) string { return "claude-swap-tunnel-" + label }

// options returns the restricted option list for one line.
//
// Order is load-bearing: a later option beats an earlier one, so `restrict` (deny everything,
// including capabilities OpenSSH has not invented yet) must come before `port-forwarding`, which
// re-enables forwarding only.
//
// tighten adds permitopen="127.0.0.1:1", a deliberately dead destination, to close the -L gap:
// `port-forwarding` re-enables both -R and -L, and permitlisten constrains only the -R listen
// address, so without it a stolen key is an outbound pivot into the host's network. It is OFF by
// default because it is UNVERIFIED - whether it neuters -L while leaving the -R forward working
// needs a spike on a real host (addendum open question 1).
func options(port int, tighten bool) string {
	opts := []string{`command="/bin/false"`, "restrict", "port-forwarding"}
	if tighten {
		opts = append(opts, `permitopen="127.0.0.1:1"`)
	}
	opts = append(opts, fmt.Sprintf(`permitlisten="127.0.0.1:%d"`, port))
	return strings.Join(opts, ",")
}

// keyBody returns the "ssh-ed25519 AAAA..." part of an authorized_keys line: the type and the
// base64 body, without a comment. It is the grep -F needle the generated commands match on, so
// adding or removing a line is idempotent whatever the comment says.
func keyBody(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// Line returns the whole authorized_keys line for one host.
func Line(pub ssh.PublicKey, label string, port int, tighten bool) string {
	return options(port, tighten) + " " + keyBody(pub) + " " + comment(label)
}

// hostKeyProbe prints the host's OWN public key fingerprint, which the operator pastes back into
// the UI to seed known_hosts. StrictHostKeyChecking=yes fails rather than prompts, so without
// this the first dial cannot succeed.
const hostKeyProbe = `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`

// InstallCommand returns the one line the host operator pastes to authorise this key. It is
// idempotent on the key body, creates ~/.ssh with mode 0700 and the file with 0600, keeps every
// line already there, and ends by printing the host's own fingerprint.
//
// The public key body is base64 and the label is validated to [A-Za-z0-9._-], so no value here
// can contain a quote, whitespace or a shell metacharacter; Validate refuses one rather than
// escaping it.
func InstallCommand(pub ssh.PublicKey, label string, port int, tighten bool) string {
	k := keyBody(pub)
	line := options(port, tighten) + " '\"$K\"' " + comment(label)
	return "umask 077; mkdir -p ~/.ssh; K='" + k + "'; L='" + line + "'; " +
		`grep -qF "$K" ~/.ssh/authorized_keys 2>/dev/null || printf '%s\n' "$L" >> ~/.ssh/authorized_keys; ` +
		"chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; " + hostKeyProbe
}

// RemoveCommand returns the matching one line that takes the key out again. It leaves every other
// line in the file alone, writes temp-then-rename rather than editing in place, and is a no-op
// when the file or the line is already gone.
func RemoveCommand(pub ssh.PublicKey) string {
	k := keyBody(pub)
	return "umask 077; [ -f ~/.ssh/authorized_keys ] || exit 0; K='" + k + "'; " +
		`T="$(mktemp ~/.ssh/ak.XXXXXX)"; grep -vF "$K" ~/.ssh/authorized_keys > "$T"; ` +
		`chmod 600 "$T"; mv "$T" ~/.ssh/authorized_keys`
}
