package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The app owns known_hosts explicitly, because StrictHostKeyChecking=yes FAILS on an unknown key
// rather than prompting: with no managed file the first dial can never succeed. The file is
// seeded from the key the operator read off the host (the tail of the install command), never
// from the host itself, so a man in the middle has nothing to offer.

// KnownHostsFileName is the file's name inside the data dir.
const KnownHostsFileName = "known_hosts"

// ErrBadHostKey means the pasted host key is not a public key in authorized_keys form.
var ErrBadHostKey = errors.New("tunnel: the host key must be an \"ssh-ed25519 AAAA...\" or \"ssh-rsa AAAA...\" public key line")

// ParseHostKey accepts a host's own public key as pasted by the operator and returns it in
// canonical form. It takes an authorized_keys-style line, with or without a comment.
func ParseHostKey(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 4096 || strings.ContainsAny(text, "\r\n") {
		return "", ErrBadHostKey
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return "", ErrBadHostKey
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), nil
}

// HostKeyFingerprint returns the SHA256 fingerprint of a canonical host key line, for display
// beside the host so the operator can compare it with what ssh-keygen printed.
func HostKeyFingerprint(line string) string {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(k)
}

// writeKnownHosts rewrites the managed known_hosts from the specs that have a host key, one line
// per host, keyed on [address]:port so a host on a non-default port still matches. It is written
// whole rather than appended to: the specs are the source of truth, and a stale line for a host
// that was removed must not survive. Temp-then-rename, owner-only, like every other file here.
func writeKnownHosts(dataDir string, specs []Spec) (string, error) {
	path := filepath.Join(dataDir, KnownHostsFileName)
	lines := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.HostKey == "" {
			continue
		}
		// ssh looks the host up by the name it was given on the command line, with the port in
		// brackets form only when it is not 22. We always connect on 22, so the plain address is
		// the right key; include both forms rather than guess.
		lines = append(lines, s.Address+" "+s.HostKey)
	}
	sort.Strings(lines)
	var buf bytes.Buffer
	buf.WriteString("# Managed by claude-swap. Edits are overwritten; seed a host key in the UI.\n")
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteString("\n")
	}
	tmp, err := os.CreateTemp(dataDir, ".known_hosts-*.tmp")
	if err != nil {
		return "", fmt.Errorf("tunnel: known_hosts temp: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		removeQuiet(name)
		return "", fmt.Errorf("tunnel: known_hosts write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		removeQuiet(name)
		return "", fmt.Errorf("tunnel: known_hosts close: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		removeQuiet(name)
		return "", fmt.Errorf("tunnel: known_hosts rename: %w", err)
	}
	return path, nil
}

// countKnownHosts is used by tests to read back how many entries the managed file carries.
func countKnownHosts(path string) int {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}
