package tunnel

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Keys is the key material the supervisor needs. *vault.Keyring satisfies it. Seed hands out
// private key bytes and is called from exactly one place - the ephemeral key file in spawn.go.
// No HTTP handler, log line or error string may ever reach it.
type Keys interface {
	Seed(hostID string) ([]byte, bool)
	PublicKey(hostID string) (cur, prev ed25519.PublicKey, ok bool)
}

// SSHPublicKey wraps an ed25519 public key in the ssh wire type, which is what an
// authorized_keys line and a fingerprint are computed from.
func SSHPublicKey(pub ed25519.PublicKey) (ssh.PublicKey, error) {
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("tunnel: public key: %w", err)
	}
	return k, nil
}

// Fingerprint returns the SHA256:<base64> form, byte for byte what `ssh-keygen -lf` prints, so an
// operator can compare it against the host.
func Fingerprint(pub ed25519.PublicKey) (string, error) {
	k, err := SSHPublicKey(pub)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(k), nil
}

// FingerprintKey is Fingerprint for a key already in ssh wire form.
func FingerprintKey(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// Short is the first 8 characters of the fingerprint's base64 body, the form the Hosts tab shows
// beside a host - the same convention the enrolment fingerprint already uses.
func Short(fingerprint string) string {
	body := fingerprint
	if len(body) > 7 && body[:7] == "SHA256:" {
		body = body[7:]
	}
	if len(body) > 8 {
		body = body[:8]
	}
	return body
}

// encodePrivateKey encodes a seed as an OpenSSH private key, unencrypted. There is no passphrase
// by design: the key at rest lives inside the encrypted keyring, and this encoding exists only
// for the few seconds a child holds the file open. A passphrase here would have to be stored
// somewhere to be typed, which is no gain.
func encodePrivateKey(seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("tunnel: bad seed length %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("tunnel: encode private key: %w", err)
	}
	return pem.EncodeToMemory(blk), nil
}
