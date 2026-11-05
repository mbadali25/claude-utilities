package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"claude-utilities/internal/credfile"
)

const (
	certName = "server-cert.pem"
	keyName  = "server-key.pem"
)

// EnsureCert returns the paths of a self-signed server certificate and key in dir, creating
// them on first use, plus the SHA-256 fingerprint (lowercase hex of the DER) agents pin.
// An existing, parseable, unexpired pair is reused so the fingerprint survives restarts.
func EnsureCert(dir string) (certFile, keyFile, fingerprint string, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", fmt.Errorf("hub: cert dir: %w", err)
	}
	certFile = filepath.Join(dir, certName)
	keyFile = filepath.Join(dir, keyName)
	if fp, ok := loadFingerprint(certFile, keyFile); ok {
		return certFile, keyFile, fp, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("hub: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", "", fmt.Errorf("hub: serial: %w", err)
	}
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "claude-swap"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host != "" {
		tpl.DNSNames = append(tpl.DNSNames, host)
	}
	if addrs, aerr := net.InterfaceAddrs(); aerr == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				tpl.IPAddresses = append(tpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", "", fmt.Errorf("hub: create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", "", fmt.Errorf("hub: marshal key: %w", err)
	}
	if err = writePrivate(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return "", "", "", err
	}
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", "", fmt.Errorf("hub: write cert: %w", err)
	}
	sum := sha256.Sum256(der)
	return certFile, keyFile, hex.EncodeToString(sum[:]), nil
}

// writePrivate writes b to path with owner-only permissions.
func writePrivate(path string, b []byte) error {
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("hub: write %s: %w", filepath.Base(path), err)
	}
	if err := credfile.RestrictFile(path); err != nil {
		return fmt.Errorf("hub: restrict %s: %w", filepath.Base(path), err)
	}
	return nil
}

func loadFingerprint(certFile, keyFile string) (string, bool) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return "", false
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return "", false
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", false
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || time.Now().After(cert.NotAfter.Add(-24*time.Hour)) {
		return "", false
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return "", false
	}
	priv, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return "", false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		return "", false
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:]), true
}
