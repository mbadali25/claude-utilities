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
	"errors"
	"fmt"
	"io/fs"
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

// renameFn is replaced in tests to inject write failures.
var renameFn = os.Rename

// Certificate refusals, one per cause. A new pair is a new sha256 fingerprint, and every
// enrolled agent pins the old one, so replacing a pair the server merely failed to READ
// de-enrols the whole fleet silently. EnsureCert therefore never regenerates a pair it could
// load: it returns one of these instead, and the caller exits 5 (see cmd/server).
var (
	ErrCertPairIncomplete = errors.New("hub: one file of the certificate pair is missing")
	ErrCertUnreadable     = errors.New("hub: the certificate pair cannot be read")
	ErrCertCorrupt        = errors.New("hub: the certificate pair does not parse")
	ErrCertMismatch       = errors.New("hub: the key does not match the certificate")
	ErrCertExpired        = errors.New("hub: the certificate has expired")
)

// The two causes of ErrCertUnreadable, told apart for the log reason only: a read the OS denied,
// and a failure to re-apply the owner-only restriction. They stay unexported so the public error
// set keeps one member for "cannot be read" - every caller matches ErrCertUnreadable, and only
// CertReason tells the causes apart.
var (
	errReasonPermission = fmt.Errorf("permission: %w", ErrCertUnreadable)
	errReasonACL        = fmt.Errorf("acl: %w", ErrCertUnreadable)
)

// errCertNeither reports that neither file of the pair exists, which is the only case EnsureCert
// generates for. It is not a refusal and never reaches a caller.
var errCertNeither = errors.New("hub: no certificate pair yet")

// Reasons, one word each, for the structured log line. A reason is a label: never a path, a
// fingerprint or key material.
const (
	reasonIncomplete = "incomplete"
	reasonPermission = "permission"
	reasonUnreadable = "unreadable"
	reasonCorrupt    = "corrupt"
	reasonMismatch   = "mismatch"
	reasonExpired    = "expired"
	reasonACL        = "acl"
)

// Expiry thresholds. These are the ONLY use of the 24-hour and 30-day figures: a pair inside its
// validity always keeps serving, however close to expiry, and is never replaced because of one.
const (
	certWarnWithin  = 30 * 24 * time.Hour // log once per start and once a day
	certShoutWithin = 24 * time.Hour      // log hourly and raise it to the event log / journal
)

// CertReason returns the one-word cause of a certificate refusal for a log line, or "" when err
// is not a certificate refusal. It is the half of the case table an exit code cannot carry.
func CertReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrCertPairIncomplete):
		return reasonIncomplete
	case errors.Is(err, errReasonACL):
		return reasonACL
	case errors.Is(err, errReasonPermission):
		return reasonPermission
	case errors.Is(err, ErrCertUnreadable):
		return reasonUnreadable
	case errors.Is(err, ErrCertCorrupt):
		return reasonCorrupt
	case errors.Is(err, ErrCertMismatch):
		return reasonMismatch
	case errors.Is(err, ErrCertExpired):
		return reasonExpired
	}
	return ""
}

// EnsureCert returns the paths of a self-signed server certificate and key in dir, plus the
// SHA-256 fingerprint (lowercase hex of the DER) agents pin. It generates the pair only when
// NEITHER file exists; any other failure to load is refused with a typed error and both files are
// left byte-identical, because regenerating would change the fingerprint every enrolled agent
// pins. `server cert renew` is the only command that writes a new pair.
func EnsureCert(dir string) (certFile, keyFile, fingerprint string, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", fmt.Errorf("hub: cert dir: %w", err)
	}
	if rerr := credfile.RestrictDir(dir); rerr != nil {
		// A failed icacls changes nothing on disk, so a restart cannot make this worse - but it
		// cannot fix it either, hence exit 5 rather than the old retry loop.
		return "", "", "", fmt.Errorf("hub: restrict cert dir: %v: %w", rerr, errReasonACL)
	}
	certFile = filepath.Join(dir, certName)
	keyFile = filepath.Join(dir, keyName)
	fp, lerr := loadPair(certFile, keyFile)
	switch {
	case lerr == nil:
		// A key left loose by an older version or a manual copy is tightened (Chmod is a no-op on
		// Windows, where the ACL does the work).
		cerr := os.Chmod(keyFile, 0o600)
		if cerr == nil {
			cerr = credfile.RestrictFile(keyFile)
		}
		if cerr != nil {
			return "", "", "", fmt.Errorf("hub: restrict key file: %v: %w", cerr, errReasonACL)
		}
		return certFile, keyFile, fp, nil
	case errors.Is(lerr, errCertNeither):
		// First run: there is no pin for anyone to hold, so generating is safe.
	default:
		return "", "", "", lerr
	}
	if fingerprint, err = generatePair(certFile, keyFile); err != nil {
		return "", "", "", err
	}
	return certFile, keyFile, fingerprint, nil
}

// RenewCert writes a fresh pair into dir and returns the previous certificate's fingerprint
// (empty when there was no loadable pair) and the new one. It is the only way the pair ever
// changes, so the caller must warn that every enrolled agent has to re-enrol. It refuses on an
// unreadable pair: there the fault is a permission or ACL problem, not a worn-out certificate,
// and replacing the pair would destroy a working pin for nothing.
func RenewCert(dir string) (oldFP, newFP string, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("hub: cert dir: %w", err)
	}
	if rerr := credfile.RestrictDir(dir); rerr != nil {
		return "", "", fmt.Errorf("hub: restrict cert dir: %v: %w", rerr, errReasonACL)
	}
	certFile := filepath.Join(dir, certName)
	keyFile := filepath.Join(dir, keyName)
	fp, lerr := loadPair(certFile, keyFile)
	if errors.Is(lerr, ErrCertUnreadable) {
		return "", "", lerr
	}
	// The old fingerprint is reported even when the pair did not load, because it is the pin the
	// agents still hold and the operator needs it to see what changed. It is a public value.
	switch cert, rerr := readCert(certFile); {
	case lerr == nil:
		oldFP = fp
	case rerr == nil:
		sum := sha256.Sum256(cert.Raw)
		oldFP = hex.EncodeToString(sum[:])
	}
	// Incomplete, corrupt, mismatched and expired all reach here on purpose: renew is the
	// operator's deliberate way out of each of them.
	if newFP, err = generatePair(certFile, keyFile); err != nil {
		return "", "", err
	}
	return oldFP, newFP, nil
}

// CertExpiryWarning reports what to say about the pair's remaining validity, and nothing more: it
// reads the certificate, never writes one and never regenerates. ok is false beyond
// certWarnWithin, and also when the certificate cannot be read or parsed - refusing is
// EnsureCert's job, not a warning's. level is "info" inside 30 days and "warn" inside 24 hours.
// WHEN to emit is the caller's: once per start here, once a day and hourly from the server's run
// loop (scheduled in Task 4.3 of the cert-vault plan, which owns that loop).
func CertExpiryWarning(certFile string, now time.Time) (level, text string, ok bool) {
	cert, err := readCert(certFile)
	if err != nil {
		return "", "", false
	}
	left := cert.NotAfter.Sub(now)
	switch {
	case left > certWarnWithin:
		return "", "", false
	case left > certShoutWithin:
		return "info", "cert expires in " + plural(roundUnits(left, 24*time.Hour), "day") + ", run server cert renew", true
	case left > 0:
		return "warn", "cert expires in " + plural(roundUnits(left, time.Hour), "hour") + ", run server cert renew", true
	default:
		return "warn", "cert expired " + plural(roundUnits(-left, time.Hour), "hour") + " ago, run server cert renew", true
	}
}

// roundUnits reports d in whole units, rounded to the nearest one, because a certificate's
// NotAfter is stored to the second: an exactly-20-day cert is 20 days minus a fraction on disk
// and must still read as "20 days", not 19.
func roundUnits(d, unit time.Duration) int { return int((d + unit/2) / unit) }

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// generatePair writes a fresh self-signed pair over certFile and keyFile and returns the new
// fingerprint. Both files are staged as owner-only temp files before either is renamed, so a
// failure before the first rename leaves the pair exactly as it was. The two renames are not one
// atomic step, and the KEY is renamed first, so a crash between them lands differently depending
// on what was there before:
//   - a first generation leaves one file of two, which EnsureCert REFUSES as
//     ErrCertPairIncomplete, naming the missing file;
//   - a renew over an existing pair leaves the new key beside the OLD certificate - two files -
//     which EnsureCert REFUSES as ErrCertMismatch.
//
// Either way it refuses instead of regenerating behind the operator's back, and no backup of the
// old pair is kept: the way out of both is another `server cert renew`.
func generatePair(certFile, keyFile string) (fingerprint string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("hub: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", fmt.Errorf("hub: serial: %w", err)
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
		return "", fmt.Errorf("hub: create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("hub: marshal key: %w", err)
	}
	keyTmp, err := stagePrivate(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return "", err
	}
	defer func() {
		if keyTmp != "" {
			_ = os.Remove(keyTmp)
		}
	}()
	certTmp, err := stagePrivate(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		return "", err
	}
	defer func() {
		if certTmp != "" {
			_ = os.Remove(certTmp)
		}
	}()
	if err = commit(keyTmp, keyFile); err != nil {
		return "", err
	}
	keyTmp = ""
	if err = commit(certTmp, certFile); err != nil {
		return "", err
	}
	certTmp = ""
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// writePrivate atomically replaces path with b, owner-only from the first byte.
func writePrivate(path string, b []byte) error {
	tmp, err := stagePrivate(path, b)
	if err != nil {
		return err
	}
	if err := commit(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// stagePrivate writes b into a fresh, uniquely named temp file beside path that is owner-only
// before any byte is written, and fsyncs it, so the content is never readable under an inherited
// ACL. The caller renames it over path with commit, or removes it.
func stagePrivate(path string, b []byte) (string, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("hub: write %s: %w", base, err)
	}
	tmp := f.Name()
	if err := fillPrivate(f, tmp, b); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("hub: write %s: %w", base, err)
	}
	return tmp, nil
}

// fillPrivate closes the freshly created temp file, restricts it, then reopens it and writes b.
func fillPrivate(f *os.File, tmp string, b []byte) error {
	if err := f.Close(); err != nil {
		return err
	}
	if err := credfile.RestrictFile(tmp); err != nil {
		return err
	}
	g, err := os.OpenFile(filepath.Clean(tmp), os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = g.Write(b)
	if err == nil {
		err = g.Sync()
	}
	if cerr := g.Close(); err == nil {
		err = cerr
	}
	return err
}

// commit renames a staged temp file over path and fsyncs the directory so the rename is durable.
func commit(tmp, path string) error {
	if err := renameFn(tmp, path); err != nil {
		return fmt.Errorf("hub: replace %s: %w", filepath.Base(path), err)
	}
	credfile.SyncDir(filepath.Dir(path))
	return nil
}

// loadPair returns the certificate's sha256 fingerprint when the pair loads, and one typed
// refusal per cause when it does not. It never writes. Expiry is tested against cert.NotAfter
// ALONE: a pair inside its validity loads and keeps serving however close to expiry, because the
// alternative is replacing a working pin hours before anyone asked.
func loadPair(certFile, keyFile string) (string, error) {
	certPEM, cerr := os.ReadFile(filepath.Clean(certFile))
	keyPEM, kerr := os.ReadFile(filepath.Clean(keyFile))
	certMissing, keyMissing := errors.Is(cerr, fs.ErrNotExist), errors.Is(kerr, fs.ErrNotExist)
	switch {
	case certMissing && keyMissing:
		return "", errCertNeither
	case certMissing:
		return "", incompleteErr(keyName, certName)
	case keyMissing:
		return "", incompleteErr(certName, keyName)
	}
	if cerr != nil {
		return "", unreadableErr(certName, cerr)
	}
	if kerr != nil {
		return "", unreadableErr(keyName, kerr)
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", fmt.Errorf("hub: %s is not a PEM CERTIFICATE block: %w", certName, ErrCertCorrupt)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", fmt.Errorf("hub: %s does not parse as a certificate: %w", certName, ErrCertCorrupt)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return "", fmt.Errorf("hub: %s is not a PEM block: %w", keyName, ErrCertCorrupt)
	}
	priv, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return "", fmt.Errorf("hub: %s does not parse as an EC private key: %w", keyName, ErrCertCorrupt)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		return "", fmt.Errorf("hub: %s does not match %s; nothing here keeps a backup of the pair, so recover "+
			"by running `server cert renew`, which mints a fresh pair and changes the sha256 every agent pins: %w",
			keyName, certName, ErrCertMismatch)
	}
	if time.Now().After(cert.NotAfter) {
		return "", fmt.Errorf("hub: the certificate expired on %s; run `server cert renew`, which mints a new "+
			"pair and changes the sha256 every agent pins: %w", cert.NotAfter.UTC().Format(time.RFC3339), ErrCertExpired)
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// readCert reads and parses the certificate half of the pair. Used by the warning path, which
// needs NotAfter and nothing else.
func readCert(certFile string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, ErrCertCorrupt
	}
	return x509.ParseCertificate(blk.Bytes)
}

func incompleteErr(present, missing string) error {
	return fmt.Errorf("hub: %s is present but %s is missing: restore the missing one, or delete both to "+
		"regenerate on a host with no enrolled agents (a new pair changes the sha256 every agent pins): %w",
		present, missing, ErrCertPairIncomplete)
}

func unreadableErr(name string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("hub: %s cannot be read: %v: fix its owner, mode or ACL; it is NOT replaced, "+
			"so the fingerprint agents pin is unchanged: %w", name, err, errReasonPermission)
	}
	return fmt.Errorf("hub: %s cannot be read: %v: it is NOT replaced, so the fingerprint agents pin "+
		"is unchanged: %w", name, err, ErrCertUnreadable)
}
