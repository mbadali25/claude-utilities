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
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// certFixture writes a self-signed pair into dir with the given NotAfter and returns the
// certificate's sha256 fingerprint. The shapes match what EnsureCert writes, so a fixture pair
// is indistinguishable from a real one.
func certFixture(t *testing.T, dir string, notAfter time.Time) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "claude-swap-test"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certWrite(t, filepath.Join(dir, certName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	certWrite(t, filepath.Join(dir, keyName), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func certWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// pairSums returns the sha256 of each file of the pair, or "absent" for one that is not there,
// so a test can prove EnsureCert wrote nothing.
func pairSums(t *testing.T, dir string) [2]string {
	t.Helper()
	var out [2]string
	for i, name := range []string{certName, keyName} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case errors.Is(err, os.ErrNotExist):
			out[i] = "absent"
		case err != nil:
			out[i] = "unreadable" // a deny ACE or a 0000 mode: still a stable value to compare
		default:
			sum := sha256.Sum256(b)
			out[i] = hex.EncodeToString(sum[:])
		}
	}
	return out
}

// --- Task 2.1: EnsureCert refuses instead of regenerating. One test per case-table row. ---

func TestEnsureCertGeneratesWhenNeitherFileExists(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, fp, err := EnsureCert(dir)
	if err != nil {
		t.Fatalf("first run must generate: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint %q", fp)
	}
	for _, p := range []string{certFile, keyFile} {
		if _, serr := os.Stat(p); serr != nil {
			t.Fatalf("%s: %v", p, serr)
		}
	}
}

func TestEnsureCertRefusesWhenOnlyCertExists(t *testing.T) {
	dir := t.TempDir()
	certFixture(t, dir, time.Now().AddDate(10, 0, 0))
	if err := os.Remove(filepath.Join(dir, keyName)); err != nil {
		t.Fatal(err)
	}
	before := pairSums(t, dir)
	_, _, _, err := EnsureCert(dir)
	if !errors.Is(err, ErrCertPairIncomplete) {
		t.Fatalf("err = %v, want ErrCertPairIncomplete", err)
	}
	if !strings.Contains(err.Error(), keyName) {
		t.Fatalf("message must name the missing %s: %v", keyName, err)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("pair rewritten: %v -> %v", before, after)
	}
}

func TestEnsureCertRefusesWhenOnlyKeyExists(t *testing.T) {
	dir := t.TempDir()
	certFixture(t, dir, time.Now().AddDate(10, 0, 0))
	if err := os.Remove(filepath.Join(dir, certName)); err != nil {
		t.Fatal(err)
	}
	before := pairSums(t, dir)
	_, _, _, err := EnsureCert(dir)
	if !errors.Is(err, ErrCertPairIncomplete) {
		t.Fatalf("err = %v, want ErrCertPairIncomplete", err)
	}
	if !strings.Contains(err.Error(), certName) {
		t.Fatalf("message must name the missing %s: %v", certName, err)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("pair rewritten: %v -> %v", before, after)
	}
}

func TestEnsureCertRefusesUnreadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits; the Windows deny-ACE case is TestEnsureCertRefusesUnreadableKeyWindows")
	}
	dir := t.TempDir()
	certFixture(t, dir, time.Now().AddDate(10, 0, 0))
	key := filepath.Join(dir, keyName)
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(key, 0o600) })
	if _, err := os.ReadFile(key); err == nil {
		t.Skipf("a 0000 mode does not deny this process (running as root?): %s stayed readable", keyName)
	}
	before := pairSums(t, dir)
	_, _, _, err := EnsureCert(dir)
	if !errors.Is(err, ErrCertUnreadable) {
		t.Fatalf("err = %v, want ErrCertUnreadable", err)
	}
	if r := CertReason(err); r != "permission" {
		t.Fatalf("reason = %q, want permission", r)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("pair rewritten: %v -> %v", before, after)
	}
}

func TestEnsureCertRefusesUnreadableKeyWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("deny ACEs are a Windows concept; the POSIX case is TestEnsureCertRefusesUnreadableKey")
	}
	dir := t.TempDir()
	certFixture(t, dir, time.Now().AddDate(10, 0, 0))
	key := filepath.Join(dir, keyName)
	me := os.Getenv("USERNAME")
	if me == "" {
		t.Skip("USERNAME is empty, so there is no principal to deny")
	}
	// The service-account case that destroyed pins: the key is there and the process may not read it.
	if out, err := exec.Command("icacls", key, "/deny", me+":(R)").CombinedOutput(); err != nil {
		t.Skipf("icacls cannot apply the deny ACE: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("icacls", key, "/remove:d", me).Run() })
	if _, err := os.ReadFile(key); err == nil {
		t.Skipf("the deny ACE did not take effect: %s stayed readable", keyName)
	}
	before := pairSums(t, dir)
	_, _, _, err := EnsureCert(dir)
	if !errors.Is(err, ErrCertUnreadable) {
		t.Fatalf("err = %v, want ErrCertUnreadable", err)
	}
	if r := CertReason(err); r != "permission" {
		t.Fatalf("reason = %q, want permission", r)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("pair rewritten: %v -> %v", before, after)
	}
}

func TestEnsureCertRefusesBadPEM(t *testing.T) {
	for _, tc := range []struct{ name, file, body string }{
		{"key is not PEM", keyName, "junk"},
		{"cert is not PEM", certName, "junk"},
		{"cert block is the wrong type", certName, "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFixture(t, dir, time.Now().AddDate(10, 0, 0))
			certWrite(t, filepath.Join(dir, tc.file), []byte(tc.body))
			before := pairSums(t, dir)
			_, _, _, err := EnsureCert(dir)
			if !errors.Is(err, ErrCertCorrupt) {
				t.Fatalf("err = %v, want ErrCertCorrupt", err)
			}
			if after := pairSums(t, dir); after != before {
				t.Fatalf("pair rewritten: %v -> %v", before, after)
			}
		})
	}
}

func TestEnsureCertRefusesKeyCertMismatch(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	certFixture(t, dir, time.Now().AddDate(10, 0, 0))
	certFixture(t, other, time.Now().AddDate(10, 0, 0))
	okey, err := os.ReadFile(filepath.Join(other, keyName))
	if err != nil {
		t.Fatal(err)
	}
	certWrite(t, filepath.Join(dir, keyName), okey)
	before := pairSums(t, dir)
	_, _, _, err = EnsureCert(dir)
	if !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("err = %v, want ErrCertMismatch", err)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("pair rewritten: %v -> %v", before, after)
	}
}

func TestEnsureCertKeepsServingWithin30Days(t *testing.T) {
	dir := t.TempDir()
	fp := certFixture(t, dir, time.Now().Add(20*24*time.Hour))
	_, _, got, err := EnsureCert(dir)
	if err != nil || got != fp {
		t.Fatalf("a pair 20 days from expiry must keep serving unchanged: fp %q want %q err %v", got, fp, err)
	}
}

func TestEnsureCertKeepsServingWithin24Hours(t *testing.T) {
	dir := t.TempDir()
	fp := certFixture(t, dir, time.Now().Add(6*time.Hour))
	_, _, got, err := EnsureCert(dir)
	if err != nil || got != fp {
		t.Fatalf("a pair 6 hours from expiry must keep serving unchanged: fp %q want %q err %v", got, fp, err)
	}
}

func TestEnsureCertRefusesExpiredPair(t *testing.T) {
	dir := t.TempDir()
	certFixture(t, dir, time.Now().Add(-time.Hour))
	before := pairSums(t, dir)
	_, _, _, err := EnsureCert(dir)
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("err = %v, want ErrCertExpired", err)
	}
	if !strings.Contains(err.Error(), "server cert renew") {
		t.Fatalf("message must name the way out: %v", err)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("expired pair replaced, which re-pins every agent: %v -> %v", before, after)
	}
}

func TestEnsureCertNeverRewritesAPairItCouldLoad(t *testing.T) {
	for _, tc := range []struct {
		name     string
		notAfter time.Duration
	}{
		{"ten years out", 10 * 365 * 24 * time.Hour},
		{"twenty days out", 20 * 24 * time.Hour},
		{"six hours out", 6 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fp := certFixture(t, dir, time.Now().Add(tc.notAfter))
			before := pairSums(t, dir)
			for i := 0; i < 3; i++ {
				_, _, got, err := EnsureCert(dir)
				if err != nil || got != fp {
					t.Fatalf("call %d: fp %q want %q err %v", i, got, fp, err)
				}
			}
			if after := pairSums(t, dir); after != before {
				t.Fatalf("pair rewritten: %v -> %v", before, after)
			}
		})
	}
}

// --- Task 2.2: the reason half of the case table, including the row only this package can build. ---

func TestCertReasonCoversEveryCaseTableRow(t *testing.T) {
	// One entry per row of spec "Admin password and TLS certificate". The three rows that keep
	// serving or generate produce no error and therefore no reason.
	for _, tc := range []struct {
		row    string
		err    error
		reason string
	}{
		{"1 neither file exists", nil, ""},
		{"2 exactly one file exists", fmt.Errorf("wrapped: %w", ErrCertPairIncomplete), "incomplete"},
		{"3 a file cannot be read", fmt.Errorf("wrapped: %w", errReasonPermission), "permission"},
		{"4 a file does not parse", fmt.Errorf("wrapped: %w", ErrCertCorrupt), "corrupt"},
		{"5 the key does not match the cert", fmt.Errorf("wrapped: %w", ErrCertMismatch), "mismatch"},
		{"6 valid, within 30 days", nil, ""},
		{"7 valid, within 24 hours", nil, ""},
		{"8 NotAfter already past", fmt.Errorf("wrapped: %w", ErrCertExpired), "expired"},
		{"9 the re-ACL failed", fmt.Errorf("wrapped: %w", errReasonACL), "acl"},
	} {
		if got := CertReason(tc.err); got != tc.reason {
			t.Errorf("row %s: reason = %q, want %q", tc.row, got, tc.reason)
		}
	}
}

func TestCertReasonForTheReACLFailureIsACLNotPermission(t *testing.T) {
	// Both causes are ErrCertUnreadable to every caller, so only the reason tells them apart.
	for _, e := range []error{errReasonACL, errReasonPermission} {
		if !errors.Is(e, ErrCertUnreadable) {
			t.Fatalf("%v must match ErrCertUnreadable", e)
		}
	}
	if got := CertReason(errReasonACL); got != "acl" {
		t.Errorf("acl reason = %q", got)
	}
	if got := CertReason(errReasonPermission); got != "permission" {
		t.Errorf("permission reason = %q", got)
	}
}

// A read failure that is not a permission error (EISDIR, EIO) is still ErrCertUnreadable, but
// calling it "permission" would be a false label, so it gets its own reason. This row is not in
// the spec's table; it exists because the table's row 3 is specifically fs.ErrPermission.
func TestUnreadableReasonForANonPermissionReadFailure(t *testing.T) {
	err := unreadableErr(keyName, errors.New("input/output error"))
	if !errors.Is(err, ErrCertUnreadable) {
		t.Fatalf("err = %v, want ErrCertUnreadable", err)
	}
	if got := CertReason(err); got != "unreadable" {
		t.Fatalf("reason = %q, want unreadable", got)
	}
}

func TestCertReasonIsEmptyForAnUnrelatedError(t *testing.T) {
	if got := CertReason(errors.New("listen tcp: address already in use")); got != "" {
		t.Fatalf("reason invented for a non-certificate error: %q", got)
	}
}

// --- Task 2.5: the expiry warnings of rows 6-7, and RenewCert. ---

func TestCertExpiryWarningIsSilentBeyondThirtyDays(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certFixture(t, dir, now.Add(31*24*time.Hour))
	if level, text, ok := CertExpiryWarning(filepath.Join(dir, certName), now); ok {
		t.Fatalf("warned at 31 days: %q %q", level, text)
	}
}

func TestCertExpiryWarningIsInfoWithinThirtyDays(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certFixture(t, dir, now.Add(20*24*time.Hour))
	level, text, ok := CertExpiryWarning(filepath.Join(dir, certName), now)
	if !ok || level != "info" {
		t.Fatalf("level %q ok %v", level, ok)
	}
	if !strings.Contains(text, "server cert renew") || !strings.Contains(text, "20 days") {
		t.Fatalf("text %q must name the command and the days left", text)
	}
}

func TestCertExpiryWarningIsWarnWithinTwentyFourHours(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certFixture(t, dir, now.Add(6*time.Hour))
	level, text, ok := CertExpiryWarning(filepath.Join(dir, certName), now)
	if !ok || level != "warn" {
		t.Fatalf("level %q ok %v", level, ok)
	}
	if !strings.Contains(text, "6 hours") || strings.Contains(text, "days") {
		t.Fatalf("text %q must count hours, not days", text)
	}
}

func TestCertExpiryWarningNeverRegenerates(t *testing.T) {
	for _, d := range []time.Duration{31 * 24 * time.Hour, 20 * 24 * time.Hour, 6 * time.Hour, -time.Hour} {
		dir := t.TempDir()
		now := time.Now()
		certFixture(t, dir, now.Add(d))
		before := pairSums(t, dir)
		for i := 0; i < 3; i++ {
			_, _, _ = CertExpiryWarning(filepath.Join(dir, certName), now)
		}
		if after := pairSums(t, dir); after != before {
			t.Fatalf("notAfter %v: a warning rewrote the pair: %v -> %v", d, before, after)
		}
	}
}

func TestCertExpiryWarningCarriesNoFingerprintOrPath(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	fp := certFixture(t, dir, now.Add(6*time.Hour))
	_, text, ok := CertExpiryWarning(filepath.Join(dir, certName), now)
	if !ok {
		t.Fatal("no warning to inspect")
	}
	for _, leak := range []string{fp, dir, certName, keyName, "BEGIN"} {
		if strings.Contains(text, leak) {
			t.Fatalf("warning text %q carries %q", text, leak)
		}
	}
}

func TestRenewCertLeavesNoTempFileOnAnInjectedFailure(t *testing.T) {
	dir := t.TempDir()
	fp := certFixture(t, dir, time.Now().AddDate(10, 0, 0))
	before := pairSums(t, dir)
	old := renameFn
	renameFn = func(string, string) error { return errors.New("injected rename failure") }
	t.Cleanup(func() { renameFn = old })
	if _, _, err := RenewCert(dir); err == nil {
		t.Fatal("RenewCert reported success with a failing rename")
	}
	renameFn = old
	if after := pairSums(t, dir); after != before {
		t.Fatalf("the old pair changed: %v -> %v", before, after)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
	if len(ents) != 2 {
		t.Fatalf("cert dir holds %d entries", len(ents))
	}
	if _, _, got, err := EnsureCert(dir); err != nil || got != fp {
		t.Fatalf("the pin moved: fp %q want %q err %v", got, fp, err)
	}
}

func TestRenewCertRefusesAnUnreadablePair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits; loadPair's Windows deny-ACE path is covered by TestEnsureCertRefusesUnreadableKeyWindows")
	}
	dir := t.TempDir()
	certFixture(t, dir, time.Now().Add(-time.Hour)) // expired as well: renew must still refuse
	key := filepath.Join(dir, keyName)
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(key, 0o600) })
	if _, err := os.ReadFile(key); err == nil {
		t.Skipf("a 0000 mode does not deny this process (running as root?): %s stayed readable", keyName)
	}
	before := pairSums(t, dir)
	if _, _, err := RenewCert(dir); !errors.Is(err, ErrCertUnreadable) {
		t.Fatalf("err = %v, want ErrCertUnreadable", err)
	}
	if after := pairSums(t, dir); after != before {
		t.Fatalf("pair rewritten: %v -> %v", before, after)
	}
}

func TestRenewCertReplacesAnExpiredPairAndReportsBothFingerprints(t *testing.T) {
	dir := t.TempDir()
	oldWant := certFixture(t, dir, time.Now().Add(-time.Hour))
	oldFP, newFP, err := RenewCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if oldFP != oldWant || newFP == oldWant || len(newFP) != 64 {
		t.Fatalf("old %q (want %q) new %q", oldFP, oldWant, newFP)
	}
	// The new pair is loadable, so the server starts again on it.
	if _, _, got, lerr := EnsureCert(dir); lerr != nil || got != newFP {
		t.Fatalf("new pair does not load: fp %q want %q err %v", got, newFP, lerr)
	}
}

func TestRenewCertGeneratesWhenNeitherFileExists(t *testing.T) {
	dir := t.TempDir()
	oldFP, newFP, err := RenewCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if oldFP != "" || len(newFP) != 64 {
		t.Fatalf("old %q new %q", oldFP, newFP)
	}
}
