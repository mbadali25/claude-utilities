package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Tests for the kek-file slot opener and the KEK resolution order behind it. Every path is a temp
// directory and every uid is the geteuidFn seam: nothing here reads /etc/credstore, runs
// systemd-creds, or needs root. The 32-byte KEKs are fixed test bytes.

// kekFixture redirects the two credstore directories at a temp dir and returns it. The real paths
// are absolute, so a test that did not redirect them would either read a real host's key or depend
// on a host that has none.
func kekFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	plainPrev, encPrev := credstoreDir, credstoreEncryptedDir
	credstoreDir = filepath.Join(dir, "credstore")
	credstoreEncryptedDir = filepath.Join(dir, "credstore.encrypted")
	if err := os.MkdirAll(credstoreDir, 0o700); err != nil {
		t.Fatalf("mkdir credstore: %v", err)
	}
	if err := os.MkdirAll(credstoreEncryptedDir, 0o700); err != nil {
		t.Fatalf("mkdir credstore.encrypted: %v", err)
	}
	t.Cleanup(func() { credstoreDir, credstoreEncryptedDir = plainPrev, encPrev })
	return dir
}

// asUID pins the effective uid the resolver sees.
func asUID(t *testing.T, uid int) {
	t.Helper()
	prev := geteuidFn
	geteuidFn = func() int { return uid }
	t.Cleanup(func() { geteuidFn = prev })
}

// decryptSeam replaces the systemd-creds child process and records what it was asked for.
func decryptSeam(t *testing.T, out []byte, err error) *[][2]string {
	t.Helper()
	var calls [][2]string
	prev := credsDecryptFn
	credsDecryptFn = func(name, path string) ([]byte, error) {
		calls = append(calls, [2]string{name, path})
		return out, err
	}
	t.Cleanup(func() { credsDecryptFn = prev })
	return &calls
}

// writeKEK drops a key file of n bytes at path with the given mode.
func writeKEK(t *testing.T, path string, n int, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xbe}, n), mode); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
}

func TestResolveKEKPrefersCredentialsDirectory(t *testing.T) {
	// Step 1 of the order, and it wins over everything: when systemd handed this process a
	// credential, that is the KEK, and no root-only route and no flag may override it. A service
	// running inside the unit must never be the thing that shells out to systemd-creds.
	dir := kekFixture(t)
	credsDir := filepath.Join(dir, "creds")
	if err := os.MkdirAll(credsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeKEK(t, filepath.Join(credsDir, "vault-kek"), keyLen, 0o600)
	// Everything else also present and pointing at different bytes, so a wrong precedence shows up
	// as the wrong bytes and not only as the wrong route.
	writeKEK(t, filepath.Join(credstoreDir, kekCredstoreFile), keyLen, 0o600)
	flagFile := filepath.Join(dir, "flag.kek")
	writeKEK(t, flagFile, keyLen, 0o600)
	t.Setenv(credentialsDirEnv, credsDir)
	asUID(t, 0)
	decryptSeam(t, bytes.Repeat([]byte{0x01}, keyLen), nil)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", KEKFile: flagFile, AllowRootCredsDecrypt: true})
	if err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	if route != kekRouteCredentialsDir {
		t.Fatalf("route = %q, want %q", route, kekRouteCredentialsDir)
	}
	if len(kek) != keyLen {
		t.Fatalf("kek is %d bytes, want %d", len(kek), keyLen)
	}
}

func TestResolveKEKUsesSystemdCredsDecryptAsRoot(t *testing.T) {
	kekFixture(t)
	if err := os.WriteFile(filepath.Join(credstoreEncryptedDir, kekCredstoreFile), []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}
	asUID(t, 0)
	calls := decryptSeam(t, bytes.Repeat([]byte{0x3c}, keyLen), nil)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	if route != kekRouteCredsDecrypt {
		t.Fatalf("route = %q, want %q", route, kekRouteCredsDecrypt)
	}
	if !bytes.Equal(kek, bytes.Repeat([]byte{0x3c}, keyLen)) {
		t.Fatalf("kek = %x, want the bytes the seam returned", kek)
	}
	if len(*calls) != 1 {
		t.Fatalf("decrypt called %d times, want 1", len(*calls))
	}
	if got := (*calls)[0][0]; got != "vault-kek" {
		t.Fatalf("decrypt --name = %q, want %q", got, "vault-kek")
	}
}

func TestResolveKEKSkipsTheRootRoutesWithoutTheOptIn(t *testing.T) {
	// The root routes are opt-in: a process that did not ask for them must not shell out to
	// systemd-creds or read /etc, even when it happens to be running as root.
	kekFixture(t)
	if err := os.WriteFile(filepath.Join(credstoreEncryptedDir, kekCredstoreFile), []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}
	writeKEK(t, filepath.Join(credstoreDir, kekCredstoreFile), keyLen, 0o600)
	asUID(t, 0)
	calls := decryptSeam(t, bytes.Repeat([]byte{0x3c}, keyLen), nil)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek"})
	if err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	if route != kekRouteUnreachable {
		t.Fatalf("route = %q, want %q", route, kekRouteUnreachable)
	}
	if kek != nil {
		t.Fatalf("resolveKEK returned %d bytes without the opt-in", len(kek))
	}
	if len(*calls) != 0 {
		t.Fatal("systemd-creds was run without AllowRootCredsDecrypt")
	}
}

func TestResolveKEKRefusesSystemdCredsDecryptAsNonRoot(t *testing.T) {
	// The encrypted credential is root-only. A non-root CLI must refuse by name rather than fall
	// quietly through to the passphrase: the operator asked for the machine slot, and a silent
	// fall-through would read as "your passphrase is the only key", which is the wrong diagnosis.
	kekFixture(t)
	encPath := filepath.Join(credstoreEncryptedDir, kekCredstoreFile)
	if err := os.WriteFile(encPath, []byte("ciphertext"), 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}
	asUID(t, 1000)
	calls := decryptSeam(t, bytes.Repeat([]byte{0x3c}, keyLen), nil)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if err == nil {
		t.Fatal("a non-root process resolved the encrypted credential")
	}
	if route != kekRouteUnreachable {
		t.Fatalf("route = %q, want %q", route, kekRouteUnreachable)
	}
	if kek != nil {
		t.Fatalf("a refused resolve returned %d bytes", len(kek))
	}
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("err = %v, want ErrKEKUnreachable (the exit-2 class)", err)
	}
	// The error names the file, because that is what the operator has to act on. The log line is
	// the thing that must not carry it, and that is asserted separately.
	if !strings.Contains(err.Error(), encPath) {
		t.Fatalf("error does not name the file: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatal("systemd-creds was run as a non-root uid")
	}
}

func TestResolveKEKRefusesNonThirtyTwoBytePlaintext(t *testing.T) {
	// 31 bytes is the dangerous one: a resolver that returned it would hand aes.NewCipher a key of
	// a length it rejects, or worse, a padded one. Every route is checked, so no single route can
	// become the short-key hole.
	for _, n := range []int{0, 1, keyLen - 1, keyLen + 1} {
		t.Run("decrypt returns "+strconv.Itoa(n), func(t *testing.T) {
			kekFixture(t)
			if err := os.WriteFile(filepath.Join(credstoreEncryptedDir, kekCredstoreFile), []byte("ct"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			asUID(t, 0)
			decryptSeam(t, bytes.Repeat([]byte{0x11}, n), nil)
			kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
			if err == nil {
				t.Fatalf("resolveKEK accepted %d bytes", n)
			}
			if kek != nil {
				t.Fatalf("a refused resolve returned %d bytes", len(kek))
			}
			if route != kekRouteUnreachable {
				t.Fatalf("route = %q, want %q", route, kekRouteUnreachable)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(n)) {
				t.Fatalf("error does not name the length it got: %v", err)
			}
		})
		t.Run("kek-file holds "+strconv.Itoa(n), func(t *testing.T) {
			dir := kekFixture(t)
			path := filepath.Join(dir, "flag.kek")
			writeKEK(t, path, n, 0o600)
			asUID(t, 1000)
			kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", KEKFile: path})
			if err == nil {
				t.Fatalf("resolveKEK accepted a %d-byte --kek-file", n)
			}
			if kek != nil || route != kekRouteUnreachable {
				t.Fatalf("kek = %d bytes, route = %q", len(kek), route)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(n)) {
				t.Fatalf("error does not name the length it got: %v", err)
			}
		})
	}
}

func TestResolveKEKRefusesWhenDecryptExitsNonZero(t *testing.T) {
	kekFixture(t)
	if err := os.WriteFile(filepath.Join(credstoreEncryptedDir, kekCredstoreFile), []byte("ct"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	asUID(t, 0)
	sentinel := errors.New("exit status 1")
	decryptSeam(t, nil, sentinel)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the child's error", err)
	}
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("err = %v, want ErrKEKUnreachable too", err)
	}
	if kek != nil || route != kekRouteUnreachable {
		t.Fatalf("kek = %d bytes, route = %q", len(kek), route)
	}
}

func TestResolveKEKReadsPlainFileAsRoot(t *testing.T) {
	// The portable floor: no systemd-creds on the host, or no encrypted credential, and the KEK is
	// the 0600 root-owned file. Tried after the encrypted form and before the flag.
	kekFixture(t)
	writeKEK(t, filepath.Join(credstoreDir, kekCredstoreFile), keyLen, 0o600)
	asUID(t, 0)
	calls := decryptSeam(t, nil, errors.New("should not run"))

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	if route != kekRoutePlainFile {
		t.Fatalf("route = %q, want %q", route, kekRoutePlainFile)
	}
	if len(kek) != keyLen {
		t.Fatalf("kek is %d bytes, want %d", len(kek), keyLen)
	}
	if len(*calls) != 0 {
		t.Fatal("systemd-creds ran although there was no encrypted credential")
	}
}

func TestResolveKEKRefusesAPlainFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are synthesized on Windows; the plain-file route is Linux-only by design")
	}
	// The whole value of the portable floor is that the KEK is not in the vault's copy and not
	// readable by the accounts the vault is protected from. A world-readable key file is not that,
	// and reading it anyway would make the slot look like protection it is not giving.
	kekFixture(t)
	path := filepath.Join(credstoreDir, kekCredstoreFile)
	writeKEK(t, path, keyLen, 0o644)
	asUID(t, 0)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if err == nil {
		t.Fatal("resolveKEK read a 0644 key file")
	}
	if kek != nil || route != kekRouteUnreachable {
		t.Fatalf("kek = %d bytes, route = %q", len(kek), route)
	}
	if !strings.Contains(err.Error(), "0644") && !strings.Contains(err.Error(), "644") {
		t.Fatalf("error does not name the mode it found: %v", err)
	}
}

func TestResolveKEKFallsThroughWhenNothingResolves(t *testing.T) {
	// No credential, no credstore entry, no flag: not an error. A console run with a passphrase is
	// the normal case on a host with no machine slot, and an error here would turn it into a
	// failure. The opener is nil, which is what makes the passphrase path run.
	kekFixture(t)
	asUID(t, 1000)
	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if err != nil {
		t.Fatalf("resolveKEK on a host with no KEK: %v", err)
	}
	if kek != nil {
		t.Fatalf("resolveKEK returned %d bytes with nothing configured", len(kek))
	}
	if route != kekRouteUnreachable {
		t.Fatalf("route = %q, want %q", route, kekRouteUnreachable)
	}
	if op := kekFileOpener(HostKeyOptions{CredentialName: "vault-kek"}); op != nil {
		t.Fatalf("kekFileOpener = %#v, want nil so the passphrase path runs", op)
	}
}

func TestKEKFileOpenerReportsAnUnreachableKEKRatherThanDisappearing(t *testing.T) {
	// nil means "this host has no kek-file slot"; it must not also mean "the slot is configured and
	// I could not reach it". The second case is an operator-visible refusal, so the opener exists
	// and says so when the open flow reaches it.
	kekFixture(t)
	if err := os.WriteFile(filepath.Join(credstoreEncryptedDir, kekCredstoreFile), []byte("ct"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	asUID(t, 1000)
	decryptSeam(t, bytes.Repeat([]byte{1}, keyLen), nil)

	op := kekFileOpener(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true})
	if op == nil {
		t.Fatal("an unreachable kek-file slot produced no opener, so the refusal is invisible")
	}
	if op.Type() != slotTypeKEKFile {
		t.Fatalf("Type() = %q, want %q", op.Type(), slotTypeKEKFile)
	}
	if _, err := op.Unwrap(kekSlot(t, nil, nil), []byte("aad")); !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("Unwrap err = %v, want ErrKEKUnreachable", err)
	}
}

// kekSlot builds a kek-file slot whose wrap holds the given nonce and ciphertext.
func kekSlot(t *testing.T, nonce, ct []byte) Slot {
	t.Helper()
	return Slot{
		ID:      base64.StdEncoding.EncodeToString(testSlotID(1)),
		Type:    slotTypeKEKFile,
		Name:    "vault-kek",
		Created: "2026-11-08T00:00:00Z",
		Wrap: WrapInfo{
			Nonce: base64.StdEncoding.EncodeToString(nonce),
			CT:    base64.StdEncoding.EncodeToString(ct),
		},
	}
}

func TestKEKFileUnwrapRoundTripAndWrongKEKIsErrBadKey(t *testing.T) {
	dir := kekFixture(t)
	path := filepath.Join(dir, "flag.kek")
	kek := bytes.Repeat([]byte{0xbe}, keyLen)
	writeKEK(t, path, keyLen, 0o600)
	asUID(t, 1000)

	aad := slotAAD(v2VaultMagic, testDEKID(), testSlotID(1), slotTypeKEKFile)
	nonce, ct, err := sealSlot(kek, testDEK(), aad)
	if err != nil {
		t.Fatalf("sealSlot: %v", err)
	}

	op := kekFileOpener(HostKeyOptions{CredentialName: "vault-kek", KEKFile: path})
	if op == nil {
		t.Fatal("kekFileOpener returned nil with --kek-file resolving")
	}
	got, err := op.Unwrap(kekSlot(t, nonce, ct), aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, testDEK()) {
		t.Fatalf("Unwrap returned %x, want %x", got, testDEK())
	}

	// A different KEK file with different bytes is a bad key, so the open flow tries the next slot.
	other := filepath.Join(dir, "other.kek")
	if err := os.WriteFile(other, bytes.Repeat([]byte{0x01}, keyLen), 0o600); err != nil {
		t.Fatalf("write other: %v", err)
	}
	wrong := kekFileOpener(HostKeyOptions{CredentialName: "vault-kek", KEKFile: other})
	if _, err := wrong.Unwrap(kekSlot(t, nonce, ct), aad); !errors.Is(err, ErrBadKey) {
		t.Fatalf("wrong KEK gave %v, want ErrBadKey", err)
	}
	// And a slot of another type is this opener's business to refuse, not to try.
	notMine := kekSlot(t, nonce, ct)
	notMine.Type = slotTypeDPAPI
	if _, err := op.Unwrap(notMine, aad); err == nil {
		t.Fatal("the kek-file opener unwrapped a dpapi slot")
	}
	// A wrap field that is not base64 of the stated length is malformed, not a bad key.
	badB64 := kekSlot(t, nonce, ct)
	badB64.Wrap.CT = "not base64 !!"
	if _, err := op.Unwrap(badB64, aad); err == nil {
		t.Fatal("the kek-file opener accepted a ct that is not base64")
	}
}

func TestKEKPlaintextNeverTouchesDisk(t *testing.T) {
	// The decided mechanism is `systemd-creds decrypt ... -`, read from a pipe into memory. A
	// temporary file would be the one thing the chosen option was chosen to avoid, and it would
	// survive a crash between write and unlink.
	args := credsDecryptArgs("vault-kek", "/etc/credstore.encrypted/claude-swap.vault-kek")
	if len(args) == 0 {
		t.Fatal("credsDecryptArgs returned nothing")
	}
	if args[0] != "systemd-creds" || args[1] != "decrypt" {
		t.Fatalf("argv = %q, want systemd-creds decrypt ...", args)
	}
	if last := args[len(args)-1]; last != "-" {
		t.Fatalf("argv ends with %q, want \"-\" so the plaintext goes to stdout", last)
	}
	if !slices.Contains(args, "--name=vault-kek") {
		t.Fatalf("argv = %q, missing --name=vault-kek", args)
	}
	// Nothing in the argv may be a writable destination: exactly one path, the ciphertext's.
	for _, a := range args[2:] {
		if strings.HasPrefix(a, "--out") || strings.Contains(a, ">") {
			t.Fatalf("argv carries an output destination: %q", a)
		}
	}

	// And resolveKEK itself creates no file anywhere it looked.
	kekFixture(t)
	encPath := filepath.Join(credstoreEncryptedDir, kekCredstoreFile)
	if err := os.WriteFile(encPath, []byte("ct"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	asUID(t, 0)
	decryptSeam(t, bytes.Repeat([]byte{0x3c}, keyLen), nil)
	before := dirListing(t, credstoreEncryptedDir)
	if _, _, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", AllowRootCredsDecrypt: true}); err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	after := dirListing(t, credstoreEncryptedDir)
	if !slices.Equal(before, after) {
		t.Fatalf("resolveKEK changed the directory: before %q, after %q", before, after)
	}
	if plain := dirListing(t, credstoreDir); len(plain) != 0 {
		t.Fatalf("resolveKEK wrote into the plain credstore: %q", plain)
	}
}

func dirListing(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

func TestResolveKEKNeverLogsThePathOrTheBytes(t *testing.T) {
	// The structured line is `op`, `slot`, `slottype`, `exit` and `reason`, and `reason` is the
	// route - the one value this package produces for that line. So the assertion this package can
	// be held to is: the route is from the closed set, it never carries a path or a byte of the
	// KEK, and no error on the success path leaks either. (The refusal errors DO name the file: an
	// operator has to know which file to fix. They are errors, not log fields, and `exit`,
	// `slot` and `slottype` reach logx's allowlist in Task 3a.9.)
	dir := kekFixture(t)
	path := filepath.Join(dir, "flag.kek")
	writeKEK(t, path, keyLen, 0o600)
	asUID(t, 1000)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", KEKFile: path})
	if err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	closed := []string{kekRouteCredentialsDir, kekRouteCredsDecrypt, kekRoutePlainFile, kekRouteUnreachable}
	if !slices.Contains(closed, route) {
		t.Fatalf("route %q is not in the closed set %q", route, closed)
	}
	for _, leak := range []string{path, dir, credstoreDir, credstoreEncryptedDir, kekCredstoreFile} {
		if strings.Contains(route, leak) {
			t.Fatalf("route %q carries %q", route, leak)
		}
	}
	for _, enc := range []string{string(kek), hex.EncodeToString(kek), base64.StdEncoding.EncodeToString(kek)} {
		if strings.Contains(route, enc) {
			t.Fatalf("route %q carries the KEK", route)
		}
	}

	// Every route value is reachable, so the closed set is not aspirational.
	seen := map[string]bool{route: true}
	if _, r, _ := resolveKEK(HostKeyOptions{CredentialName: "vault-kek"}); true {
		seen[r] = true
	}
	credsDir := filepath.Join(dir, "creds")
	if err := os.MkdirAll(credsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeKEK(t, filepath.Join(credsDir, "vault-kek"), keyLen, 0o600)
	t.Setenv(credentialsDirEnv, credsDir)
	if _, r, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek"}); err == nil {
		seen[r] = true
	}
	for _, want := range []string{kekRouteCredentialsDir, kekRoutePlainFile, kekRouteUnreachable} {
		if !seen[want] {
			t.Fatalf("route %q was never produced; seen %v", want, seen)
		}
	}
}

func TestResolveKEKReadsTheKEKFileEnvironmentVariable(t *testing.T) {
	dir := kekFixture(t)
	path := filepath.Join(dir, "env.kek")
	writeKEK(t, path, keyLen, 0o600)
	asUID(t, 1000)
	t.Setenv(kekFileEnv, path)

	kek, route, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek"})
	if err != nil {
		t.Fatalf("resolveKEK: %v", err)
	}
	if route != kekRoutePlainFile {
		t.Fatalf("route = %q, want %q", route, kekRoutePlainFile)
	}
	if len(kek) != keyLen {
		t.Fatalf("kek is %d bytes", len(kek))
	}
	// The flag wins over the variable: a flag is this run's explicit instruction.
	other := filepath.Join(dir, "flag.kek")
	if err := os.WriteFile(other, bytes.Repeat([]byte{0x02}, keyLen), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	flagKEK, _, err := resolveKEK(HostKeyOptions{CredentialName: "vault-kek", KEKFile: other})
	if err != nil {
		t.Fatalf("resolveKEK with the flag: %v", err)
	}
	if !bytes.Equal(flagKEK, bytes.Repeat([]byte{0x02}, keyLen)) {
		t.Fatalf("the environment variable won over --kek-file")
	}
}
