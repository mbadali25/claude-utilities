package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"
)

// The KEK drop-in: the one systemd file that tells the server unit where its vault key comes from.
//
// It is a drop-in, not a line in the unit, because `service install` runs before anyone knows which
// form this host gets, and a unit that names an encrypted credential that does not exist (or
// LoadCredentialEncrypted= for a plain file) fails before ExecStart. (A plain LoadCredential= with a
// missing file does not: CI showed the server is exec'd with no key, falls through to the passphrase
// and exits 3 or 4.) The command that creates the KEK writes the drop-in; this file is the writer and
// the preflight that makes the failure rare.
//
// Everything that touches the machine goes through `host`, so the tests need no systemd, no root and
// no /etc. Every error this file returns is a fixed sentence: an OS error carries the path it failed
// on, and a path under /etc/credstore in a log is the thing the observability rule forbids.

const (
	// DropInDir is the directory systemd reads a unit's drop-ins from.
	DropInDir = "/etc/systemd/system/" + UnitName + ".d"

	// DropInPath is the one file this package writes into it. It is named here and nowhere else:
	// the writer, the remover, `service uninstall` and the runbook are the only places that may.
	DropInPath = DropInDir + "/10-kek.conf"

	// credstoreDir and credstoreEncryptedDir are systemd's own search directories for plaintext and
	// encrypted credentials; credentialFile is the name in both. They match internal/vault's, which
	// reads the same files, and a change to one is a change to both.
	//
	//nolint:gosec // G101: directory and file names, not credentials.
	credstoreDir = "/etc/credstore"
	//nolint:gosec // G101: directory and file names, not credentials.
	credstoreEncryptedDir = "/etc/credstore.encrypted"
	//nolint:gosec // G101: a file name, not a credential.
	credentialFile = "claude-swap.vault-kek"

	// preflightCredentialName names the throwaway credential the round trip encrypts.
	//
	//nolint:gosec // G101: a credential NAME embedded in the throwaway ciphertext, not a secret.
	preflightCredentialName = "claude-swap-preflight"

	// PreflightExitCode is the exit status of a command whose preflight failed: the operator has a
	// setup step to take, and nothing was written.
	PreflightExitCode = 2

	// commandTimeout bounds each systemctl / systemd-creds call. TPM2 operations can be slow; a hung
	// one must not hold the install.
	commandTimeout = 60 * time.Second
)

// Rung is one of the three ranked ways a host holds its vault key. All three are first class
// (Decision 3, O19): tpm2 is an upgrade where the hardware is present, not the normal case with two
// excuses.
type Rung int

const (
	// RungHostTPM2 is an encrypted credential sealed to the host key and the TPM2.
	RungHostTPM2 Rung = iota + 1
	// RungHost is an encrypted credential sealed to the host key alone. It is still a
	// systemd-creds credential, never the plain file.
	RungHost
	// RungPlain is a root-owned 0600 file, the portable floor for a host with no systemd-creds.
	RungPlain
)

// Valid reports whether r is one of the three rungs. The zero Rung is not.
func (r Rung) Valid() bool { return r >= RungHostTPM2 && r <= RungPlain }

func (r Rung) String() string {
	switch r {
	case RungHostTPM2:
		return "host+tpm2"
	case RungHost:
		return "host"
	case RungPlain:
		return "plain"
	}
	return "invalid"
}

// Errors. Sentinels so a caller can branch; the text of each is fixed and names no path.
var (
	// ErrNeedsRoot: the operation changes /etc/systemd and reads root-only credentials.
	ErrNeedsRoot = errors.New("kek drop-in: this needs root")
	// ErrCredentialMissing: the credential the drop-in would name is not there. An encrypted one
	// fails the start; a plain one starts a server with no key. Neither is worth writing ahead of.
	ErrCredentialMissing = errors.New("kek drop-in: the credential the drop-in would name does not exist")
	// ErrCredentialMode: the credential is not root-owned and closed to everyone else.
	ErrCredentialMode = errors.New("kek drop-in: the credential is not owned by root with mode 0600")
	// ErrPreflight: a preflight check failed; nothing was written.
	ErrPreflight = errors.New("kek drop-in: preflight failed")
	// ErrDropIn: a write, remove or reload failed.
	ErrDropIn = errors.New("kek drop-in: the change failed")
	// ErrRung: the rung is not one of the three.
	ErrRung = errors.New("kek drop-in: not a valid rung")
)

// SelectRung picks the best rung a host supports: the TPM2-sealed credential where there is one,
// the host-key credential where there is systemd-creds without a TPM2, the plain file otherwise.
// A TPM2 without systemd-creds cannot seal anything this unit could load, so it selects Plain.
func SelectRung(hasCreds, hasTPM2 bool) Rung {
	switch {
	case hasCreds && hasTPM2:
		return RungHostTPM2
	case hasCreds:
		return RungHost
	}
	return RungPlain
}

// RenderKEKDropIn renders the drop-in for a rung: exactly one of LoadCredentialEncrypted= and
// LoadCredential=, never both. host and host+tpm2 render the same bytes - the TPM2 is a property of
// how the credential was sealed, which systemd reads from the file - and an invalid rung renders
// nothing rather than a guess.
func RenderKEKDropIn(r Rung) string {
	switch r {
	case RungHostTPM2, RungHost:
		return "[Service]\nLoadCredentialEncrypted=" + credentialName + ":" + credentialPath(r) + "\n"
	case RungPlain:
		return "[Service]\nLoadCredential=" + credentialName + ":" + credentialPath(r) + "\n"
	}
	return ""
}

// credDir is the credstore directory a rung's credential lives in.
func credDir(r Rung) string {
	if r == RungPlain {
		return credstoreDir
	}
	return credstoreEncryptedDir
}

// credentialPath is the file a rung's drop-in names.
func credentialPath(r Rung) string { return credDir(r) + "/" + credentialFile }

// WriteKEKDropIn writes the drop-in for r and reloads systemd. It refuses, writing nothing, unless
// it is root and the credential the drop-in would name exists, root-owned and closed to others:
// the drop-in is never written ahead of the file it points at.
func WriteKEKDropIn(r Rung) error {
	if !r.Valid() {
		return ErrRung
	}
	if host.Euid() != 0 {
		return ErrNeedsRoot
	}
	if err := checkCredential(r); err != nil {
		return err
	}
	if err := host.MkdirAll(DropInDir, 0o755); err != nil {
		return fmt.Errorf("%w (%s)", ErrDropIn, errClass(err))
	}
	if err := host.WriteFile(DropInPath, []byte(RenderKEKDropIn(r)), 0o644); err != nil {
		return fmt.Errorf("%w (%s)", ErrDropIn, errClass(err))
	}
	return daemonReload()
}

// RemoveKEKDropIn removes the drop-in and reloads. Nothing to remove is success without a reload:
// it is what `remove-slot` of the last kek-file slot and `service uninstall` both call, and either
// may run twice.
func RemoveKEKDropIn() error {
	if host.Euid() != 0 {
		return ErrNeedsRoot
	}
	if err := host.Remove(DropInPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w (%s)", ErrDropIn, errClass(err))
	}
	if err := daemonReload(); err != nil {
		return err
	}
	// Best effort: the directory is ours, and an operator's own drop-in beside it keeps it alive.
	_ = host.Remove(DropInDir)
	return nil
}

// SwitchToPlainKEK is `--plain-kek` on a host that already has an encrypted credential: it points
// the drop-in at the plain file, reloads, and only then removes the encrypted file it replaces. The
// order is the point - a failure between the steps leaves a drop-in that names a file that exists.
func SwitchToPlainKEK() error {
	if err := WriteKEKDropIn(RungPlain); err != nil {
		return err
	}
	if err := host.Remove(credentialPath(RungHost)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w (%s)", ErrDropIn, errClass(err))
	}
	return nil
}

// SyncKEKDropIn makes the drop-in name the credential this host actually holds, for the commands
// (`vault migrate`, and the slot commands that create a kek-file slot) that have just wrapped under
// it. It returns the rung and whether it wrote.
//
// It looks at what is on disk rather than being told a rung, because those commands wrap under the
// KEK the host ALREADY resolves; they do not create one. No visible credential - a console run keyed
// by CLAUDESWAP_KEK_FILE, a non-root run that cannot see /etc/credstore, a host with neither - is a
// quiet no-op, since there is nothing a unit could name. An up-to-date drop-in is left alone.
func SyncKEKDropIn() (Rung, bool, error) {
	var found Rung
	for _, r := range []Rung{RungHost, RungPlain} { // the encrypted form is the stronger, so it wins
		if _, _, _, err := host.Stat(credentialPath(r)); err == nil {
			found = r
			break
		}
	}
	if found == 0 {
		return 0, false, nil
	}
	if cur, err := host.ReadFile(DropInPath); err == nil && bytes.Equal(cur, []byte(RenderKEKDropIn(found))) {
		return found, false, nil
	}
	if err := WriteKEKDropIn(found); err != nil {
		return found, false, err
	}
	return found, true, nil
}

// Preflight is the installer's check that the host key WORKS, run before the real KEK is written:
// systemd accepts the drop-in, the credential directory and file are root-only where they exist,
// and (for the encrypted forms) a throwaway credential survives an encrypt/decrypt round trip as
// root. Any failure is ErrPreflight, the caller exits PreflightExitCode, and nothing has been
// written - the checks only read, run systemd-analyze on a temp copy and encrypt random bytes that
// are discarded.
func Preflight(r Rung) error {
	if !r.Valid() {
		return fmt.Errorf("%w: not a valid rung", ErrPreflight)
	}
	if host.Euid() != 0 {
		return fmt.Errorf("%w: this needs root", ErrPreflight)
	}
	if err := host.Verify(stubUnit, RenderKEKDropIn(r)); err != nil {
		return fmt.Errorf("%w: systemd-analyze verify rejected the drop-in", ErrPreflight)
	}
	if err := assertCredstore(r); err != nil {
		return fmt.Errorf("%w: %s", ErrPreflight, preflightDetail(err))
	}
	if r == RungPlain {
		return nil
	}
	return roundTrip(r)
}

// stubUnit is the minimal service the drop-in is verified against: the real unit's ExecStart names a
// binary that may not be installed yet, and verify would fail on that rather than on the drop-in.
const stubUnit = "[Service]\nExecStart=/bin/true\n"

// assertCredstore checks, where they exist, that the credential's directory and file are root-owned
// and closed to everyone else. Absent is fine: preflight runs before the KEK is written.
func assertCredstore(r Rung) error {
	if uid, mode, _, err := host.Stat(credDir(r)); err == nil && (uid != 0 || mode.Perm()&0o077 != 0) {
		return ErrCredentialMode
	}
	return credentialModeOK(r, false)
}

// checkCredential is the write-time form: the credential must exist.
func checkCredential(r Rung) error { return credentialModeOK(r, true) }

func credentialModeOK(r Rung, mustExist bool) error {
	uid, mode, isDir, err := host.Stat(credentialPath(r))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if mustExist {
			return ErrCredentialMissing
		}
		return nil
	case err != nil:
		return ErrCredentialMode
	case isDir, uid != 0, mode.Perm()&^0o600 != 0:
		return ErrCredentialMode
	}
	return nil
}

func preflightDetail(err error) string {
	if errors.Is(err, ErrCredentialMode) {
		return "the credstore directory or credential is not root-owned and closed to others"
	}
	return "the credstore could not be checked"
}

// roundTrip proves the host key by encrypting 32 random bytes and decrypting them back. The bytes
// are never the real KEK and are cleared afterwards; the ciphertext lives only in memory.
func roundTrip(r Rung) error {
	key := "--with-key=host"
	if r == RungHostTPM2 {
		key = "--with-key=host+tpm2"
	}
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		return fmt.Errorf("%w: no randomness for the round trip", ErrPreflight)
	}
	defer clear(plain)
	ct, err := host.Run(plain, "systemd-creds", "encrypt", key, "--name="+preflightCredentialName, "-", "-")
	if err != nil {
		return fmt.Errorf("%w: systemd-creds could not encrypt with the host key", ErrPreflight)
	}
	got, err := host.Run(ct, "systemd-creds", "decrypt", "--name="+preflightCredentialName, "-", "-")
	if err != nil {
		return fmt.Errorf("%w: systemd-creds could not decrypt what it encrypted", ErrPreflight)
	}
	defer clear(got)
	if !bytes.Equal(got, plain) {
		return fmt.Errorf("%w: the round trip returned different bytes", ErrPreflight)
	}
	return nil
}

func daemonReload() error {
	if _, err := host.Run(nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("%w (daemon-reload failed)", ErrDropIn)
	}
	return nil
}

// errClass names the kind of an OS error without the path inside it.
func errClass(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	}
	return "see the system log"
}

// hostOps is everything the writer asks of the machine.
type hostOps interface {
	Euid() int
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, mode fs.FileMode) error
	Remove(path string) error
	Stat(path string) (uid int, mode fs.FileMode, isDir bool, err error)
	MkdirAll(path string, mode fs.FileMode) error
	// Run runs a program with stdin and returns its stdout. stderr is dropped: it can name paths.
	Run(stdin []byte, name string, args ...string) ([]byte, error)
	// Verify runs systemd-analyze verify on a unit and a drop-in, in a temp directory.
	Verify(unit, dropIn string) error
}

// host is the real machine unless a test replaces it.
var host hostOps = osHost{}

type osHost struct{}

func (osHost) Euid() int { return os.Geteuid() }

func (osHost) ReadFile(p string) ([]byte, error) { return os.ReadFile(filepath.Clean(p)) }

// WriteFile is atomic: a temp file in the same directory, then a rename, so systemd never reads a
// half-written drop-in.
func (osHost) WriteFile(p string, data []byte, mode fs.FileMode) error {
	p = filepath.Clean(p)
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp, mode)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (osHost) Remove(p string) error { return os.Remove(filepath.Clean(p)) }

func (osHost) Stat(p string) (int, fs.FileMode, bool, error) {
	fi, err := os.Stat(filepath.Clean(p))
	if err != nil {
		return 0, 0, false, err
	}
	return ownerUID(fi), fi.Mode(), fi.IsDir(), nil
}

func (osHost) MkdirAll(p string, mode fs.FileMode) error { return os.MkdirAll(filepath.Clean(p), mode) }

func (osHost) Run(stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- name and args are this package's own constants
	cmd.Stdin = bytes.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (h osHost) Verify(unit, dropIn string) error {
	dir, err := os.MkdirTemp("", "claude-swap-verify-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	up := filepath.Join(dir, UnitName)
	if err := os.WriteFile(up, []byte(unit), 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(up+".d", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(up+".d", "10-kek.conf"), []byte(dropIn), 0o600); err != nil {
		return err
	}
	_, err = h.Run(nil, "systemd-analyze", "verify", up)
	return err
}

// ownerUID is the numeric owner of a file, or -1 when the platform does not say. It reads the Uid
// field of the platform's stat structure by name, so one file builds everywhere: on unix that is
// syscall.Stat_t, elsewhere there is no such field and -1 is never root, so a credential check that
// reaches it fails closed. The writer only ever runs on Linux.
func ownerUID(fi fs.FileInfo) int {
	v := reflect.Indirect(reflect.ValueOf(fi.Sys()))
	if v.IsValid() && v.Kind() == reflect.Struct {
		if f := v.FieldByName("Uid"); f.IsValid() && f.CanUint() {
			return int(f.Uint()) // #nosec G115 -- a uid is 32 bits
		}
	}
	return -1
}
