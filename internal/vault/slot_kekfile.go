package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// The kek-file slot opener and the KEK resolution behind it. This is the Linux machine slot: the
// DEK is wrapped under a 32-byte key-encryption key the host holds outside the vault's copy, so a
// stolen vault.bin, .bak or data dir carries no key.
//
// One file, no build tag, because every route is expressed through seams (geteuidFn, credsDecryptFn
// and the two credstore directories) and the file must still compile for Windows - where the dpapi
// slot is the machine slot and os.Geteuid returns -1, so the root-only routes are structurally
// unreachable.
//
// The resolution order is the spec's, and the order is the design:
//
//	1.  $CREDENTIALS_DIRECTORY/<name>       - systemd handed this process the credential
//	2a. root only, opt-in:
//	      systemd-creds decrypt --name=<name> <credstore.encrypted>/claude-swap.vault-kek -
//	      or the 0600 <credstore>/claude-swap.vault-kek for the portable floor
//	2.  --kek-file PATH / CLAUDESWAP_KEK_FILE - always a PLAINTEXT KEK, for non-systemd runs and
//	      tests. Never the way to hand in decrypted bytes on a systemd host.
//	3.  nothing resolves                     - no usable slot; the open falls through to the
//	      passphrase, which is the normal case for a console run.
//
// Step 1 winning outright matters: a service running inside its unit already has the credential in
// tmpfs, and a service that shelled out to systemd-creds instead would need root and a child
// process to learn what it was handed at activation.
//
// Step 2a is the operator CLI, run as root directly (decided by Matthew 2026-11-07; there is no
// --in-transient-unit flag). The accepted cost is named in the spec and is real: the plaintext KEK
// crosses a pipe in the operator's own shell session, and a mistyped redirect on that command
// writes a KEK to disk. It is accepted because the threat model already puts root out of scope, and
// nobody but root can rotate a root-owned KEK. What this code can do about it, it does: the
// plaintext is read from a pipe into memory and never through a temporary file.

// kekCredstoreFile is the credstore entry's file name, in both the plain and the encrypted
// directory. The slot stores only `name`, never a path: a path in the header would be a second
// place the truth lives, and a host that moved its credstore would have an unopenable vault.
//
//nolint:gosec // G101: a file name, not a credential. The key is the file's 32 bytes of content.
const kekCredstoreFile = "claude-swap.vault-kek"

// credentialsDirEnv and kekFileEnv are the two environment variables consulted. The first is
// systemd's; the second is this project's escape hatch for a non-systemd host and for tests.
const (
	credentialsDirEnv = "CREDENTIALS_DIRECTORY"
	kekFileEnv        = "CLAUDESWAP_KEK_FILE"
)

// The routes, a closed set. The value goes straight into the `reason` field of the one structured
// line per mutator run, which is why it is a fixed vocabulary and not a sentence: a free-text
// reason built from a path is how a credential's location ends up in a log.
const (
	kekRouteCredentialsDir = "credentials-dir"
	//nolint:gosec // G101: the name of a route, logged as `reason`. It is never key material -
	// TestResolveKEKNeverLogsThePathOrTheBytes asserts the closed set carries no path and no bytes.
	kekRouteCredsDecrypt = "systemd-creds-decrypt"
	kekRoutePlainFile    = "plain-file"
	kekRouteUnreachable  = "unreachable"
)

// credstoreDir and credstoreEncryptedDir are systemd's own search locations for plaintext and
// encrypted credentials. They are variables so a test can redirect them at a temp directory: they
// are absolute paths, and a test that did not redirect them would read a real host's key or depend
// on a host that has none.
var (
	//nolint:gosec // G101: systemd's own search directories, not credentials.
	credstoreDir = "/etc/credstore"
	//nolint:gosec // G101: systemd's own search directories, not credentials.
	credstoreEncryptedDir = "/etc/credstore.encrypted"
)

// geteuidFn is os.Geteuid unless a test replaces it. On Windows it returns -1, which is not 0, so
// the root-only routes are unreachable there by construction rather than by a GOOS branch.
var geteuidFn = os.Geteuid

// credsDecryptFn runs `systemd-creds decrypt` and returns the plaintext it wrote to stdout. The
// seam exists so the whole route can be tested without systemd, root, or a real credential.
var credsDecryptFn = systemdCredsDecrypt

// fileOwnerUIDFn is fileOwnerUID unless a test replaces it. It is a seam for the same reason
// geteuidFn is: a test cannot chown a file to root, so the only way to exercise both sides of the
// root-ownership check is to say what the owner is.
var fileOwnerUIDFn = fileOwnerUID

// ErrKEKUnreachable is the exit-2 class: a kek-file slot is configured and this process cannot
// reach its KEK - not root, the child exited non-zero, the plaintext was the wrong length, or the
// key file is readable by more than its owner.
//
// Its own error and not ErrBadKey, because the two lead an operator in opposite directions.
// ErrBadKey says "try another key", which on a machine slot means rotating something that is very
// probably correct; this says "the key is where it should be and this process may not have it",
// whose fix is a root shell or a mode bit.
var ErrKEKUnreachable = errors.New("vault: kek-file slot is configured but its key is unreachable")

// resolveKEK finds this host's KEK and says which route produced it.
//
// Three outcomes, and the difference between the last two is the whole point:
//   - a KEK and a route: the slot is usable.
//   - nil, "unreachable", nil error: this host has no kek-file slot at all. Not a failure - a
//     console run with a passphrase is the normal case - and the caller falls through.
//   - nil, "unreachable", an error wrapping ErrKEKUnreachable: a KEK is configured and could not be
//     reached. This must never be reported as the case above, or an operator who asked for the
//     machine slot is told, in effect, that their passphrase is the only key.
func resolveKEK(opts HostKeyOptions) (kek []byte, route string, err error) {
	name := opts.CredentialName
	if name == "" {
		name = "vault-kek"
	}

	// 1. The credential systemd handed us. Wins outright.
	//
	// Three outcomes from the stat, and only one of them is a fall-through. ENOENT is: a unit may
	// have been handed some other credential and no KEK, and that is a console-equivalent run. Any
	// other error is not - a credential directory this process cannot read is a KEK that is there
	// and out of reach, and reading that as "absent" is the exit-2 case reported as a passphrase
	// prompt.
	if dir := os.Getenv(credentialsDirEnv); dir != "" {
		path := filepath.Join(dir, name)
		//nolint:gosec // G703: the path is systemd's own credential directory joined with the
		// credential name this process was configured with. Naming the KEK's location is the
		// feature; there is no untrusted traversal to prevent, and filepath.Join already cleans.
		_, statErr := os.Stat(path)
		switch {
		case statErr == nil:
			b, rerr := readKEKFile(path, false)
			if rerr != nil {
				return nil, kekRouteUnreachable, rerr
			}
			return b, kekRouteCredentialsDir, nil
		case !errors.Is(statErr, fs.ErrNotExist):
			return nil, kekRouteUnreachable, fmt.Errorf("%w: %s: %w", ErrKEKUnreachable, path, statErr)
		}
	}

	// 2a. Root only, and only when the caller opted in. A process that did not ask must not shell
	// out to systemd-creds or read /etc, even when it happens to be running as root.
	if opts.AllowRootCredsDecrypt {
		encPath := filepath.Join(credstoreEncryptedDir, kekCredstoreFile)
		plainPath := filepath.Join(credstoreDir, kekCredstoreFile)
		encExists, encErr := credstoreEntryExists(encPath)
		plainExists, plainErr := credstoreEntryExists(plainPath)
		// A credstore entry this process could not even stat is the case that matters, and it is the
		// normal one off root: /etc/credstore and /etc/credstore.encrypted are root:root 0700, so a
		// non-root CLI gets EACCES on the entry inside and learns nothing about whether it is there.
		// Treated as absent - which is what an `err == nil` existence check does - the uid-0 refusal
		// below becomes unreachable and the open falls through to the passphrase, which is exactly
		// the wrong diagnosis to hand an operator who asked for the machine slot.
		//
		// The cost is named rather than hidden: a non-root run with AllowRootCredsDecrypt set now
		// refuses on a host whose credstore directory exists and is empty, because it cannot tell
		// that from a host whose KEK is sitting right there. That is the direction to fail in, and
		// the spec's own answer for a slot that cannot be reached is the passphrase plus
		// remove-slot, not a silent fall-through.
		if encErr != nil || plainErr != nil {
			which, perr := encPath, encErr
			if encErr == nil {
				which, perr = plainPath, plainErr
			}
			if geteuidFn() != 0 {
				return nil, kekRouteUnreachable, fmt.Errorf("%w: %s needs root; re-run as root (sudo)", ErrKEKUnreachable, which)
			}
			return nil, kekRouteUnreachable, fmt.Errorf("%w: %s: %w", ErrKEKUnreachable, which, perr)
		}
		if (encExists || plainExists) && geteuidFn() != 0 {
			// Names the file, because that is what the operator acts on. The log line carries the
			// route and never this string.
			which := encPath
			if !encExists {
				which = plainPath
			}
			return nil, kekRouteUnreachable, fmt.Errorf("%w: %s needs root; re-run as root (sudo)", ErrKEKUnreachable, which)
		}
		if encExists {
			b, derr := credsDecryptFn(name, encPath)
			if derr != nil {
				return nil, kekRouteUnreachable, fmt.Errorf("%w: systemd-creds decrypt of %s failed: %w", ErrKEKUnreachable, encPath, derr)
			}
			if len(b) != keyLen {
				zero(b)
				return nil, kekRouteUnreachable, fmt.Errorf("%w: systemd-creds decrypt of %s gave %d bytes, want %d", ErrKEKUnreachable, encPath, len(b), keyLen)
			}
			return b, kekRouteCredsDecrypt, nil
		}
		if plainExists {
			b, rerr := readKEKFile(plainPath, true)
			if rerr != nil {
				return nil, kekRouteUnreachable, rerr
			}
			return b, kekRoutePlainFile, nil
		}
	}

	// 2. An explicit plaintext KEK: the flag first, then the variable. A flag is this run's
	// instruction and outranks an inherited environment.
	if path := opts.KEKFile; path != "" {
		b, rerr := readKEKFile(path, false)
		if rerr != nil {
			return nil, kekRouteUnreachable, rerr
		}
		return b, kekRoutePlainFile, nil
	}
	if path := os.Getenv(kekFileEnv); path != "" {
		b, rerr := readKEKFile(path, false)
		if rerr != nil {
			return nil, kekRouteUnreachable, rerr
		}
		return b, kekRoutePlainFile, nil
	}

	// 3. Nothing. Not an error.
	return nil, kekRouteUnreachable, nil
}

// readKEKFile reads exactly a 32-byte KEK. credstore is set for the credstore's own file, where the
// 0600 and the root ownership are part of what the slot is claiming: a key file the vault's own
// attackers can read is not a secret outside the copy, and reading it anyway would make the slot
// look like protection it is not giving. The explicit --kek-file path is the operator's choice and
// is not second-guessed on either.
//
// Those two checks are skipped on Windows, where os.FileMode's permission bits are synthesized from
// the read-only attribute and a file is owned by a SID, not a uid, so neither says anything about
// who may read it. That costs nothing: the credstore routes are reachable only as uid 0, and
// os.Geteuid is -1 on Windows.
// The stat is unconditional and comes before any open, which is the only order that cannot hang: a
// FIFO at this path blocks os.Open in open(2) until something writes to it, so a readKEKFile that
// opened first and asked questions later would turn a misconfigured path into a server start that
// hangs with no error and no log line. Lstat and not Stat, which gives O_NOFOLLOW's useful half for
// free: a symlink is not a regular file, so a symlink pointed at a FIFO is refused on the link
// itself and the FIFO is never touched. A KEK is 32 bytes on disk at the path the operator named,
// and the loss - a symlinked --kek-file - is worth not having that shape to reason about.
//
// The read is bounded at keyLen+1. One byte past, so "exactly 32" is still provable, and a 1 GiB
// file at the named path is refused on its length without being pulled into memory first.
func readKEKFile(path string, credstore bool) ([]byte, error) {
	path = filepath.Clean(path)
	//nolint:gosec // G703: see resolveKEK - the operator names this file on purpose, by flag, by
	// environment variable or by being systemd's credstore. Cleaned on the line above.
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrKEKUnreachable, path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file (mode %s); a key file is %d bytes on disk", ErrKEKUnreachable, path, fi.Mode().Type(), keyLen)
	}
	if credstore && runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s is mode %#o; it must be 0600 so only its owner can read it", ErrKEKUnreachable, path, perm)
		}
		// 0600 is the slot's claim only when root is the owner: a root-owned 0700 directory holding
		// a file some other account owns is still a 0600 file, and that account is who the machine
		// slot is keeping the key away from. The directory's mode is not the file's owner.
		if uid, known := fileOwnerUIDFn(fi); known && uid != 0 {
			return nil, fmt.Errorf("%w: %s is owned by uid %d, not root; a credstore KEK must be root-owned", ErrKEKUnreachable, path, uid)
		}
	}
	//nolint:gosec // G703: same path, cleaned above; reading the file the operator named is the job.
	// It is a regular file, checked on the Lstat above, so this open cannot block.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrKEKUnreachable, path, err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, keyLen+1)
	n, rerr := io.ReadFull(f, b)
	if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
		zero(b)
		return nil, fmt.Errorf("%w: %s: %w", ErrKEKUnreachable, path, rerr)
	}
	if n > keyLen {
		zero(b)
		return nil, fmt.Errorf("%w: %s holds at least %d bytes, want a %d-byte key", ErrKEKUnreachable, path, n, keyLen)
	}
	if n != keyLen {
		zero(b)
		return nil, fmt.Errorf("%w: %s holds %d bytes, want a %d-byte key", ErrKEKUnreachable, path, n, keyLen)
	}
	return b[:keyLen:keyLen], nil
}

// credstoreEntryExists says whether a credstore entry is there to be used. The three-way answer is
// the point, and a two-way one is the bug it replaces:
//   - true, nil: a non-directory is at that path.
//   - false, nil: nothing is, and the caller moves to the next route. The only fall-through.
//   - false, an error: this process could not tell. EACCES is the live case - the credstore
//     directories are root:root 0700 - and "could not tell" must never collapse into "absent".
func credstoreEntryExists(path string) (bool, error) {
	fi, err := os.Stat(filepath.Clean(path))
	switch {
	case err == nil:
		return !fi.IsDir(), nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// credsDecryptArgs is the child's argv, as its own function so a test can assert the shape without
// running anything. The trailing "-" is the decision: the plaintext goes to stdout and this process
// reads it from a pipe. There is no output path in this argv, and there must never be one - a
// temporary file is the single thing the chosen mechanism was chosen to avoid, and it would survive
// a crash between the write and the unlink.
func credsDecryptArgs(name, path string) []string {
	return []string{"systemd-creds", "decrypt", "--name=" + name, path, "-"}
}

// systemdCredsDecrypt runs the child and returns what it wrote to stdout. cmd.Output() gives the
// pipe; nothing is written to disk by this process.
func systemdCredsDecrypt(name, path string) ([]byte, error) {
	argv := credsDecryptArgs(name, path)
	//nolint:gosec // G204: argv[0] is a fixed program name and the two variable parts are a
	// credential name and a credstore path this process resolved, never caller-supplied text.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		// Deliberately not including the child's stderr: systemd-creds is not expected to print key
		// material, but an error path that forwards an unbounded child's output into a message that
		// reaches a log is not a guarantee this code can make.
		return nil, err
	}
	return out, nil
}

// kekFileSlotOpener is the SlotOpener for a kek-file slot. It holds the resolved KEK, or the reason
// it could not be resolved.
//
// The KEK is resolved once, when the opener is built, and kept for the opener's lifetime. That is
// deliberate: the service's opener is built at startup and used to open both the vault and the
// keyring, and re-resolving per slot would mean a second systemd-creds child per open. The KEK is
// therefore in this process's memory for its lifetime - exactly as the argon2id-derived file key
// already is, and for the same reason: the key derived from it outlives the bytes anyway.
type kekFileSlotOpener struct {
	kek   []byte
	route string
	err   error
}

// kekFileOpener returns the opener for this host's kek-file slot, or nil when this host has none.
//
// nil means one thing only: "there is no kek-file slot here, fall through to the passphrase". A KEK
// that is configured and unreachable is NOT nil - the opener is returned carrying the refusal, so
// the open flow reports it instead of quietly asking for a passphrase.
func kekFileOpener(opts HostKeyOptions) SlotOpener {
	kek, route, err := resolveKEK(opts)
	if err == nil && kek == nil {
		return nil
	}
	return &kekFileSlotOpener{kek: kek, route: route, err: err}
}

// Type is the only thing about this opener that may be logged or printed.
func (*kekFileSlotOpener) Type() string { return slotTypeKEKFile }

// Route is the closed-set value for the `reason` field of the structured line the mutator writes.
// It is never a path and never a byte of the key.
func (o *kekFileSlotOpener) Route() string { return o.route }

// Unwrap recovers the DEK from the slot's nonce and ciphertext under the resolved KEK.
func (o *kekFileSlotOpener) Unwrap(slot Slot, aad []byte) ([]byte, error) {
	if o.err != nil {
		return nil, o.err
	}
	if slot.Type != slotTypeKEKFile {
		return nil, fmt.Errorf("%w: the kek-file opener was handed a slot of another type", errCorrupt)
	}
	// The same decode as the passphrase slot's: one definition of what a symmetric wrap's two fields
	// must be, so the two slot types cannot disagree about a nonce of the wrong length.
	nonce, ct, err := symmetricWrapBytes(slot)
	if err != nil {
		return nil, err
	}
	return openSlot(o.kek, nonce, ct, aad)
}
