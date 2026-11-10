package service

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// fakeHost is the whole of what the KEK drop-in writer asks of the machine: a file system, a way to
// run three commands, and who it is. No test here needs systemd, root or a real /etc.
type fakeHost struct {
	euid    int
	files   map[string]fakeFile
	dirs    map[string]fakeFile
	calls   []string // every mutation and every command, in order
	runErr  map[string]error
	created map[string][]byte // what encrypt returned, so decrypt can invert it
	// verifyErr is what Verify returns.
	verifyErr error
	// corruptRoundTrip makes decrypt return other bytes than were encrypted.
	corruptRoundTrip bool
	// writeErr makes the next WriteFile fail.
	writeErr error
}

type fakeFile struct {
	data  []byte
	uid   int
	mode  fs.FileMode
	isDir bool
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		files:   map[string]fakeFile{},
		dirs:    map[string]fakeFile{},
		runErr:  map[string]error{},
		created: map[string][]byte{},
	}
}

func (f *fakeHost) record(s string) { f.calls = append(f.calls, s) }

func (f *fakeHost) Euid() int { return f.euid }

func (f *fakeHost) WriteFile(p string, data []byte, mode fs.FileMode) error {
	f.record("write " + p)
	if f.writeErr != nil {
		return f.writeErr
	}
	f.files[p] = fakeFile{data: append([]byte(nil), data...), mode: mode}
	return nil
}

func (f *fakeHost) ReadFile(p string) ([]byte, error) {
	if fi, ok := f.files[p]; ok {
		return fi.data, nil
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}

func (f *fakeHost) Remove(p string) error {
	f.record("remove " + p)
	if _, ok := f.files[p]; !ok {
		return &fs.PathError{Op: "remove", Path: p, Err: fs.ErrNotExist}
	}
	delete(f.files, p)
	return nil
}

func (f *fakeHost) Stat(p string) (uid int, mode fs.FileMode, isDir bool, err error) {
	if fi, ok := f.files[p]; ok {
		return fi.uid, fi.mode, false, nil
	}
	if d, ok := f.dirs[p]; ok {
		return d.uid, d.mode, true, nil
	}
	return 0, 0, false, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}

func (f *fakeHost) MkdirAll(p string, mode fs.FileMode) error {
	f.record("mkdir " + p)
	f.dirs[p] = fakeFile{mode: mode, isDir: true}
	return nil
}

func (f *fakeHost) Run(stdin []byte, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.record("run " + call)
	if err, ok := f.runErr[name+" "+firstArg(args)]; ok {
		return nil, err
	}
	switch {
	case name == "systemd-creds" && firstArg(args) == "encrypt":
		ct := append([]byte("ct:"), stdin...)
		f.created[string(ct)] = append([]byte(nil), stdin...)
		return ct, nil
	case name == "systemd-creds" && firstArg(args) == "decrypt":
		if f.corruptRoundTrip {
			return []byte("not the same bytes"), nil
		}
		if pt, ok := f.created[string(stdin)]; ok {
			return pt, nil
		}
		return nil, errors.New("decrypt: unknown ciphertext")
	}
	return nil, nil
}

func (f *fakeHost) Verify(unit, dropIn string) error {
	f.record("verify")
	return f.verifyErr
}

func firstArg(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

func (f *fakeHost) indexOf(prefix string) int {
	for i, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func (f *fakeHost) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "write ") || strings.HasPrefix(c, "remove ") || strings.HasPrefix(c, "mkdir ") ||
			strings.HasPrefix(c, "run systemctl") {
			out = append(out, c)
		}
	}
	return out
}

func install(t *testing.T, h *fakeHost) {
	t.Helper()
	old := host
	host = h
	t.Cleanup(func() { host = old })
}

// rootHostWithCredential is a root-run host that already has the credential file a rung names.
func rootHostWithCredential(t *testing.T, r Rung) *fakeHost {
	t.Helper()
	h := newFakeHost()
	install(t, h)
	cred := credentialPath(r)
	h.dirs[credDir(r)] = fakeFile{uid: 0, mode: 0o700, isDir: true}
	h.files[cred] = fakeFile{data: []byte("kek"), uid: 0, mode: 0o600}
	return h
}

func TestSelectRungPrefersHostTPM2ThenHostThenPlain(t *testing.T) {
	for _, tc := range []struct {
		hasCreds, hasTPM2 bool
		want              Rung
	}{
		{true, true, RungHostTPM2},
		{true, false, RungHost}, // still an encrypted credential, not the plain file
		{false, false, RungPlain},
		{false, true, RungPlain}, // a TPM2 with no systemd-creds is not usable by this unit
	} {
		if got := SelectRung(tc.hasCreds, tc.hasTPM2); got != tc.want {
			t.Errorf("SelectRung(%v,%v) = %v, want %v", tc.hasCreds, tc.hasTPM2, got, tc.want)
		}
	}
	if Rung(0).Valid() {
		t.Error("the zero Rung must not be valid")
	}
}

func TestDropInHasExactlyOneCredentialLine(t *testing.T) {
	for _, r := range []Rung{RungHostTPM2, RungHost, RungPlain} {
		got := RenderKEKDropIn(r)
		n := 0
		for _, l := range lines(got) {
			if strings.HasPrefix(l, "LoadCredential") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("rung %v: %d credential lines, want exactly 1:\n%s", r, n, got)
		}
		if !hasLine(got, "[Service]") {
			t.Errorf("rung %v: no [Service] header", r)
		}
	}
	if RenderKEKDropIn(Rung(0)) != "" {
		t.Error("an invalid rung must render nothing, not a guess")
	}
}

func TestDropInForHostRungUsesLoadCredentialEncrypted(t *testing.T) {
	// The correction revision 8 item 1 exists for: the host-only rung is still an ENCRYPTED
	// credential. Handing it the plain directive would read ciphertext as the key.
	const enc = "LoadCredentialEncrypted=vault-kek:/etc/credstore.encrypted/claude-swap.vault-kek"
	const plain = "LoadCredential=vault-kek:/etc/credstore/claude-swap.vault-kek"
	for r, want := range map[Rung]string{RungHostTPM2: enc, RungHost: enc, RungPlain: plain} {
		if got := RenderKEKDropIn(r); !hasLine(got, want) {
			t.Errorf("rung %v: no line %q in\n%s", r, want, got)
		}
	}
	if hasLinePrefix(RenderKEKDropIn(RungHost), "LoadCredential=") {
		t.Error("the host rung carries the plain directive")
	}
}

func TestWriteDropInRunsDaemonReloadAfterWriting(t *testing.T) {
	h := rootHostWithCredential(t, RungHost)
	if err := WriteKEKDropIn(RungHost); err != nil {
		t.Fatal(err)
	}
	w, r := h.indexOf("write "+DropInPath), h.indexOf("run systemctl daemon-reload")
	if w < 0 || r < 0 || r < w {
		t.Fatalf("want the drop-in written then daemon-reload, got %q", h.calls)
	}
	if got := string(h.files[DropInPath].data); got != RenderKEKDropIn(RungHost) {
		t.Fatalf("drop-in content = %q", got)
	}
	if h.files[DropInPath].mode != 0o644 {
		t.Fatalf("drop-in mode = %v; it holds no secret and systemd reads it as root", h.files[DropInPath].mode)
	}
}

func TestWriteDropInRefusesACredentialThatIsNotThere(t *testing.T) {
	// A unit that names a credential that does not exist fails before ExecStart, so the drop-in is
	// never written ahead of the file it names.
	h := newFakeHost()
	install(t, h)
	err := WriteKEKDropIn(RungHost)
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("err = %v, want ErrCredentialMissing", err)
	}
	if got := h.mutations(); len(got) != 0 {
		t.Fatalf("a refused write still changed the host: %q", got)
	}
}

func TestWriteDropInRefusesACredentialOthersCanRead(t *testing.T) {
	h := rootHostWithCredential(t, RungPlain)
	h.files[credentialPath(RungPlain)] = fakeFile{uid: 0, mode: 0o644}
	if err := WriteKEKDropIn(RungPlain); !errors.Is(err, ErrCredentialMode) {
		t.Fatalf("err = %v, want ErrCredentialMode", err)
	}
	h.files[credentialPath(RungPlain)] = fakeFile{uid: 1000, mode: 0o600}
	if err := WriteKEKDropIn(RungPlain); !errors.Is(err, ErrCredentialMode) {
		t.Fatalf("not root-owned: err = %v, want ErrCredentialMode", err)
	}
	if got := h.mutations(); len(got) != 0 {
		t.Fatalf("a refused write still changed the host: %q", got)
	}
}

func TestWriteDropInNeedsRoot(t *testing.T) {
	h := rootHostWithCredential(t, RungHost)
	h.euid = 1000
	if err := WriteKEKDropIn(RungHost); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("err = %v, want ErrNeedsRoot", err)
	}
	if len(h.mutations()) != 0 {
		t.Fatal("a non-root write changed the host")
	}
}

func TestPlainKEKRewritesTheDropInAndRemovesTheEncryptedFile(t *testing.T) {
	h := rootHostWithCredential(t, RungHost)
	h.files[credentialPath(RungPlain)] = fakeFile{data: []byte("kek"), uid: 0, mode: 0o600}
	h.dirs[credDir(RungPlain)] = fakeFile{uid: 0, mode: 0o700, isDir: true}
	h.files[DropInPath] = fakeFile{data: []byte(RenderKEKDropIn(RungHost))}

	if err := SwitchToPlainKEK(); err != nil {
		t.Fatal(err)
	}
	if got := string(h.files[DropInPath].data); got != RenderKEKDropIn(RungPlain) {
		t.Fatalf("drop-in = %q, want the plain form", got)
	}
	if _, still := h.files[credentialPath(RungHost)]; still {
		t.Fatal("the encrypted credential it replaced is still there")
	}
	// Reload BEFORE the old file goes: a failure between the two must leave a drop-in that names a
	// file that exists.
	r, rm := h.indexOf("run systemctl daemon-reload"), h.indexOf("remove "+credentialPath(RungHost))
	if r < 0 || rm < 0 || rm < r {
		t.Fatalf("want daemon-reload then remove, got %q", h.calls)
	}
}

func TestPlainKEKWithNoPlainFileChangesNothing(t *testing.T) {
	h := rootHostWithCredential(t, RungHost)
	h.files[DropInPath] = fakeFile{data: []byte(RenderKEKDropIn(RungHost))}
	if err := SwitchToPlainKEK(); !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("err = %v, want ErrCredentialMissing", err)
	}
	if got := h.mutations(); len(got) != 0 {
		t.Fatalf("host changed: %q", got)
	}
	if _, ok := h.files[credentialPath(RungHost)]; !ok {
		t.Fatal("the encrypted credential was removed although the plain one is not there")
	}
}

func TestRemoveDropInOnTheLastKEKSlotAlsoReloads(t *testing.T) {
	h := newFakeHost()
	install(t, h)
	h.files[DropInPath] = fakeFile{data: []byte(RenderKEKDropIn(RungHost))}
	if err := RemoveKEKDropIn(); err != nil {
		t.Fatal(err)
	}
	if _, still := h.files[DropInPath]; still {
		t.Fatal("drop-in still there")
	}
	if h.indexOf("run systemctl daemon-reload") < 0 {
		t.Fatalf("no daemon-reload after the removal: %q", h.calls)
	}
}

func TestRemoveDropInWhenThereIsNoneIsNotAnError(t *testing.T) {
	h := newFakeHost()
	install(t, h)
	if err := RemoveKEKDropIn(); err != nil {
		t.Fatalf("removing nothing failed: %v", err)
	}
	if h.indexOf("run systemctl") >= 0 {
		t.Fatalf("reloaded although nothing changed: %q", h.calls)
	}
}

func TestPreflightNeedsRootAndRejectsAnInvalidRung(t *testing.T) {
	h := newFakeHost()
	h.euid = 1000
	install(t, h)
	if err := Preflight(RungHost); !errors.Is(err, ErrPreflight) {
		t.Fatalf("non-root: err = %v, want ErrPreflight", err)
	}
	if err := Preflight(Rung(0)); !errors.Is(err, ErrPreflight) {
		t.Fatalf("invalid rung: err = %v, want ErrPreflight", err)
	}
	if len(h.calls) != 0 {
		t.Fatalf("a refused preflight ran something: %q", h.calls)
	}
}

func TestPreflightRunsSystemdAnalyzeVerify(t *testing.T) {
	h := newFakeHost()
	install(t, h)
	if err := Preflight(RungHost); err != nil {
		t.Fatal(err)
	}
	if h.indexOf("verify") < 0 {
		t.Fatalf("no verify: %q", h.calls)
	}
	h2 := newFakeHost()
	h2.verifyErr = errors.New("bad unit")
	install(t, h2)
	if err := Preflight(RungHost); !errors.Is(err, ErrPreflight) {
		t.Fatalf("err = %v, want ErrPreflight", err)
	}
}

func TestPreflightAssertsTheCredentialOwnerAndMode(t *testing.T) {
	// root, 0600 on the file; its directory closed to others. Both are asserted when present.
	for name, tc := range map[string]struct {
		file, dir fakeFile
		wantErr   bool
	}{
		"good":         {fakeFile{uid: 0, mode: 0o600}, fakeFile{uid: 0, mode: 0o700, isDir: true}, false},
		"file open":    {fakeFile{uid: 0, mode: 0o640}, fakeFile{uid: 0, mode: 0o700, isDir: true}, true},
		"file owner":   {fakeFile{uid: 1000, mode: 0o600}, fakeFile{uid: 0, mode: 0o700, isDir: true}, true},
		"dir open":     {fakeFile{uid: 0, mode: 0o600}, fakeFile{uid: 0, mode: 0o755, isDir: true}, true},
		"dir owner":    {fakeFile{uid: 1000, mode: 0o600}, fakeFile{uid: 1000, mode: 0o700, isDir: true}, true},
		"dir g+x only": {fakeFile{uid: 0, mode: 0o600}, fakeFile{uid: 0, mode: 0o710, isDir: true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost()
			install(t, h)
			h.files[credentialPath(RungPlain)] = tc.file
			h.dirs[credDir(RungPlain)] = tc.dir
			err := Preflight(RungPlain)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrPreflight) {
				t.Fatalf("err = %v, want ErrPreflight", err)
			}
		})
	}
}

func TestPreflightRoundTripsAThrowawayCredentialForTheEncryptedForm(t *testing.T) {
	h := newFakeHost()
	install(t, h)
	if err := Preflight(RungHost); err != nil {
		t.Fatal(err)
	}
	e, d := h.indexOf("run systemd-creds encrypt"), h.indexOf("run systemd-creds decrypt")
	if e < 0 || d < 0 || d < e {
		t.Fatalf("want encrypt then decrypt, got %q", h.calls)
	}
	if !strings.Contains(h.calls[e], "--with-key=host") || strings.Contains(h.calls[e], "tpm2") {
		t.Fatalf("host rung encrypt used %q", h.calls[e])
	}
	h3 := newFakeHost()
	install(t, h3)
	if err := Preflight(RungHostTPM2); err != nil {
		t.Fatal(err)
	}
	if got := h3.calls[h3.indexOf("run systemd-creds encrypt")]; !strings.Contains(got, "--with-key=host+tpm2") {
		t.Fatalf("tpm2 rung encrypt used %q", got)
	}
	// The plain rung has no key to prove.
	h2 := newFakeHost()
	install(t, h2)
	if err := Preflight(RungPlain); err != nil {
		t.Fatal(err)
	}
	if h2.indexOf("run systemd-creds") >= 0 {
		t.Fatalf("plain rung ran systemd-creds: %q", h2.calls)
	}
	// A key that encrypts and does not decrypt back is the failure the round trip exists for.
	h4 := newFakeHost()
	h4.corruptRoundTrip = true
	install(t, h4)
	if err := Preflight(RungHost); !errors.Is(err, ErrPreflight) {
		t.Fatalf("a round trip that returns other bytes passed: err = %v", err)
	}
	h5 := newFakeHost()
	h5.runErr["systemd-creds encrypt"] = errors.New("exit status 1")
	install(t, h5)
	if err := Preflight(RungHost); !errors.Is(err, ErrPreflight) {
		t.Fatalf("an encrypt failure passed: err = %v", err)
	}
}

func TestPreflightThrowawayBytesAreRandomAndNeverTheRealKEK(t *testing.T) {
	var seen [][]byte
	for i := 0; i < 2; i++ {
		h := newFakeHost()
		install(t, h)
		if err := Preflight(RungHost); err != nil {
			t.Fatal(err)
		}
		for ct := range h.created {
			seen = append(seen, []byte(ct))
		}
	}
	if len(seen) != 2 || bytes.Equal(seen[0], seen[1]) {
		t.Fatalf("throwaway credential is not fresh each run: %q", seen)
	}
}

func TestPreflightFailureExitsTwoAndWritesNothing(t *testing.T) {
	h := newFakeHost()
	h.verifyErr = errors.New("bad unit")
	install(t, h)
	err := Preflight(RungHost)
	if !errors.Is(err, ErrPreflight) {
		t.Fatalf("err = %v", err)
	}
	if PreflightExitCode != 2 {
		t.Fatalf("PreflightExitCode = %d, want 2", PreflightExitCode)
	}
	if got := h.mutations(); len(got) != 0 {
		t.Fatalf("a failed preflight changed the host: %q", got)
	}
}

func TestSyncKEKDropInWritesTheFormTheHostHolds(t *testing.T) {
	// The encrypted credential wins when both exist: it is the stronger of the two.
	h := rootHostWithCredential(t, RungHost)
	h.files[credentialPath(RungPlain)] = fakeFile{uid: 0, mode: 0o600}
	r, wrote, err := SyncKEKDropIn()
	if err != nil || !wrote || r != RungHost {
		t.Fatalf("Sync = %v %v %v", r, wrote, err)
	}
	if got := string(h.files[DropInPath].data); got != RenderKEKDropIn(RungHost) {
		t.Fatalf("drop-in = %q", got)
	}

	h2 := rootHostWithCredential(t, RungPlain)
	r, wrote, err = SyncKEKDropIn()
	if err != nil || !wrote || r != RungPlain {
		t.Fatalf("plain Sync = %v %v %v", r, wrote, err)
	}
	_ = h2
}

func TestSyncKEKDropInDoesNothingWhenNoCredentialIsVisible(t *testing.T) {
	// A console run keyed by CLAUDESWAP_KEK_FILE, a non-root run, or a host with no credstore: no
	// credential this unit could name, so no drop-in and no error.
	h := newFakeHost()
	install(t, h)
	_, wrote, err := SyncKEKDropIn()
	if err != nil || wrote {
		t.Fatalf("Sync = %v %v, want a quiet no-op", wrote, err)
	}
	if len(h.mutations()) != 0 {
		t.Fatalf("host changed: %q", h.mutations())
	}
}

func TestSyncKEKDropInLeavesAnUpToDateDropInAlone(t *testing.T) {
	h := rootHostWithCredential(t, RungHost)
	h.files[DropInPath] = fakeFile{data: []byte(RenderKEKDropIn(RungHost))}
	_, wrote, err := SyncKEKDropIn()
	if err != nil || wrote {
		t.Fatalf("Sync = %v %v; an identical drop-in is not rewritten", wrote, err)
	}
	if len(h.mutations()) != 0 {
		t.Fatalf("host changed: %q", h.mutations())
	}
}

func TestDropInIsNeverWrittenWithoutTheCallerAskingToWrite(t *testing.T) {
	// Preflight, SelectRung and RenderKEKDropIn are the dry-run-safe surface: none of them mutates.
	h := rootHostWithCredential(t, RungHost)
	_ = Preflight(RungHost)
	_ = RenderKEKDropIn(SelectRung(true, false))
	if got := h.mutations(); len(got) != 0 {
		t.Fatalf("read-only surface changed the host: %q", got)
	}
}

func TestDropInPathAndCredentialNameAreNeverLogged(t *testing.T) {
	// Every error this package returns is a fixed sentence. An OS error carries the path it failed
	// on, so a raw %w would put /etc/credstore... into a log.
	h := rootHostWithCredential(t, RungHost)
	h.writeErr = &fs.PathError{Op: "open", Path: DropInPath, Err: fs.ErrPermission}
	err := WriteKEKDropIn(RungHost)
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, leak := range []string{DropInPath, "credstore", "claude-swap.vault-kek", "vault-kek", "/etc/"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err.Error(), leak)
		}
	}
	if !errors.Is(err, ErrDropIn) {
		t.Errorf("err = %v, want ErrDropIn", err)
	}

	h2 := newFakeHost()
	install(t, h2)
	for _, e := range []error{
		WriteKEKDropIn(RungHost), SwitchToPlainKEK(), Preflight(Rung(0)),
		func() error { h2.verifyErr = fmt.Errorf("x %s", DropInPath); return Preflight(RungHost) }(),
	} {
		if e == nil {
			continue
		}
		for _, leak := range []string{DropInPath, "claude-swap.vault-kek", "/etc/"} {
			if strings.Contains(e.Error(), leak) {
				t.Errorf("error %q leaks %q", e.Error(), leak)
			}
		}
	}
}

func TestEveryDropInPathNamesOneConstant(t *testing.T) {
	if DropInPath != "/etc/systemd/system/claude-swap-server.service.d/10-kek.conf" {
		t.Fatalf("DropInPath = %q", DropInPath)
	}
	if credentialPath(RungPlain) != "/etc/credstore/claude-swap.vault-kek" ||
		credentialPath(RungHost) != "/etc/credstore.encrypted/claude-swap.vault-kek" ||
		credentialPath(RungHostTPM2) != credentialPath(RungHost) {
		t.Fatal("credential paths drifted from the spec")
	}
}
