package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"claude-utilities/internal/vault"
)

// Tests for the `vault` dispatch and its two read-only commands, `status` and `verify`.
//
// Every v2 fixture here is built by writeV2Fixture from the format's own primitives rather than by
// calling into internal/vault, and that is deliberate: `vault init` (the only creator of a v2 file)
// is a later PR, and a fixture built out here pins the byte format from OUTSIDE the package that
// writes it. If internal/vault ever changes what it emits, these fixtures stop opening.
//
// Nothing in this file touches a real data dir, a real credstore or a host's live vault: every path
// is under t.TempDir() and the only machine key in sight is a 32-byte temp file named by
// CLAUDESWAP_KEK_FILE.

const (
	// fixturePass is the passphrase every fixture is sealed under.
	fixturePass = "fixture-passphrase"
	// fixtureCreated is the one `created` stamp, so a fixture is byte-reproducible.
	fixtureCreated = "2026-11-07T12:00:00Z"
	// The argon2id floor the parser accepts: a real derivation, in microseconds.
	fixtureArgonT = 1
	fixtureArgonM = 8
	fixtureArgonP = 1
)

// fixSpec is one slot writeV2Fixture should write. Exactly one of pass and kek says what kind it is.
type fixSpec struct {
	id   string // 8 raw bytes
	pass string
	kek  []byte
}

// fixHeader mirrors the v2 header's shape. It is a local copy on purpose: a test that marshalled
// internal/vault's own types would be asserting that package against itself.
type fixHeader struct {
	V     int               `json:"v"`
	DEK   fixDEK            `json:"dek"`
	Slots []json.RawMessage `json:"slots"`
}

type fixDEK struct {
	ID      string `json:"id"`
	Created string `json:"created"`
}

type fixSlot struct {
	ID       string     `json:"id"`
	Type     string     `json:"type"`
	Name     string     `json:"name,omitempty"`
	Created  string     `json:"created"`
	Argon2id *fixArgon  `json:"argon2id,omitempty"`
	Wrap     fixWrapped `json:"wrap"`
}

type fixArgon struct {
	T    uint32 `json:"t"`
	M    uint32 `json:"m"`
	P    uint32 `json:"p"`
	Salt string `json:"salt"`
}

type fixWrapped struct {
	Nonce string `json:"nonce,omitempty"`
	CT    string `json:"ct,omitempty"`
}

func fixB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// writeV2Fixture writes a v2 sealed file: magic | hdrLen | header JSON | nonce | GCM(DEK, payload),
// with each slot's wrap sealed under HKDF(KEK, dek.id, "claude-swap/slot-wrap/v2" || slotAAD).
func writeV2Fixture(t *testing.T, path, magicStr string, specs []fixSpec, payload []byte) {
	t.Helper()
	dek := bytes.Repeat([]byte{0xd4}, 32)
	dekID := []byte("0123456789abcdef")
	salt := []byte("abcdefghijklmnop")

	elems := make([]json.RawMessage, 0, len(specs))
	for _, sp := range specs {
		if len(sp.id) != 8 {
			t.Fatalf("fixture slot id %q is %d bytes, want 8", sp.id, len(sp.id))
		}
		slot := fixSlot{ID: fixB64([]byte(sp.id)), Created: fixtureCreated}
		var kek []byte
		switch {
		case sp.pass != "":
			slot.Type = "passphrase"
			slot.Argon2id = &fixArgon{T: fixtureArgonT, M: fixtureArgonM, P: fixtureArgonP, Salt: fixB64(salt)}
			kek = argon2.IDKey([]byte(sp.pass), salt, fixtureArgonT, fixtureArgonM, fixtureArgonP, 32)
		default:
			slot.Type = "kek-file"
			slot.Name = "vault-kek"
			kek = sp.kek
		}
		aad := fixSlotAAD(magicStr, dekID, []byte(sp.id), slot.Type)
		wk, err := hkdf.Key(sha256.New, kek, dekID, "claude-swap/slot-wrap/v2"+string(aad), 32)
		if err != nil {
			t.Fatalf("hkdf: %v", err)
		}
		nonce := bytes.Repeat([]byte{byte(len(elems) + 1)}, 12)
		slot.Wrap = fixWrapped{Nonce: fixB64(nonce), CT: fixB64(fixSeal(t, wk, nonce, dek, aad))}
		enc, err := json.Marshal(slot)
		if err != nil {
			t.Fatalf("marshal slot: %v", err)
		}
		elems = append(elems, enc)
	}
	header, err := json.Marshal(fixHeader{V: 2, DEK: fixDEK{ID: fixB64(dekID), Created: fixtureCreated}, Slots: elems})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	raw := append([]byte(magicStr), make([]byte, 4)...)
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(header)))
	raw = append(raw, header...)

	pnonce := bytes.Repeat([]byte{0x9f}, 12)
	out := append(append([]byte(nil), raw...), pnonce...)
	out = append(out, fixSeal(t, dek, pnonce, payload, raw)...)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// fixSlotAAD is the format's slot AAD: magic || 0x10 || dek.id || 0x08 || slot.id || len(type) || type.
func fixSlotAAD(magicStr string, dekID, slotID []byte, slotType string) []byte {
	out := append([]byte(nil), magicStr...)
	out = append(out, byte(len(dekID)))
	out = append(out, dekID...)
	out = append(out, byte(len(slotID)))
	out = append(out, slotID...)
	out = append(out, byte(len(slotType)))
	return append(out, slotType...)
}

func fixSeal(t *testing.T, key, nonce, plain, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	return aead.Seal(nil, nonce, plain, aad)
}

// emptyAccounts is the payload of a vault with no accounts in it.
func emptyAccounts() []byte { return []byte(`[]`) }

// v2DataDir is a data dir holding a v2 vault.bin with the slots given, and nothing else.
func v2DataDir(t *testing.T, specs ...fixSpec) string {
	t.Helper()
	dir := t.TempDir()
	// Every environment input these commands read is pinned, so no test here can be decided by the
	// machine it runs on: no inherited passphrase, no credentials directory, no KEK file.
	t.Setenv(keyEnv, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("CLAUDESWAP_KEK_FILE", "")
	writeV2Fixture(t, filepath.Join(dir, "vault.bin"), "CSV2", specs, emptyAccounts())
	return dir
}

// withKEKFile points CLAUDESWAP_KEK_FILE at a temp file holding kek, which is what gives this host a
// kek-file opener without a credstore, a unit or root.
func withKEKFile(t *testing.T, kek []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(p, kek, 0o600); err != nil {
		t.Fatalf("write kek file: %v", err)
	}
	t.Setenv("CLAUDESWAP_KEK_FILE", p)
}

func fixtureKEK() []byte { return bytes.Repeat([]byte{0x7e}, 32) }

// --- the dispatch ---

// A bare flag run is not a subcommand. scripts/start-server.ps1 and the e2e start script pass
// --listen with no subcommand, and they must keep working exactly as written.
func TestBareFlagsStillReachTheFlagParser(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), []string{"--listen", "127.0.0.1:1"},
		func(string) string { return "" }, strings.NewReader(""), &out)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(out.String(), keyEnv) {
		t.Fatalf("a bare flag run did not reach the flag parser: %q", out.String())
	}
}

// A name that is not in the fixed set is not an error of its own: it goes to the flag parser and
// fails there, which is the shape main.go has always had.
func TestUnknownSubcommandNameGoesToTheFlagParser(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), []string{"wibble"},
		func(string) string { return "" }, strings.NewReader(""), &out)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(out.String(), "--listen") {
		t.Fatalf("an unknown name did not reach the flag parser: %q", out.String())
	}
}

// set-password keeps today's exact-compare dispatch.
func TestSetPasswordStillDispatches(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	code := run(context.Background(), []string{"set-password", "--data-dir", dir},
		func(string) string { return "" }, strings.NewReader("a-long-enough-password\n"), &out)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if _, err := os.Stat(passwordPath(dir)); err != nil {
		t.Fatalf("set-password did not write the hash: %v", err)
	}
}

// The invariant, in both directions: every name in the table resolves to a real handler, and every
// handler is one of the five names the fixed set allows. `service` joins the table in slice 4 and
// re-runs this test; a name with no owner, or an owner with no name, fails here.
func TestEveryRegisteredDispatchNameResolvesToACommand(t *testing.T) {
	table := dispatchTable()
	fixed := map[string]bool{"run": true, "service": true, "vault": true, "cert": true, "set-password": true}
	for name, handler := range table {
		if !fixed[name] {
			t.Fatalf("the dispatch table registers %q, which is not in the fixed name set", name)
		}
		if handler == nil {
			t.Fatalf("the dispatch table registers %q with no handler", name)
		}
	}
	for _, name := range []string{"run", "vault", "cert", "set-password"} {
		if _, ok := table[name]; !ok {
			t.Fatalf("the dispatch table has no entry for %q", name)
		}
	}
}

// The `vault` command with no subcommand prints its usage and exits 2, like `cert` does.
func TestVaultWithNoSubcommandPrintsUsage(t *testing.T) {
	var out bytes.Buffer
	if code := vaultCmd(nil, strings.NewReader(""), &out, &out); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(out.String(), "status") || !strings.Contains(out.String(), "verify") {
		t.Fatalf("the usage names neither status nor verify: %q", out.String())
	}
}

// A default console run must not gain ANY way to write v2 from this slice. serve() builds exactly
// this key source (main.go), create-on-open stays v1, and the first save a console run makes is
// therefore a CSV1 file - with or without the `vault` commands on the binary. `vault init` is the
// only creator of a v2 file and it is not in this PR.
func TestADefaultConsoleRunStillWritesV1(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(keyEnv, "a-console-passphrase")
	ks := vault.EnvKey(keyEnv)
	if ks.Machine() != nil {
		t.Fatalf("the console key source offers a machine opener; a console run must have none")
	}
	v, err := vault.Open(filepath.Join(dir, "vault.bin"), ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(vault.Account{ID: "a1", Label: "one", Identity: "x"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "vault.bin"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(data[:4]); got != "CSV1" {
		t.Fatalf("a console run wrote magic %q, want CSV1", got)
	}
	// And the new commands say so rather than quietly working on it.
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 || !strings.Contains(out.String(), "migrate") {
		t.Fatalf("status on a v1 vault: exit %d: %s", code, out.String())
	}
}

// --- --data-dir and the service's copy of it (Decision 10) ---

// The flag is this run's instruction and outranks the registered service's value.
func TestDataDirFlagWinsOverTheRegisteredService(t *testing.T) {
	prev := serviceDataDir
	serviceDataDir = func() (string, bool, error) { return "C:\\from-the-scm", true, nil }
	t.Cleanup(func() { serviceDataDir = prev })
	dir, fromService, err := dataDirFromFlagOrService("D:\\from-the-flag")
	if err != nil {
		t.Fatalf("dataDirFromFlagOrService: %v", err)
	}
	if dir != "D:\\from-the-flag" || fromService {
		t.Fatalf("dir = %q fromService = %v", dir, fromService)
	}
}

// With no flag, the registered service's value is the source of truth, so console, CLI and service
// agree on one vault.
func TestDataDirFallsBackToTheRegisteredService(t *testing.T) {
	prev := serviceDataDir
	serviceDataDir = func() (string, bool, error) { return "C:\\from-the-scm", true, nil }
	t.Cleanup(func() { serviceDataDir = prev })
	dir, fromService, err := dataDirFromFlagOrService("")
	if err != nil {
		t.Fatalf("dataDirFromFlagOrService: %v", err)
	}
	if dir != "C:\\from-the-scm" || !fromService {
		t.Fatalf("dir = %q fromService = %v", dir, fromService)
	}
}

// No flag and no registered service: today's default, unchanged.
func TestDataDirFallsBackToTheDefaultWithNoService(t *testing.T) {
	prev := serviceDataDir
	serviceDataDir = func() (string, bool, error) { return "", false, nil }
	t.Cleanup(func() { serviceDataDir = prev })
	dir, fromService, err := dataDirFromFlagOrService("")
	if err != nil {
		t.Fatalf("dataDirFromFlagOrService: %v", err)
	}
	if dir != defaultDataDir() || fromService {
		t.Fatalf("dir = %q fromService = %v", dir, fromService)
	}
}

// --- status ---

func TestVaultStatusListsSlotsByTypeAndID(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	text := out.String()
	for _, want := range []string{"passphrase", "kek-file", fixB64([]byte("slot0001")), fixB64([]byte("slot0002"))} {
		if !strings.Contains(text, want) {
			t.Fatalf("status does not name %q: %s", want, text)
		}
	}
	// Never a wrap, a blob or a passphrase.
	for _, secret := range []string{fixturePass, "ct", base64.StdEncoding.EncodeToString(fixtureKEK())} {
		if secret == "ct" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Fatalf("status printed %q: %s", secret, text)
		}
	}
	if strings.Contains(text, `"wrap"`) {
		t.Fatalf("status printed a wrap: %s", text)
	}
}

func TestVaultStatusNamesUnwrappableSlotsForThisHost(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	withKEKFile(t, fixtureKEK())
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	lines := strings.Split(out.String(), "\n")
	var kekLine, passLine string
	for _, l := range lines {
		if strings.Contains(l, fixB64([]byte("slot0002"))) {
			kekLine = l
		}
		if strings.Contains(l, fixB64([]byte("slot0001"))) {
			passLine = l
		}
	}
	if !strings.Contains(kekLine, "this host holds a key") {
		t.Fatalf("the kek-file slot is not reported as unwrappable here: %q", kekLine)
	}
	if !strings.Contains(passLine, "passphrase") || strings.Contains(passLine, "this host holds a key") {
		t.Fatalf("the passphrase slot must not be reported as machine-unwrappable: %q", passLine)
	}
}

func TestVaultStatusListsV1ArtefactsWithAgeAndTheFinalizeLine(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	// A v1 copy of the kind `migrate` leaves behind.
	v1 := append([]byte("CSV1"), bytes.Repeat([]byte{0x11}, 16+12+16)...)
	name := "vault.bin.v1.20261101T120000Z"
	if err := os.WriteFile(filepath.Join(dir, name), v1, 0o600); err != nil {
		t.Fatalf("write v1 copy: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, name), old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	text := out.String()
	if !strings.Contains(text, name) {
		t.Fatalf("status does not list the v1 artefact: %s", text)
	}
	if !strings.Contains(text, "48h") && !strings.Contains(text, "2d") {
		t.Fatalf("status does not give the artefact's age: %s", text)
	}
	if !strings.Contains(text, "finalize-migration") {
		t.Fatalf("status does not print the finalize line: %s", text)
	}
}

func TestVaultStatusReportsAnInterruptedVaultOp(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	if err := vault.WriteVaultOp(dir, vault.VaultOp{
		Op: "rotate", Files: []string{"vault.bin"}, Stage: vault.StageRenamed}); err != nil {
		t.Fatalf("WriteVaultOp: %v", err)
	}
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	text := out.String()
	if !strings.Contains(text, vault.VaultOpFileName) || !strings.Contains(text, "rotate") {
		t.Fatalf("status does not report the interrupted operation: %s", text)
	}
	if !strings.Contains(text, "verify --all-slots") {
		t.Fatalf("status does not name the verify a journal is handed to: %s", text)
	}
}

// status is read-only, so it runs while the service holds the data-dir lock. That is the whole
// reason it exists: the first thing an operator does to a server that will not start.
func TestVaultStatusTakesNoLock(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	lock, err := vault.AcquireLock(dir, "run")
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release() }()
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 {
		t.Fatalf("status exit %d while the lock was held, want 0: %s", code, out.String())
	}
}

func TestVaultStatusReportsAMixedPair(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	v1ring := append([]byte("CSK1"), bytes.Repeat([]byte{0x11}, 16+12+16)...)
	if err := os.WriteFile(filepath.Join(dir, vault.KeyringFileName), v1ring, 0o600); err != nil {
		t.Fatalf("write v1 keyring: %v", err)
	}
	var out bytes.Buffer
	if code := vaultStatus(dir, &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "disagree") {
		t.Fatalf("status does not report the mixed pair: %s", out.String())
	}
}

// --- verify ---

func TestVaultVerifyTakesNoLockAndOpensWithTheMachineSlot(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	withKEKFile(t, fixtureKEK())
	lock, err := vault.AcquireLock(dir, "run")
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release() }()
	var out bytes.Buffer
	// Empty stdin: the default verify must not need a passphrase at all.
	if code := vaultVerify(dir, false, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), fixB64([]byte("slot0002"))) {
		t.Fatalf("verify does not name the slot that opened the file: %s", out.String())
	}
}

func TestVaultVerifyAllSlotsPromptsAndOpensEachInTurn(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass}, fixSpec{id: "slot0002", kek: fixtureKEK()})
	withKEKFile(t, fixtureKEK())
	var out bytes.Buffer
	code := vaultVerify(dir, true, strings.NewReader(fixturePass+"\n"), &out)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	text := out.String()
	for _, id := range []string{fixB64([]byte("slot0001")), fixB64([]byte("slot0002"))} {
		if !strings.Contains(text, id) {
			t.Fatalf("verify --all-slots does not report slot %s: %s", id, text)
		}
	}
	if strings.Contains(text, fixturePass) {
		t.Fatalf("verify printed the passphrase: %s", text)
	}
}

func TestVaultVerifyExitsThreeWhenNoSlotOpens(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	var out bytes.Buffer
	if code := vaultVerify(dir, true, strings.NewReader("not-the-passphrase\n"), &out); code != 3 {
		t.Fatalf("exit %d, want 3: %s", code, out.String())
	}
}

func TestVaultVerifyExitsFourOnAV1OrAbsentFile(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		var out bytes.Buffer
		if code := vaultVerify(t.TempDir(), false, strings.NewReader(""), &out); code != 4 {
			t.Fatalf("exit %d, want 4: %s", code, out.String())
		}
	})
	t.Run("v1", func(t *testing.T) {
		dir := t.TempDir()
		v1 := append([]byte("CSV1"), bytes.Repeat([]byte{0x11}, 16+12+16)...)
		if err := os.WriteFile(filepath.Join(dir, "vault.bin"), v1, 0o600); err != nil {
			t.Fatalf("write v1: %v", err)
		}
		var out bytes.Buffer
		if code := vaultVerify(dir, false, strings.NewReader(""), &out); code != 4 {
			t.Fatalf("exit %d, want 4: %s", code, out.String())
		}
		if !strings.Contains(out.String(), "migrate") {
			t.Fatalf("verify on a v1 file does not name migrate: %s", out.String())
		}
	})
}

// A malformed header is exit 2 for THIS command, deliberately apart from the service's exit 4: the
// operator ran a read-only check by hand and the answer is about the file they named, not a service
// the supervisor must stop restarting.
func TestVaultVerifyExitsTwoOnAMalformedHeader(t *testing.T) {
	dir := t.TempDir()
	bad := append([]byte("CSV2"), make([]byte, 4)...)
	binary.BigEndian.PutUint32(bad[4:8], 9)
	bad = append(bad, []byte("not json!")...)
	bad = append(bad, bytes.Repeat([]byte{0x00}, 12+16)...)
	if err := os.WriteFile(filepath.Join(dir, "vault.bin"), bad, 0o600); err != nil {
		t.Fatalf("write malformed: %v", err)
	}
	var out bytes.Buffer
	if code := vaultVerify(dir, false, strings.NewReader(""), &out); code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, out.String())
	}
}

func TestVaultVerifyNeverPrintsPayload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("CLAUDESWAP_KEK_FILE", "")
	payload := []byte(`[{"id":"a1","label":"a-very-secret-label","identity":"nobody@example.com",` +
		`"block":{"accessToken":"tok-do-not-print"},"updated":"2026-11-07T12:00:00Z"}]`)
	writeV2Fixture(t, filepath.Join(dir, "vault.bin"), "CSV2", []fixSpec{{id: "slot0001", pass: fixturePass}}, payload)
	var out bytes.Buffer
	if code := vaultVerify(dir, true, strings.NewReader(fixturePass+"\n"), &out); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out.String())
	}
	for _, secret := range []string{"a-very-secret-label", "nobody@example.com", "tok-do-not-print"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("verify printed %q: %s", secret, out.String())
		}
	}
}

func TestVaultVerifyReportsAMixedPair(t *testing.T) {
	dir := v2DataDir(t, fixSpec{id: "slot0001", pass: fixturePass})
	v1ring := append([]byte("CSK1"), bytes.Repeat([]byte{0x11}, 16+12+16)...)
	if err := os.WriteFile(filepath.Join(dir, vault.KeyringFileName), v1ring, 0o600); err != nil {
		t.Fatalf("write v1 keyring: %v", err)
	}
	var out bytes.Buffer
	code := vaultVerify(dir, true, strings.NewReader(fixturePass+"\n"), &out)
	if code == 0 {
		t.Fatalf("verify on a mixed pair exited 0: %s", out.String())
	}
	if !strings.Contains(out.String(), "disagree") {
		t.Fatalf("verify does not report the mixed pair: %s", out.String())
	}
}
