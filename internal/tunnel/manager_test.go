package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

type mgr struct {
	m   *Manager
	r   *fakeRunner
	kr  *vault.Keyring
	dir string
	log *bytes.Buffer
}

func newMgr(t *testing.T) *mgr {
	t.Helper()
	t.Setenv("CSTUNNELKEY", "a-long-test-passphrase")
	dir := t.TempDir()
	kr, err := vault.OpenKeyring(filepath.Join(dir, vault.KeyringFileName), "CSTUNNELKEY")
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	r := newFakeRunner()
	r.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute }
	buf := &bytes.Buffer{}
	m, err := NewManager(Options{DataDir: dir, Runner: r, Log: logx.New(buf),
		Grace: 10 * time.Millisecond, Delay: func(int) time.Duration { return 5 * time.Millisecond }}, kr)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return &mgr{m: m, r: r, kr: kr, dir: dir, log: buf}
}

func (x *mgr) add(t *testing.T, label, addr, user string) View {
	t.Helper()
	v, err := x.m.Add(Spec{Label: label, Address: addr, User: user})
	if err != nil {
		t.Fatalf("Add %s: %v", label, err)
	}
	return v
}

func TestManagerAddGivesAKeyAnInstallCommandAndLeavesTheTunnelOff(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	if v.ID == "" || !strings.HasPrefix(v.ID, "tun-") {
		t.Fatalf("no generated id: %q", v.ID)
	}
	if !v.HasKey || v.Fingerprint == "" || len(v.Short) != 8 {
		t.Fatalf("no key or fingerprint: %+v", v)
	}
	if v.Enabled {
		t.Fatal("a new tunnel must not be enabled before the operator has pasted the command")
	}
	if v.Install == "" || v.Remove == "" || v.InstallTight == "" {
		t.Fatal("the generated commands are missing")
	}
	if !strings.Contains(v.InstallTight, `permitopen="127.0.0.1:1"`) {
		t.Fatal("the tightened option is not offered")
	}
	if strings.Contains(v.Install, `permitopen=`) {
		t.Fatal("the recommended command must not carry the unverified option")
	}
	// Enabling before the host key is seeded is refused rather than left to fail on the dial.
	if _, err := x.m.SetEnabled(v.ID, true); err == nil {
		t.Fatal("enabling a tunnel with no seeded host key was allowed")
	}
	if x.r.count() != 0 {
		t.Fatalf("Add spawned %d children", x.r.count())
	}
}

func TestManagerRefusesADuplicateLabelAndABadSpec(t *testing.T) {
	x := newMgr(t)
	x.add(t, "SRL-LIN", secretAddress, secretUser)
	if _, err := x.m.Add(Spec{Label: "srl-lin", Address: "other.invalid", User: "u"}); err == nil {
		t.Fatal("a duplicate label, differing only in case, was accepted")
	}
	if _, err := x.m.Add(Spec{Label: "X", Address: "a b", User: "u"}); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("want ErrBadAddress, got %v", err)
	}
	if n := len(x.m.List()); n != 1 {
		t.Fatalf("List has %d tunnels, want 1", n)
	}
}

func TestManagerConfigurationSurvivesARestart(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	if _, err := x.m.SeedHostKey(v.ID, testHostKey(t)); err != nil {
		t.Fatalf("SeedHostKey: %v", err)
	}
	if _, err := x.m.SetEnabled(v.ID, true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	// A fresh Manager over the same keyring file is what a server restart looks like.
	kr2, err := vault.OpenKeyring(filepath.Join(x.dir, vault.KeyringFileName), "CSTUNNELKEY")
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	r2 := newFakeRunner()
	r2.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute }
	m2, err := NewManager(Options{DataDir: x.dir, Runner: r2, Log: logx.New(&bytes.Buffer{}),
		Grace: 10 * time.Millisecond, Delay: func(int) time.Duration { return 5 * time.Millisecond }}, kr2)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	got, ok := m2.Get(v.ID)
	if !ok {
		t.Fatal("the configuration did not survive the restart")
	}
	if got.Address != secretAddress || got.User != secretUser || !got.Enabled || !got.HasHostKey {
		t.Fatalf("the restored tunnel lost fields: %+v", got)
	}
	if got.Fingerprint != v.Fingerprint {
		t.Fatal("the restored tunnel has a different key")
	}
	// The configuration must not be readable without the passphrase.
	raw, err := os.ReadFile(filepath.Join(x.dir, vault.KeyringFileName))
	if err != nil {
		t.Fatalf("read keyring: %v", err)
	}
	for _, bad := range []string{secretAddress, secretUser} {
		if bytes.Contains(raw, []byte(bad)) {
			t.Fatalf("%q is on disk in the clear", bad)
		}
	}
	m2.Start(t.Context())
	m2.Stop()
}

func TestManagerRotationKeepsTheOldLineUntilCommitted(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	before := v.Install

	rot, err := x.m.RotateKey(v.ID)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if !rot.Rotating {
		t.Fatal("the view does not report the rotation")
	}
	if rot.RotateInstall == "" {
		t.Fatal("the install command for the new key is missing")
	}
	if rot.Install != before {
		t.Fatal("the command for the key still in service changed during the overlap")
	}
	if rot.RotateInstall == rot.Install {
		t.Fatal("the new key's command is the same as the old one's")
	}
	// Rotating again before committing is refused.
	if _, err := x.m.RotateKey(v.ID); err == nil {
		t.Fatal("a second rotation was stacked on an unfinished one")
	}
	done, err := x.m.CommitRotation(v.ID)
	if err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	if done.Rotating || done.RotateInstall != "" {
		t.Fatal("the view still reports a rotation after the commit")
	}
	if done.Install == before {
		t.Fatal("after the commit the install command is still the old key's")
	}
}

func TestManagerCancelRotationGoesBackToTheKeyInService(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	if _, err := x.m.RotateKey(v.ID); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	back, err := x.m.CancelRotation(v.ID)
	if err != nil {
		t.Fatalf("CancelRotation: %v", err)
	}
	if back.Rotating || back.Fingerprint != v.Fingerprint {
		t.Fatalf("cancelling did not restore the original key: %+v", back)
	}
}

func TestManagerRevokeIsHonestAboutTheLineStillBeingOnTheHost(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	wantRemove := v.Remove

	rv, err := x.m.RevokeKey(v.ID)
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if rv.State != StateRevokePending {
		t.Fatalf("state = %q, want %q", rv.State, StateRevokePending)
	}
	if !rv.RevokePending || rv.Enabled {
		t.Fatalf("a revoked tunnel must be off and flagged: %+v", rv)
	}
	if rv.HasKey {
		t.Fatal("the view still claims a key after a revoke")
	}
	if rv.Remove != wantRemove {
		t.Fatal("the remove command is not still available after the revoke")
	}
	// The private key really is gone.
	if _, ok := x.kr.Seed(v.ID); ok {
		t.Fatal("the seed survived the revoke")
	}
	// And the reminder only clears when the operator says they ran it.
	ok2, err := x.m.ConfirmRevoked(v.ID)
	if err != nil {
		t.Fatalf("ConfirmRevoked: %v", err)
	}
	if ok2.RevokePending {
		t.Fatal("confirming did not clear the reminder")
	}
	// A revoked tunnel cannot be enabled until a key is generated again.
	if _, err := x.m.SetEnabled(v.ID, true); err == nil {
		t.Fatal("a tunnel with no key was enabled")
	}
	if _, err := x.m.GenerateKey(v.ID); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if got, _ := x.m.Get(v.ID); !got.HasKey || got.Install == "" {
		t.Fatal("generating a fresh key did not restore the install command")
	}
}

func TestManagerRateLimitsRestartAndKeyActions(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	if err := x.m.Restart(v.ID); err != nil {
		t.Fatalf("first Restart: %v", err)
	}
	if err := x.m.Restart(v.ID); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a second Restart inside 10 s returned %v, want ErrRateLimited", err)
	}
	if _, err := x.m.RotateKey(v.ID); err != nil {
		t.Fatalf("first RotateKey: %v", err)
	}
	if _, err := x.m.GenerateKey(v.ID); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a key action inside a minute returned %v, want ErrRateLimited", err)
	}
	// An unknown host is a not-found, not a rate limit.
	if err := x.m.Restart("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("want ErrUnknown, got %v", err)
	}
}

func TestManagerUpdateAndRemove(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	up, err := x.m.Update(v.ID, "moved.estate.invalid", "another", 9443)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if up.Address != "moved.estate.invalid" || up.User != "another" || up.Port != 9443 {
		t.Fatalf("Update did not take: %+v", up)
	}
	if _, err := x.m.Update(v.ID, "a b", "u", 0); err == nil {
		t.Fatal("Update accepted an invalid address")
	}
	if got, _ := x.m.Get(v.ID); got.Address == "a b" {
		t.Fatal("a refused Update changed the stored spec")
	}
	gone, err := x.m.Remove(v.ID)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if gone.Remove == "" {
		t.Fatal("Remove must hand back the command that takes the line off the host")
	}
	if _, ok := x.m.Get(v.ID); ok {
		t.Fatal("the tunnel is still configured")
	}
	if _, ok := x.kr.Seed(v.ID); ok {
		t.Fatal("the key survived Remove")
	}
	if _, err := x.m.Remove(v.ID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("want ErrUnknown, got %v", err)
	}
}

func TestManagerSeedHostKeyRefusesRubbish(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	if _, err := x.m.SeedHostKey(v.ID, "not a key"); !errors.Is(err, ErrBadHostKey) {
		t.Fatalf("want ErrBadHostKey, got %v", err)
	}
	got, err := x.m.SeedHostKey(v.ID, testHostKey(t)+" root@box")
	if err != nil {
		t.Fatalf("SeedHostKey: %v", err)
	}
	if !got.HasHostKey || !strings.HasPrefix(got.HostKeyFingerprint, "SHA256:") {
		t.Fatalf("the host key was not recorded: %+v", got)
	}
	if _, err := x.m.SeedHostKey("nope", testHostKey(t)); !errors.Is(err, ErrUnknown) {
		t.Fatalf("want ErrUnknown, got %v", err)
	}
}

// The import must leave the interim supervisor's file in place: it is the rollback path for the
// scheduled task, so consuming it would remove the way back.
func TestManagerImportLeavesTheFileInPlaceAndIsIdempotent(t *testing.T) {
	x := newMgr(t)
	path := filepath.Join(t.TempDir(), "tunnels.json")
	body := `[{"name":"SRL-LIN","host":"` + secretAddress + `","user":"` + secretUser + `"},
	          {"name":"TSS","host":"two.estate.invalid","user":"other"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	added, skipped, err := x.m.ImportFile(path)
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if added != 2 || skipped != 0 {
		t.Fatalf("added %d skipped %d, want 2 and 0", added, skipped)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the host list was consumed: %v", err)
	}
	added2, skipped2, err := x.m.ImportFile(path)
	if err != nil {
		t.Fatalf("second ImportFile: %v", err)
	}
	if added2 != 0 || skipped2 != 2 {
		t.Fatalf("importing twice added %d skipped %d, want 0 and 2", added2, skipped2)
	}
	if got := x.m.Labels(); len(got) != 2 || got[0] != "SRL-LIN" || got[1] != "TSS" {
		t.Fatalf("labels = %v", got)
	}
	// Every imported tunnel is off and has a key waiting for its install command.
	for _, v := range x.m.List() {
		if v.Enabled || !v.HasKey || v.Install == "" {
			t.Fatalf("imported tunnel is not ready to onboard: %+v", v)
		}
	}
}

func TestManagerImportErrors(t *testing.T) {
	x := newMgr(t)
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.json")
	if _, _, err := x.m.ImportFile(missing); err == nil {
		t.Fatal("importing a missing file succeeded")
	} else if strings.Contains(err.Error(), missing) {
		t.Fatalf("the error echoes the path: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"not":"an array"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := x.m.ImportFile(bad); err == nil {
		t.Fatal("importing a non-array succeeded")
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := x.m.ImportFile(empty); err == nil {
		t.Fatal("importing an empty array succeeded")
	}
}

// The Hosts tab join must tolerate a missing partner in both directions: tunnel-first is the real
// onboarding order, so a tunnel can exist with no enrolled host and a host with no tunnel.
func TestStateByIDToleratesAMissingPartnerBothWays(t *testing.T) {
	x := newMgr(t)
	v := x.add(t, "SRL-LIN", secretAddress, secretUser)
	byID := x.m.StateByID()
	if _, ok := byID[v.ID]; !ok {
		t.Fatal("the tunnel is missing from the join map")
	}
	if _, ok := byID["h-enrolled-but-no-tunnel"]; ok {
		t.Fatal("the join map invented an entry for a host with no tunnel")
	}
	// A tunnel whose id is an enrolled host's id joins on that id, which is the other direction.
	v2, err := x.m.Add(Spec{ID: "h-real", Label: "TSS", Address: "two.estate.invalid", User: "other"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got := x.m.StateByID()["h-real"]; got.Label != "TSS" || got.ID != v2.ID {
		t.Fatalf("the join map lost the enrolled-host tunnel: %+v", got)
	}
}

func TestManagerNeedsAKeyring(t *testing.T) {
	if _, err := NewManager(Options{DataDir: t.TempDir(), Runner: newFakeRunner()}, nil); err == nil {
		t.Fatal("NewManager accepted a nil keyring")
	}
}

// A stored configuration that has been tampered into something invalid must not stop the server
// starting: the bad entries are dropped and the rest still run.
func TestManagerDropsAnInvalidStoredSpec(t *testing.T) {
	t.Setenv("CSTUNNELKEY", "a-long-test-passphrase")
	dir := t.TempDir()
	kr, err := vault.OpenKeyring(filepath.Join(dir, vault.KeyringFileName), "CSTUNNELKEY")
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	raw, err := json.Marshal([]Spec{
		{ID: "good", Label: "OK", Address: "ok.invalid", User: "u", Port: DefaultPort},
		{ID: "bad", Label: "BAD", Address: "a b", User: "u", Port: DefaultPort},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := kr.PutConfig(raw); err != nil {
		t.Fatalf("PutConfig: %v", err)
	}
	m, err := NewManager(Options{DataDir: dir, Runner: newFakeRunner(), Log: logx.New(&bytes.Buffer{})}, kr)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if got := m.Labels(); len(got) != 1 || got[0] != "OK" {
		t.Fatalf("labels = %v, want just [OK]", got)
	}
}
