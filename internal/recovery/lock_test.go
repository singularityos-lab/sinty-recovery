package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/atom"
)

const runtimeTestPIN = "1234"

// spyCrypto swaps the crypto seam for call-counting stubs so a refused unlock can
// be proven to touch none of the primitives. It restores the seam on cleanup.
func spyCrypto(t *testing.T) (wipes, bits, verity *int) {
	t.Helper()
	w, b, v := 0, 0, 0
	ow, ob, ov, op, orv := cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity, cryptoVerifyPIN, cryptoReadVerityOff
	cryptoWipeVar = func() error { w++; return nil }
	cryptoSetUnlockBit = func() error { b++; return nil }
	cryptoDisableVerity = func() error { v++; return nil }
	cryptoReadVerityOff = func() (bool, error) { return true, nil }
	cryptoVerifyPIN = func(uid int, pin string) (bool, error) { return uid == 1000 && pin == runtimeTestPIN, nil }
	t.Cleanup(func() {
		cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity, cryptoVerifyPIN, cryptoReadVerityOff = ow, ob, ov, op, orv
	})
	return &w, &b, &v
}

func newLockCore(t *testing.T) *Core {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "data")
	esp := filepath.Join(root, "esp", "EFI", "atom")
	if err := os.MkdirAll(filepath.Join(dir, "boot", "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, dataMarker), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const installID = "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, installIDMarker), []byte(installID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(esp, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(esp, "state", "install-id"), []byte(installID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"deployment.json", "rootfs-active.erofs", "rootfs-active.hash"} {
		if err := os.WriteFile(filepath.Join(dir, "boot", "rootfs", name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return NewCore(Config{DataDir: dir, Dirs: atom.StageDirs{Rootfs: dir, ESP: esp}})
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// Case 1: unlock refused when not armed -> ok:false, and NO crypto primitive runs.
func TestUnlockRefusedWhenNotArmed(t *testing.T) {
	core := newLockCore(t)
	w, b, v := spyCrypto(t)
	srv := httptest.NewServer(newHandler(core))
	defer srv.Close()

	out := postJSON(t, srv, "/unlock-bootloader", map[string]any{"confirm": "UNLOCK"})
	if out["ok"] != false {
		t.Fatalf("not-armed unlock must be refused, got %v", out)
	}
	if *w != 0 || *b != 0 || *v != 0 {
		t.Fatalf("refused unlock touched crypto: wipe=%d bit=%d verity=%d", *w, *b, *v)
	}
	t.Logf("REFUSED (not armed): %v; crypto calls wipe=%d bit=%d verity=%d", out, *w, *b, *v)
}

// Case 2: unlock refused when confirm != "UNLOCK" even though armed -> NO crypto.
func TestUnlockRefusedWhenBadConfirm(t *testing.T) {
	core := newLockCore(t)
	w, b, v := spyCrypto(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("arm failed")
	}
	srv := httptest.NewServer(newHandler(core))
	defer srv.Close()

	out := postJSON(t, srv, "/unlock-bootloader", map[string]any{"confirm": "unlock"})
	if out["ok"] != false {
		t.Fatalf("bad confirm must be refused even when armed, got %v", out)
	}
	if *w != 0 || *b != 0 || *v != 0 {
		t.Fatalf("refused unlock touched crypto: wipe=%d bit=%d verity=%d", *w, *b, *v)
	}
	t.Logf("REFUSED (bad confirm, armed): %v; crypto calls wipe=%d bit=%d verity=%d", out, *w, *b, *v)
}

func TestUnlockRefusedWhenRecoveryPINIsWrong(t *testing.T) {
	core := newLockCore(t)
	w, b, v := spyCrypto(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("arm failed")
	}
	if ok, _ := core.UnlockBootloader("UNLOCK", "9999"); ok {
		t.Fatal("unlock succeeded with the wrong recovery PIN")
	}
	if *w != 0 || *b != 0 || *v != 0 {
		t.Fatalf("wrong recovery PIN touched crypto: wipe=%d bit=%d verity=%d", *w, *b, *v)
	}
}

// Case 3: a corrupt / unreadable consent flag is read as not-armed and locked
// (fail closed), never default-allow.
func TestLockStateFailsClosed(t *testing.T) {
	core := newLockCore(t)
	// Corrupt flag on the ESP.
	p := core.unlockFlagPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Default seam: cryptoReadLockBit returns an error (not implemented).
	s := core.LockState()
	if !s.Locked || s.UnlockArmed {
		t.Fatalf("corrupt flag + failed TPM read must be locked+not-armed, got %+v", s)
	}
	t.Logf("FAIL-CLOSED lock state on corrupt flag: %+v", s)
}

// Happy path only reaches crypto once both gates pass; here the seam succeeds.
func TestUnlockReachesCryptoWhenArmedAndConfirmed(t *testing.T) {
	core := newLockCore(t)
	w, b, v := spyCrypto(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("arm failed")
	}
	out := map[string]any{}
	ok, msg := core.UnlockBootloader("UNLOCK", runtimeTestPIN)
	out["ok"], out["message"] = ok, msg
	if !ok || *w != 1 || *b != 1 || *v != 1 {
		t.Fatalf("armed+confirmed unlock should run each primitive once, got ok=%v wipe=%d bit=%d verity=%d", ok, *w, *b, *v)
	}
	if core.readUnlockFlag().Armed {
		t.Fatal("consent flag must be cleared after a successful unlock")
	}
	if n := core.LockState().UnlockCount; n != 1 {
		t.Fatalf("unlock_count should advance to 1, got %d", n)
	}
	t.Logf("UNLOCKED: %v; crypto calls wipe=%d bit=%d verity=%d; count=%d", out, *w, *b, *v, core.LockState().UnlockCount)
}

func TestUnlockLeavesLockBitForLastAndFailsClosed(t *testing.T) {
	core := newLockCore(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("arm failed")
	}
	oldWipe, oldBit, oldVerity := cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity
	oldReadVerity, oldVerify := cryptoReadVerityOff, cryptoVerifyPIN
	var calls []string
	cryptoWipeVar = func() error { calls = append(calls, "wipe"); return nil }
	cryptoDisableVerity = func() error { calls = append(calls, "verity"); return nil }
	cryptoReadVerityOff = func() (bool, error) { return true, nil }
	cryptoVerifyPIN = func(uid int, pin string) (bool, error) { return uid == 1000 && pin == runtimeTestPIN, nil }
	cryptoSetUnlockBit = func() error { calls = append(calls, "bit"); return nil }
	t.Cleanup(func() {
		cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity = oldWipe, oldBit, oldVerity
		cryptoReadVerityOff, cryptoVerifyPIN = oldReadVerity, oldVerify
	})

	if ok, msg := core.UnlockBootloader("UNLOCK", runtimeTestPIN); !ok {
		t.Fatalf("unlock failed: %s", msg)
	}
	if got := strings.Join(calls, ","); got != "verity,wipe,bit" {
		t.Fatalf("crypto order=%s, want verity,wipe,bit", got)
	}

	core = newLockCore(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("second arm failed")
	}
	calls = nil
	cryptoDisableVerity = func() error { calls = append(calls, "verity"); return errors.New("TPM unavailable") }
	if ok, _ := core.UnlockBootloader("UNLOCK", runtimeTestPIN); ok {
		t.Fatal("unlock succeeded after verity failure")
	}
	if got := strings.Join(calls, ","); got != "verity" {
		t.Fatalf("lock bit changed after verity failure: calls=%s", got)
	}
}

func TestUnlockResumesAfterLateTPMFailure(t *testing.T) {
	core := newLockCore(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("arm failed")
	}
	oldWipe, oldBit, oldVerity := cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity
	oldReadVerity, oldVerify := cryptoReadVerityOff, cryptoVerifyPIN
	var calls []string
	verityOff := false
	verifyCalls := 0
	bitCalls := 0
	cryptoVerifyPIN = func(uid int, pin string) (bool, error) {
		verifyCalls++
		if verifyCalls > 1 {
			return false, errors.New("key custody is gone")
		}
		return uid == 1000 && pin == runtimeTestPIN, nil
	}
	cryptoDisableVerity = func() error {
		calls = append(calls, "verity")
		verityOff = true
		return nil
	}
	cryptoReadVerityOff = func() (bool, error) { return verityOff, nil }
	cryptoWipeVar = func() error { calls = append(calls, "wipe"); return nil }
	cryptoSetUnlockBit = func() error {
		calls = append(calls, "bit")
		bitCalls++
		if bitCalls == 1 {
			return errors.New("TPM unavailable")
		}
		return nil
	}
	t.Cleanup(func() {
		cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity = oldWipe, oldBit, oldVerity
		cryptoReadVerityOff, cryptoVerifyPIN = oldReadVerity, oldVerify
	})

	if ok, _ := core.UnlockBootloader("UNLOCK", runtimeTestPIN); ok {
		t.Fatal("unlock succeeded after the first lock-bit failure")
	}
	if f := core.readUnlockFlag(); !f.Armed || f.Phase != unlockPhaseVerityOff {
		t.Fatalf("resume phase was not retained: %+v", f)
	}
	if ok, msg := core.UnlockBootloader("UNLOCK", ""); !ok {
		t.Fatalf("resume failed after key custody was erased: %s", msg)
	}
	if got := strings.Join(calls, ","); got != "verity,wipe,bit,wipe,bit" {
		t.Fatalf("resume order=%s", got)
	}
	if verifyCalls != 1 {
		t.Fatalf("resume tried to verify a deleted PIN key: calls=%d", verifyCalls)
	}
	if f := core.readUnlockFlag(); f.Armed || f.Phase != "" || f.Count != 1 {
		t.Fatalf("completed transaction flag=%+v", f)
	}
}

func TestDisarmRefusesPendingUnlockTransaction(t *testing.T) {
	core := newLockCore(t)
	if ok, _ := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatal("arm failed")
	}
	f := core.readUnlockFlag()
	f.Phase = unlockPhaseVerityOff
	if err := core.writeUnlockFlag(f); err != nil {
		t.Fatal(err)
	}
	oldReadLock := cryptoReadLockBit
	cryptoReadLockBit = func() (bool, error) { return true, nil }
	t.Cleanup(func() { cryptoReadLockBit = oldReadLock })

	if ok, _ := core.ArmUnlock(false); ok {
		t.Fatal("disarm cleared a pending transaction while the device was locked")
	}
	if f := core.readUnlockFlag(); !f.Armed || f.Phase != unlockPhaseVerityOff {
		t.Fatalf("pending transaction changed after refused disarm: %+v", f)
	}
	cryptoReadLockBit = func() (bool, error) { return false, nil }
	if ok, msg := core.ArmUnlock(false); !ok {
		t.Fatalf("cleanup after TPM unlock failed: %s", msg)
	}
	if f := core.readUnlockFlag(); f.Armed || f.Phase != "" || f.Count != 1 {
		t.Fatalf("finalized transaction flag=%+v", f)
	}
}

func TestRuntimePolicyOwnsPINCheckAndHidesDestructiveAPI(t *testing.T) {
	core := newLockCore(t)
	w, b, v := spyCrypto(t)
	oldVerify := cryptoVerifyPIN
	verifyCalls := 0
	cryptoVerifyPIN = func(uid int, pin string) (bool, error) {
		verifyCalls++
		return uid == 1000 && pin == runtimeTestPIN, nil
	}
	t.Cleanup(func() { cryptoVerifyPIN = oldVerify })

	srv := httptest.NewServer(newHandlerWithPolicy(core, HandlerPolicy{Runtime: true, OwnerUID: 1000}))
	defer srv.Close()

	wrong := postJSON(t, srv, "/arm-unlock", map[string]any{"armed": true, "pin": "9999"})
	if wrong["ok"] != false || core.readUnlockFlag().Armed {
		t.Fatalf("wrong PIN armed unlock: response=%v state=%+v", wrong, core.readUnlockFlag())
	}
	malformed := postJSON(t, srv, "/arm-unlock", map[string]any{"armed": true, "pin": "1234\nextra"})
	if malformed["ok"] != false || verifyCalls != 1 {
		t.Fatalf("malformed PIN reached verifier: response=%v calls=%d", malformed, verifyCalls)
	}
	oversized := postJSON(t, srv, "/arm-unlock", map[string]any{"armed": true, "pin": strings.Repeat("1", 5000)})
	if oversized["ok"] != false || verifyCalls != 1 {
		t.Fatalf("oversized request reached verifier: response=%v calls=%d", oversized, verifyCalls)
	}
	armed := postJSON(t, srv, "/arm-unlock", map[string]any{"armed": true, "pin": runtimeTestPIN})
	if armed["ok"] != true || !core.readUnlockFlag().Armed {
		t.Fatalf("correct PIN did not arm: response=%v state=%+v", armed, core.readUnlockFlag())
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/unlock-bootloader", strings.NewReader(`{"confirm":"UNLOCK"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("runtime destructive endpoint status=%d, want 404", resp.StatusCode)
	}
	if *w != 0 || *b != 0 || *v != 0 {
		t.Fatalf("hidden destructive endpoint touched crypto: wipe=%d bit=%d verity=%d", *w, *b, *v)
	}

	disarmed := postJSON(t, srv, "/arm-unlock", map[string]any{"armed": false})
	if disarmed["ok"] != true || core.readUnlockFlag().Armed {
		t.Fatalf("PIN-free disarm failed: response=%v state=%+v", disarmed, core.readUnlockFlag())
	}
}

func TestDataWipePreservesOnlyBootSlotsAndMarker(t *testing.T) {
	core := newLockCore(t)
	data := core.cfg.DataDir
	for path, content := range map[string]string{
		"boot/rootfs/rootfs-active.erofs": "root",
		"boot/rootfs/hidden":              "secret",
		"boot/efi/EFI/atom/state":         "mounted-esp",
		"boot/firmware/private":           "secret",
		"boot/secret":                     "secret",
		"home/owner/document":             "secret",
		"etc-upper/config":                "state",
		"lib/sinty/1000.priv":             "key",
		"lib/atom/state":                  "daemon",
	} {
		full := filepath.Join(data, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := core.prepareDataWipe(); err != nil {
		t.Fatalf("prepareDataWipe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "lib", "sinty", "1000.priv")); err != nil {
		t.Fatalf("key custody removed before crypto wipe: %v", err)
	}
	for _, removed := range []string{"home", "etc-upper", "lib/atom", "boot/firmware", "boot/secret", "boot/rootfs/hidden"} {
		if _, err := os.Stat(filepath.Join(data, removed)); !os.IsNotExist(err) {
			t.Fatalf("%s survived prepare wipe", removed)
		}
	}
	if err := core.finishDataWipe(); err != nil {
		t.Fatalf("finishDataWipe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "lib")); !os.IsNotExist(err) {
		t.Fatal("key custody directory survived final wipe")
	}
	for _, kept := range []string{dataMarker, installIDMarker, "boot/efi/EFI/atom/state", "boot/rootfs/rootfs-active.erofs"} {
		if _, err := os.Stat(filepath.Join(data, kept)); err != nil {
			t.Fatalf("preserved %s missing: %v", kept, err)
		}
	}
}

func TestDataWipeRefusesUnknownFilesystem(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "do-not-delete")
	if err := os.WriteFile(keep, []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	core := NewCore(Config{DataDir: dir, Dirs: atom.StageDirs{ESP: dir}})
	if err := core.prepareDataWipe(); err == nil {
		t.Fatal("wipe accepted a directory without atom-data markers")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("refused wipe changed data: %v", err)
	}
}

func TestDataWipeRefusesSymlinkedPreservedDirectory(t *testing.T) {
	core := newLockCore(t)
	data := core.cfg.DataDir
	external := t.TempDir()
	keep := filepath.Join(external, "do-not-delete")
	if err := os.WriteFile(keep, []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(data, "lib")); err != nil {
		t.Fatal(err)
	}
	if err := core.prepareDataWipe(); err == nil {
		t.Fatal("wipe accepted a symlinked key-custody parent")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("refused wipe changed the symlink target: %v", err)
	}
}
