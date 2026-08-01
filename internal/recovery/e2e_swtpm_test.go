package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/atom"
)

// TestE2EUnlockAgainstRealTPM drives the whole unlock through the recovery Core
// against a real (software) TPM: arm the ESP consent, confirm UNLOCK, and let the
// sintykey-backed seam flip the TPM lock bit and verity toggle for real. It is an
// integration test, skipped unless SINTYKEY_E2E points at a sintykey built to talk
// to a running swtpm (with SINTYKEY_TCTI set in the environment).
//
//	SINTYKEY_TCTI=swtpm:host=127.0.0.1,port=2321 \
//	SINTYKEY_E2E=/path/to/sintykey \
//	SINTYKEY_E2E_PIN=1234 \
//	go test ./internal/recovery/ -run E2EUnlockAgainstRealTPM -v
func TestE2EUnlockAgainstRealTPM(t *testing.T) {
	sk := os.Getenv("SINTYKEY_E2E")
	if sk == "" {
		t.Skip("set SINTYKEY_E2E to a sintykey wired to a running swtpm")
	}
	pin := os.Getenv("SINTYKEY_E2E_PIN")
	if pin == "" {
		t.Skip("set SINTYKEY_E2E_PIN to the provisioned test PIN")
	}
	restoreSeam(t)
	EnableSintykeyCrypto(sk)

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
	core := NewCore(Config{DataDir: dir, Dirs: atom.StageDirs{Rootfs: dir, ESP: esp}})

	if ok, msg := core.ArmUnlockForOwner(true, 1000); !ok {
		t.Fatalf("ArmUnlock: %s", msg)
	}
	ok, msg := core.UnlockBootloader("UNLOCK", pin)
	if !ok {
		t.Fatalf("UnlockBootloader refused: %s", msg)
	}
	t.Logf("UnlockBootloader: %s", msg)

	locked, err := cryptoReadLockBit()
	if err != nil {
		t.Fatalf("read lock bit after unlock: %v", err)
	}
	if locked {
		t.Fatal("after a confirmed unlock the TPM still reports locked")
	}
	st := core.LockState()
	if st.Locked {
		t.Fatalf("LockState still locked after unlock: %+v", st)
	}
	t.Logf("E2E OK: real TPM reports locked=false, unlock_count=%d", st.UnlockCount)
}
