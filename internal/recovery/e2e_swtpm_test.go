package recovery

import (
	"os"
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
//	go test ./internal/recovery/ -run E2EUnlockAgainstRealTPM -v
func TestE2EUnlockAgainstRealTPM(t *testing.T) {
	sk := os.Getenv("SINTYKEY_E2E")
	if sk == "" {
		t.Skip("set SINTYKEY_E2E to a sintykey wired to a running swtpm")
	}
	restoreSeam(t)
	EnableSintykeyCrypto(sk)

	dir := t.TempDir()
	core := NewCore(Config{Dirs: atom.StageDirs{Rootfs: dir, ESP: dir}})

	if ok, msg := core.ArmUnlock(true); !ok {
		t.Fatalf("ArmUnlock: %s", msg)
	}
	ok, msg := core.UnlockBootloader("UNLOCK")
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
