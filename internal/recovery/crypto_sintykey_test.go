package recovery

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFakeSintykey drops a stand-in sintykey whose behaviour is driven by FAKE_*
// env vars, so a test can exercise the real shell-out path without a TPM.
func writeFakeSintykey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sintykey")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  lock-state) printf 'locked=%s\\nunlock_count=%s\\n' \"${FAKE_LOCKED:-false}\" \"${FAKE_COUNT:-0}\"; exit \"${FAKE_LS_EXIT:-0}\";;\n" +
		"  verity-state) printf 'verity=%s\\n' \"${FAKE_VERITY:-off}\"; exit \"${FAKE_VS_EXIT:-0}\";;\n" +
		"  verify-pin) IFS= read -r pin; [ \"$pin\" = \"${FAKE_PIN:-1234}\" ];;\n" +
		"  wipe-var|set-unlock|disable-verity) exit \"${FAKE_PRIM_EXIT:-0}\";;\n" +
		"  *) exit 0;;\n" +
		"esac\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// restoreSeam captures the crypto seam so EnableSintykeyCrypto's global reassignment
// does not leak into other tests in the package.
func restoreSeam(t *testing.T) {
	t.Helper()
	rb, rv, vp, wv, su, dv, bin := cryptoReadLockBit, cryptoReadVerityOff, cryptoVerifyPIN, cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity, sintykeyBin
	t.Cleanup(func() {
		cryptoReadLockBit, cryptoReadVerityOff, cryptoVerifyPIN, cryptoWipeVar, cryptoSetUnlockBit, cryptoDisableVerity, sintykeyBin = rb, rv, vp, wv, su, dv, bin
	})
}

func TestSintykeyReadVerityOff(t *testing.T) {
	restoreSeam(t)
	EnableSintykeyCrypto(writeFakeSintykey(t))
	t.Setenv("FAKE_VERITY", "off")
	off, err := cryptoReadVerityOff()
	if err != nil || !off {
		t.Fatalf("want (true,nil), got (%v,%v)", off, err)
	}
	t.Setenv("FAKE_VERITY", "on")
	off, err = cryptoReadVerityOff()
	if err != nil || off {
		t.Fatalf("want (false,nil), got (%v,%v)", off, err)
	}
}

func TestSintykeyVerifyPIN(t *testing.T) {
	restoreSeam(t)
	EnableSintykeyCrypto(writeFakeSintykey(t))
	ok, err := cryptoVerifyPIN(1000, "1234")
	if err != nil || !ok {
		t.Fatalf("right PIN: want (true,nil), got (%v,%v)", ok, err)
	}
	ok, err = cryptoVerifyPIN(1000, "wrong")
	if err != nil || ok {
		t.Fatalf("wrong PIN: want (false,nil), got (%v,%v)", ok, err)
	}
}

func TestSintykeyReadLockBit_Unlocked(t *testing.T) {
	restoreSeam(t)
	EnableSintykeyCrypto(writeFakeSintykey(t))
	t.Setenv("FAKE_LOCKED", "false")
	locked, err := cryptoReadLockBit()
	if err != nil || locked {
		t.Fatalf("want (false,nil), got (%v,%v)", locked, err)
	}
}

func TestSintykeyReadLockBit_Locked(t *testing.T) {
	restoreSeam(t)
	EnableSintykeyCrypto(writeFakeSintykey(t))
	t.Setenv("FAKE_LOCKED", "true")
	locked, err := cryptoReadLockBit()
	if err != nil || !locked {
		t.Fatalf("want (true,nil), got (%v,%v)", locked, err)
	}
}

// A nonzero exit means the TPM was unreachable: it must be reported as an error so
// LockState falls back to locked, never mistaking a failed read for unlocked.
func TestSintykeyReadLockBit_FailClosed(t *testing.T) {
	restoreSeam(t)
	EnableSintykeyCrypto(writeFakeSintykey(t))
	t.Setenv("FAKE_LS_EXIT", "2")
	t.Setenv("FAKE_LOCKED", "false")
	locked, err := cryptoReadLockBit()
	if err == nil || !locked {
		t.Fatalf("nonzero exit must fail closed: want (true,err), got (%v,%v)", locked, err)
	}
}

func TestSintykeyPrimitives(t *testing.T) {
	restoreSeam(t)
	EnableSintykeyCrypto(writeFakeSintykey(t))
	if err := cryptoWipeVar(); err != nil {
		t.Fatalf("wipe-var should succeed: %v", err)
	}
	if err := cryptoSetUnlockBit(); err != nil {
		t.Fatalf("set-unlock should succeed: %v", err)
	}
	t.Setenv("FAKE_PRIM_EXIT", "1")
	if err := cryptoDisableVerity(); err == nil {
		t.Fatal("a nonzero primitive exit must be an error so the unlock aborts")
	}
}
