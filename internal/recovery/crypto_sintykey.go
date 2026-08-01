package recovery

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// sintykey is the crypto agent CLI (sinty-crypto) that owns the TPM-NV lock bit,
// the dm-verity toggle and the fscrypt key custody. The bootloader-unlock seam in
// crypto_seam.go shells out to it. sintykey's subcommands are named to match the
// seam one to one:
//
//	lock-state     -> cryptoReadLockBit
//	verity-state   -> cryptoReadVerityOff
//	verify-pin     -> cryptoVerifyPIN
//	wipe-var       -> cryptoWipeVar
//	set-unlock     -> cryptoSetUnlockBit
//	disable-verity -> cryptoDisableVerity
var sintykeyBin = "sintykey"

// EnableSintykeyCrypto replaces the fail-closed stubs in crypto_seam.go with the
// real sintykey-backed primitives. Production (cmd/atom-recovery) calls this at
// startup; without it the seam stays stubbed and every unlock aborts before it
// touches anything. An empty path keeps the default PATH lookup ("sintykey").
func EnableSintykeyCrypto(path string) {
	if path != "" {
		sintykeyBin = path
	}
	cryptoReadLockBit = sintykeyReadLockBit
	cryptoReadVerityOff = sintykeyReadVerityOff
	cryptoVerifyPIN = sintykeyVerifyPIN
	cryptoWipeVar = func() error { return runSintykey("wipe-var") }
	cryptoSetUnlockBit = func() error { return runSintykey("set-unlock") }
	cryptoDisableVerity = func() error { return runSintykey("disable-verity") }
}

func sintykeyReadVerityOff() (bool, error) {
	out, err := exec.Command(sintykeyBin, "verity-state").Output()
	if err != nil {
		return false, fmt.Errorf("sintykey verity-state: %w", err)
	}
	switch strings.TrimSpace(string(out)) {
	case "verity=off":
		return true, nil
	case "verity=on":
		return false, nil
	default:
		return false, fmt.Errorf("sintykey verity-state: invalid output")
	}
}

func sintykeyVerifyPIN(uid int, pin string) (bool, error) {
	cmd := exec.Command(sintykeyBin, "verify-pin", "--uid", strconv.Itoa(uid))
	cmd.Stdin = strings.NewReader(pin + "\n")
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// runSintykey runs one sintykey subcommand. A nonzero exit becomes an error so the
// seam fails closed: UnlockBootloader aborts on the first primitive that fails.
func runSintykey(args ...string) error {
	out, err := exec.Command(sintykeyBin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sintykey %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sintykeyReadLockBit parses `sintykey lock-state`, whose contract is two lines:
//
//	locked=<true|false>
//	unlock_count=<int>
//
// A nonzero exit means the TPM was unreachable; it is returned as an error so
// LockState falls back to locked. A reachable TPM with the index still undefined
// is a legitimate locked=true at exit 0.
func sintykeyReadLockBit() (bool, error) {
	out, err := exec.Command(sintykeyBin, "lock-state").Output()
	if err != nil {
		return true, fmt.Errorf("sintykey lock-state: %w", err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "locked=") {
			return strings.TrimPrefix(line, "locked=") == "true", nil
		}
	}
	return true, fmt.Errorf("sintykey lock-state: no locked= line in output")
}
