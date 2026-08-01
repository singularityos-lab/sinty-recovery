package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// unlockFlag is the on-ESP consent flag ("allow bootloader unlock"). It lives on
// the FAT ESP so the desktop (via ArmUnlock over this socket), the recovery UI,
// and the EFI loader all read the same bit without a user session. The desktop
// never writes the ESP directly: it must go through ArmUnlock so the privileged
// agent owns the file. Count is monotonic across unlocks, for attestation.
type unlockFlag struct {
	Armed    bool   `json:"armed"`
	Count    int    `json:"count"`
	OwnerUID int    `json:"owner_uid,omitempty"`
	Phase    string `json:"phase,omitempty"`
}

const unlockPhaseVerityOff = "verity-off"

// unlockFlagPath is <ESP>/state/unlock-armed. Dirs.ESP already points at the
// per-device \EFI\atom directory the loader reads.
func (c *Core) unlockFlagPath() string {
	return filepath.Join(c.cfg.Dirs.ESP, "state", "unlock-armed")
}

// readUnlockFlag reads the consent flag, failing closed: a missing, unreadable or
// corrupt flag is reported as not-armed, never as armed.
func (c *Core) readUnlockFlag() unlockFlag {
	b, err := os.ReadFile(c.unlockFlagPath())
	if err != nil {
		return unlockFlag{}
	}
	var f unlockFlag
	if err := json.Unmarshal(b, &f); err != nil {
		return unlockFlag{}
	}
	return f
}

// LockStateInfo is what a UI shows about the bootloader lock.
type LockStateInfo struct {
	Locked      bool `json:"locked"`
	UnlockArmed bool `json:"unlock_armed"`
	UnlockCount int  `json:"unlock_count"`
}

// LockState reports whether the bootloader is locked (TPM-NV lock bit, via the
// crypto seam) and whether an unlock is armed (ESP consent flag). Both reads fail
// closed: a failed, unparseable or unreachable read is reported as locked and
// not-armed, never as unlocked or armed.
func (c *Core) LockState() LockStateInfo {
	c.lockMu.Lock()
	defer c.lockMu.Unlock()
	locked := true
	if v, err := cryptoReadLockBit(); err == nil {
		locked = v
	}
	f := c.readUnlockFlag()
	if !locked && f.Armed && f.Phase == unlockPhaseVerityOff {
		_ = c.finalizeUnlockFlag(f)
		f = c.readUnlockFlag()
	}
	return LockStateInfo{Locked: locked, UnlockArmed: f.Armed && f.OwnerUID >= 1000, UnlockCount: f.Count}
}

func (c *Core) writeUnlockFlag(f unlockFlag) error {
	dir := filepath.Dir(c.unlockFlagPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("prepare ESP state dir: %w", err)
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".unlock-armed-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, c.unlockFlagPath()); err != nil {
		return err
	}
	return syncDir(dir)
}

// ArmUnlock writes or clears the ESP consent flag. Runtime policy verifies the
// owner's PIN before this method is reached. Arming preserves the monotonic count.
func (c *Core) ArmUnlock(armed bool) (bool, string) {
	return c.ArmUnlockForOwner(armed, 0)
}

// ArmUnlockForOwner records which local account proved ownership. Recovery uses
// the same account's PIN again before it starts the irreversible wipe.
func (c *Core) ArmUnlockForOwner(armed bool, ownerUID int) (bool, string) {
	c.lockMu.Lock()
	defer c.lockMu.Unlock()
	f := c.readUnlockFlag()
	if armed {
		if ownerUID < 1000 {
			return false, "The owner account could not be recorded. Nothing was changed."
		}
		if f.Armed && f.Phase != "" {
			return false, "The existing unlock transaction must finish in recovery."
		}
		f.Armed = true
		f.OwnerUID = ownerUID
		f.Phase = ""
	} else {
		if f.Phase != "" {
			locked, err := cryptoReadLockBit()
			if err != nil || locked {
				return false, "The unlock transaction has started and must finish in recovery."
			}
			if err := c.finalizeUnlockFlag(f); err != nil {
				return false, fmt.Sprintf("cannot finalize unlock consent: %v", err)
			}
			return true, "Bootloader unlock transaction finalized."
		}
		f.Armed = false
		f.OwnerUID = 0
		f.Phase = ""
	}
	if err := c.writeUnlockFlag(f); err != nil {
		return false, fmt.Sprintf("cannot write consent flag: %v", err)
	}
	if armed {
		return true, "Bootloader unlock is armed. Reboot into recovery to confirm."
	}
	return true, "Bootloader unlock consent cleared."
}

func (c *Core) finalizeUnlockFlag(f unlockFlag) error {
	if f.Phase != "" {
		f.Count++
	}
	f.Armed = false
	f.OwnerUID = 0
	f.Phase = ""
	return c.writeUnlockFlag(f)
}

// UnlockBootloader performs the irreversible unlock, but only fail-closed: it
// requires confirm=="UNLOCK" AND a live-armed consent flag, both re-checked here
// server-side (never trusted from the client). Only then does it call the crypto
// primitives to disable verity, record that TPM-backed phase durably, wipe /var,
// and flip the TPM-NV lock bit last. A retry resumes only when both the ESP phase
// and the TPM verity state agree, so deleted key custody is never needed again.
func (c *Core) UnlockBootloader(confirm, pin string) (bool, string) {
	c.lockMu.Lock()
	defer c.lockMu.Unlock()
	if confirm != "UNLOCK" {
		return false, "The device refused the unlock request."
	}
	f := c.readUnlockFlag()
	if !f.Armed || f.OwnerUID < 1000 {
		return false, "Unlocking must first be allowed by the owner, from the running system."
	}
	resume := false
	switch f.Phase {
	case "":
	case unlockPhaseVerityOff:
		verityOff, err := cryptoReadVerityOff()
		if err != nil || !verityOff {
			return false, "The pending unlock transaction could not be verified. Nothing was changed."
		}
		resume = true
	default:
		return false, "The pending unlock transaction is invalid. Nothing was changed."
	}
	if !resume {
		if len(pin) < 4 || len(pin) > 256 || strings.ContainsAny(pin, "\r\n") {
			return false, "Enter the owner's PIN. Nothing was changed."
		}
		valid, err := cryptoVerifyPIN(f.OwnerUID, pin)
		if err != nil {
			return false, "The owner's PIN could not be checked. Nothing was changed."
		}
		if !valid {
			return false, "Incorrect PIN. Nothing was changed."
		}
		current := c.readUnlockFlag()
		if !current.Armed || current.OwnerUID != f.OwnerUID || current.Phase != "" {
			return false, "The unlock consent changed. Nothing was changed."
		}
		if err := c.validateDataDir(); err != nil {
			return false, fmt.Sprintf("unlock: validate data wipe: %v", err)
		}
		if err := cryptoDisableVerity(); err != nil {
			return false, fmt.Sprintf("unlock: disable verity: %v", err)
		}
		verityOff, err := cryptoReadVerityOff()
		if err != nil || !verityOff {
			return false, "The TPM did not confirm the unlock transaction. User data was not erased."
		}
		current = c.readUnlockFlag()
		if !current.Armed || current.OwnerUID != f.OwnerUID || current.Phase != "" {
			return false, "The unlock consent changed before the transaction was recorded. User data was not erased."
		}
		current.Phase = unlockPhaseVerityOff
		if err := c.writeUnlockFlag(current); err != nil {
			return false, fmt.Sprintf("unlock: record transaction: %v", err)
		}
		f = current
	}
	if err := c.prepareDataWipe(); err != nil {
		return false, fmt.Sprintf("unlock: prepare data wipe: %v", err)
	}
	if err := cryptoWipeVar(); err != nil {
		return false, fmt.Sprintf("unlock: wipe user data: %v", err)
	}
	if err := c.finishDataWipe(); err != nil {
		return false, fmt.Sprintf("unlock: finish data wipe: %v", err)
	}
	if err := cryptoSetUnlockBit(); err != nil {
		return false, fmt.Sprintf("unlock: set lock bit: %v", err)
	}
	if err := c.finalizeUnlockFlag(c.readUnlockFlag()); err != nil {
		return true, "Bootloader unlocked. Consent cleanup will retry automatically."
	}
	return true, "Bootloader unlocked. This device will warn at every boot."
}
