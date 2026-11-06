package recovery

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mirkobrombin/atomloops/boot"
)

var runChecker boot.Runner = boot.RunCommand

var logRepair = boot.LogDataRepair

var verifyVerifierPIN = func(uid, pin string) (bool, error) {
	cmd := exec.Command(sintykeyBin, "verify-pin", "--uid", uid, "--verifier")
	cmd.Stdin = strings.NewReader(pin + "\n")
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DataBroken reports the data partition the recovery found but could not mount,
// or "" when the data partition is healthy.
func (c *Core) DataBroken() string { return c.cfg.BrokenData }

// DataCheck runs the read-only check on the broken data partition.
func (c *Core) DataCheck() (boot.Repair, error) {
	if c.cfg.BrokenData == "" {
		return boot.Repair{}, fmt.Errorf("the data partition is not damaged")
	}
	out, exit := runChecker(boot.F2FSChecker, "--dry-run", "-f", c.cfg.BrokenData)
	r := boot.Repair{Dev: c.cfg.BrokenData, Before: out}
	r.Verdict, r.Failed = boot.ClassifyF2FSCheck(out, exit)
	c.setLastCheck(r)
	return r, nil
}

func (c *Core) setLastCheck(r boot.Repair) {
	c.checkMu.Lock()
	c.lastCheck = &r
	c.checkMu.Unlock()
}

// LastDataCheck returns the most recent check or repair of the data partition.
func (c *Core) LastDataCheck() (boot.Repair, bool) {
	c.checkMu.Lock()
	defer c.checkMu.Unlock()
	if c.lastCheck == nil {
		return boot.Repair{}, false
	}
	return *c.lastCheck, true
}

func (c *Core) verifierUIDs() []string {
	files, _ := filepath.Glob(filepath.Join(c.cfg.Dirs.ESP, "state", "pin", "*.priv"))
	var uids []string
	for _, f := range files {
		uids = append(uids, strings.TrimSuffix(filepath.Base(f), ".priv"))
	}
	return uids
}

// HasPINVerifier reports whether an owner PIN can be checked without the data
// partition.
func (c *Core) HasPINVerifier() bool { return len(c.verifierUIDs()) > 0 }

func (c *Core) pinMatches(pin string) (bool, error) {
	if len(pin) < 4 || len(pin) > 256 || strings.ContainsAny(pin, "\r\n") {
		return false, nil
	}
	var lastErr error
	for _, uid := range c.verifierUIDs() {
		ok, err := verifyVerifierPIN(uid, pin)
		if ok {
			return true, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return false, lastErr
}

// DataRepair repairs the broken data partition. Damage limited to accounting
// is repaired as the boot would. A repair that may remove files needs an owner
// PIN and the word REPAIR typed by the operator.
func (c *Core) DataRepair(pin, confirm string) (bool, string) {
	r, err := c.DataCheck()
	if err != nil {
		return false, err.Error()
	}
	switch r.Verdict {
	case boot.CheckClean:
		return true, "The check found no damage. Nothing was changed."
	case boot.CheckAccounting:
		fixed := boot.RepairF2FS(c.cfg.BrokenData, runChecker)
		c.setLastCheck(fixed)
		logRepair(fixed)
		if !fixed.Fixed {
			return false, "The repair did not complete. Save the report and reinstall."
		}
		return true, "The data partition was repaired."
	case boot.CheckUnrepairable:
		return false, "This data partition cannot be repaired. Nothing was changed. Save a report, then reinstall."
	}
	if !c.HasPINVerifier() {
		return false, "This repair can remove files and needs the owner's PIN, which cannot be checked on this device. Nothing was changed."
	}
	ok, err := c.pinMatches(pin)
	if err != nil {
		return false, "The owner's PIN could not be checked. Nothing was changed."
	}
	if !ok {
		return false, "Incorrect PIN. Nothing was changed."
	}
	if confirm != "REPAIR" {
		return false, "The repair was not confirmed. Nothing was changed."
	}
	fix, _ := runChecker(boot.F2FSChecker, "-f", "-y", c.cfg.BrokenData)
	out, exit := runChecker(boot.F2FSChecker, "--dry-run", "-f", c.cfg.BrokenData)
	after, _ := boot.ClassifyF2FSCheck(out, exit)
	r.Fix, r.After, r.Fixed = fix, out, after == boot.CheckClean
	c.setLastCheck(r)
	logRepair(r)
	if !r.Fixed {
		return false, "The repair did not complete. Save the report and reinstall."
	}
	return true, "The data partition was repaired. Some files may have been moved to lost+found."
}

// SaveReport writes the last check of the data partition to the ESP, where the
// running system or another computer can read it.
func (c *Core) SaveReport() (string, error) {
	r, ok := c.LastDataCheck()
	if !ok {
		checked, err := c.DataCheck()
		if err != nil {
			return "", err
		}
		r = checked
	}
	dir := filepath.Join(c.cfg.Dirs.ESP, "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "SINTYRECOVERY-"+time.Now().UTC().Format("20060102-150405")+".txt")
	if err := writeDurable(path, []byte(r.Report("SINTYRECOVERY"))); err != nil {
		return "", err
	}
	return path, nil
}

// StartSystem points the next boot back at the installed system once the data
// partition checks clean.
func (c *Core) StartSystem() (bool, string) {
	if c.cfg.BrokenData != "" {
		r, err := c.DataCheck()
		if err != nil || r.Verdict != boot.CheckClean {
			return false, "The data partition still needs a repair."
		}
	}
	path := filepath.Join(c.cfg.Dirs.ESP, "boot-state")
	if err := writeDurable(path, []byte("target=active\ntrial=0\nattempts=0\n")); err != nil {
		return false, "The boot state could not be written: " + err.Error()
	}
	return true, "Sinty OS will start at the next boot."
}

func writeDurable(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".write-")
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDir(dir)
}
