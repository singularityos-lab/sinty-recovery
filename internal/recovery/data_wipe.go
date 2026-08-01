package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	dataMarker      = ".atom-var"
	installIDMarker = ".atom-install-id"
)

func readInstallID(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", fmt.Errorf("invalid install ID")
	}
	return id, nil
}

func requireRealDir(path, label string, optional bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%s: %w", label, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", label)
	}
	return nil
}

func (c *Core) validateDataDir() error {
	if c.cfg.DataDir == "" || !filepath.IsAbs(c.cfg.DataDir) || filepath.Clean(c.cfg.DataDir) == "/" {
		return fmt.Errorf("unsafe or missing atom-data path")
	}
	info, err := os.Lstat(c.cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open atom-data: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("atom-data path is not a directory mountpoint")
	}
	markerInfo, err := os.Lstat(filepath.Join(c.cfg.DataDir, dataMarker))
	if err != nil {
		return fmt.Errorf("atom-data marker missing: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return fmt.Errorf("atom-data marker is not a regular file")
	}
	dataID, err := readInstallID(filepath.Join(c.cfg.DataDir, installIDMarker))
	if err != nil {
		return fmt.Errorf("read atom-data install ID: %w", err)
	}
	espID, err := readInstallID(filepath.Join(c.cfg.Dirs.ESP, "state", "install-id"))
	if err != nil {
		return fmt.Errorf("read system partition install ID: %w", err)
	}
	if dataID != espID {
		return fmt.Errorf("installed volume IDs do not match")
	}
	boot := filepath.Join(c.cfg.DataDir, "boot")
	if err := requireRealDir(boot, "atom-data boot directory", false); err != nil {
		return err
	}
	rootfs := filepath.Join(boot, "rootfs")
	if err := requireRealDir(rootfs, "atom-data rootfs slots", false); err != nil {
		return err
	}
	lib := filepath.Join(c.cfg.DataDir, "lib")
	if err := requireRealDir(lib, "atom-data lib directory", true); err != nil {
		return err
	}
	if err := requireRealDir(filepath.Join(lib, "sinty"), "key-custody directory", true); err != nil {
		return err
	}
	for _, name := range []string{"deployment.json", "rootfs-active.erofs", "rootfs-active.hash"} {
		info, err := os.Lstat(filepath.Join(rootfs, name))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("atom-data rootfs artifact %s missing", name)
		}
	}
	if c.cfg.RequireMount {
		parentInfo, err := os.Stat(filepath.Dir(c.cfg.DataDir))
		if err != nil {
			return fmt.Errorf("stat atom-data parent: %w", err)
		}
		dataStat, dataOK := info.Sys().(*syscall.Stat_t)
		parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
		if !dataOK || !parentOK || dataStat.Dev == parentStat.Dev {
			return fmt.Errorf("atom-data is not a distinct mounted filesystem")
		}
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeChildrenExcept(dir string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("remove %s: %w", entry.Name(), err)
		}
	}
	return syncDir(dir)
}

func (c *Core) scrubBootArtifacts() error {
	boot := filepath.Join(c.cfg.DataDir, "boot")
	if err := removeChildrenExcept(boot, map[string]bool{"rootfs": true}); err != nil {
		return fmt.Errorf("scrub boot directory: %w", err)
	}
	rootfs := filepath.Join(boot, "rootfs")
	keep := map[string]bool{
		"deployment.json":     true,
		"deployment.json.bak": true,
		"rootfs-active.erofs": true,
		"rootfs-active.hash":  true,
		"rootfs-next.erofs":   true,
		"rootfs-next.hash":    true,
		"rootfs-prev.erofs":   true,
		"rootfs-prev.hash":    true,
	}
	if err := removeChildrenExcept(rootfs, keep); err != nil {
		return fmt.Errorf("scrub rootfs slots: %w", err)
	}
	return nil
}

// prepareDataWipe removes persistent state while retaining the rootfs slots and
// the key-custody directory needed by the cryptographic wipe. It is idempotent so
// recovery can safely retry after a power loss.
func (c *Core) prepareDataWipe() error {
	if err := c.validateDataDir(); err != nil {
		return err
	}
	if err := c.scrubBootArtifacts(); err != nil {
		return err
	}
	if err := removeChildrenExcept(c.cfg.DataDir, map[string]bool{
		"boot": true, dataMarker: true, installIDMarker: true, "lib": true,
	}); err != nil {
		return err
	}
	libDir := filepath.Join(c.cfg.DataDir, "lib")
	if err := os.MkdirAll(filepath.Join(libDir, "sinty"), 0o700); err != nil {
		return fmt.Errorf("preserve key custody: %w", err)
	}
	return removeChildrenExcept(libDir, map[string]bool{"sinty": true})
}

// finishDataWipe runs only after key custody is gone. A second pass removes the
// retained crypto directory and any state recreated between the two phases.
func (c *Core) finishDataWipe() error {
	if err := c.validateDataDir(); err != nil {
		return err
	}
	return removeChildrenExcept(c.cfg.DataDir, map[string]bool{
		"boot": true, dataMarker: true, installIDMarker: true,
	})
}
