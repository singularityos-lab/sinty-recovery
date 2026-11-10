package recovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/mirkobrombin/atomloops/atom"
)

// Home is an account of the rescued computer.
type Home struct {
	UID  int    `json:"uid"`
	Name string `json:"name"`
	Path string `json:"path"`
	Open bool   `json:"open"`
}

var (
	errNoHome     = errors.New("no such account on this computer")
	errHomeLocked = errors.New("open the account with its PIN or recovery code first")
	errNoRescue   = errors.New("there is nowhere to copy the files to")
)

const (
	fsIocAddEncryptionKey = 0xc0506617
	fscryptKeySpecID      = 2
	homeKeyLen            = 32
)

var homeKey = func(uid int, secret string, recovery bool) ([]byte, error) {
	cmd := "unseal"
	if recovery {
		cmd = "unwrap-recovery"
	}
	c := exec.Command(sintykeyBin, cmd, "--uid", strconv.Itoa(uid))
	c.Stdin = strings.NewReader(secret + "\n")
	out, err := c.Output()
	if err != nil || len(out) != homeKeyLen {
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("the PIN or recovery code is not correct")
	}
	return out, nil
}

var addHomeKey = func(dir string, raw []byte) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 80+len(raw))
	binary.LittleEndian.PutUint32(buf[0:], fscryptKeySpecID)
	binary.LittleEndian.PutUint32(buf[40:], uint32(len(raw)))
	copy(buf[80:], raw)
	defer clear(buf)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocAddEncryptionKey, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return fmt.Errorf("add the key of %s: %w", dir, errno)
	}
	return nil
}

var copyTree = func(src, dst string) error {
	out, err := exec.Command("cp", "-a", "--", src+"/.", dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("copy: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

var readSealedLog = func(ring, cold, key string) (string, error) {
	var out, errOut bytes.Buffer
	c := exec.Command("sealedlogd", "read", "--ring", ring, "--cold", cold, "--key", key)
	c.Stdout, c.Stderr = &out, &errOut
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("sealed log: %s", strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

func (c *Core) dataPath(p string) string {
	if rest, ok := strings.CutPrefix(p, "/var/"); ok {
		p = rest
	}
	return filepath.Join(c.cfg.DataDir, strings.TrimPrefix(p, "/"))
}

// Homes lists the accounts of the rescued computer.
func (c *Core) Homes() ([]Home, error) {
	f, err := os.Open(filepath.Join(c.cfg.DataDir, "etc-upper", "passwd"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c.homeMu.Lock()
	defer c.homeMu.Unlock()
	var homes []Home
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		if err != nil || uid < 1000 || uid >= 60000 || !strings.HasPrefix(p[5], "/") || strings.Contains(p[5], "..") {
			continue
		}
		homes = append(homes, Home{UID: uid, Name: p[0], Path: c.dataPath(p[5]), Open: c.opened[uid]})
	}
	return homes, sc.Err()
}

func (c *Core) home(uid int) (Home, error) {
	homes, err := c.Homes()
	if err != nil {
		return Home{}, err
	}
	for _, h := range homes {
		if h.UID == uid {
			return h, nil
		}
	}
	return Home{}, errNoHome
}

// UnlockHome opens an account's files with its PIN, or with its recovery code
// when recovery is set, without changing either.
func (c *Core) UnlockHome(uid int, secret string, recovery bool) error {
	h, err := c.home(uid)
	if err != nil {
		return err
	}
	if secret == "" || len(secret) > 256 || strings.ContainsAny(secret, "\r\n") {
		return errors.New("the PIN or recovery code is not correct")
	}
	raw, err := homeKey(uid, secret, recovery)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := addHomeKey(h.Path, raw); err != nil {
		return err
	}
	c.homeMu.Lock()
	c.opened[uid] = true
	c.homeMu.Unlock()
	return nil
}

func (c *Core) openHome(uid int) (Home, error) {
	h, err := c.home(uid)
	if err != nil {
		return Home{}, err
	}
	if !h.Open {
		return Home{}, errHomeLocked
	}
	return h, nil
}

// CopyHome copies an opened account's files to the rescue drive and returns
// where they went.
func (c *Core) CopyHome(uid int) (string, error) {
	h, err := c.openHome(uid)
	if err != nil {
		return "", err
	}
	if c.cfg.RescueDir == "" {
		return "", errNoRescue
	}
	dst := filepath.Join(c.cfg.RescueDir, h.Name+"-"+time.Now().Format("2006-01-02-150405"))
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return "", err
	}
	if err := copyTree(h.Path, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// SealedLog opens the sealed boot and session log of the computer with the
// reader key kept in the home of the account that claimed it.
func (c *Core) SealedLog(uid int) (string, error) {
	h, err := c.openHome(uid)
	if err != nil {
		return "", err
	}
	key := filepath.Join(h.Path, ".local", "share", "sealedlog", "reader.key")
	if _, err := os.Stat(key); err != nil {
		return "", errors.New("this account does not hold the key of the sealed log")
	}
	return readSealedLog(filepath.Join(c.cfg.DataDir, "lib", "sealedlog", "ring"), filepath.Join(c.cfg.DataDir, "log", "sealedlog"), key)
}

func (c *Core) reinstallLocal(ctx context.Context) (string, error) {
	msg, err := atom.StageFrom(ctx, c.cfg.WALPath, c.cfg.LocalRelease, c.cfg.RootPub, c.cfg.Dirs, true)
	if err != nil {
		return "", fmt.Errorf("recovery reinstall: %w", err)
	}
	if err := atom.SyncBootState(c.cfg.WALPath, c.cfg.Dirs); err != nil {
		return "", fmt.Errorf("recovery reinstall: sync boot-state: %w", err)
	}
	return msg, nil
}
