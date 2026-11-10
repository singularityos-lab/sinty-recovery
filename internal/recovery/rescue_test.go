package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rescueCore(t *testing.T) (*Core, string) {
	t.Helper()
	data := t.TempDir()
	os.MkdirAll(filepath.Join(data, "etc-upper"), 0o755)
	os.WriteFile(filepath.Join(data, "etc-upper", "passwd"), []byte(
		"root:x:0:0::/root:/bin/sh\nalex:x:1000:1000:Alex:/home/alex:/bin/bash\nsam:x:1001:1001::/var/home/sam:/bin/bash\nsinty-badge:x:61000:61000::/run/sinty-badge/home:/bin/bash\nevil:x:1002:1002::/home/../../etc:/bin/sh\n"), 0o644)
	os.MkdirAll(filepath.Join(data, "home", "alex"), 0o700)
	os.MkdirAll(filepath.Join(data, "home", "sam"), 0o700)
	c := NewCore(Config{DataDir: data, RescueDir: filepath.Join(t.TempDir(), "Rescued")})
	return c, data
}

func stubRescue(t *testing.T) (*[]string, *[]byte) {
	t.Helper()
	oldKey, oldAdd, oldCopy, oldLog := homeKey, addHomeKey, copyTree, readSealedLog
	t.Cleanup(func() { homeKey, addHomeKey, copyTree, readSealedLog = oldKey, oldAdd, oldCopy, oldLog })
	var calls []string
	var added []byte
	homeKey = func(uid int, secret string, recovery bool) ([]byte, error) {
		calls = append(calls, map[bool]string{true: "code", false: "pin"}[recovery]+":"+secret)
		if secret != "482915" && secret != "ABCD-EFGH" {
			return nil, errors.New("the PIN or recovery code is not correct")
		}
		return make([]byte, homeKeyLen), nil
	}
	addHomeKey = func(dir string, raw []byte) error {
		calls = append(calls, "add:"+dir)
		added = append([]byte(nil), raw...)
		return nil
	}
	copyTree = func(src, dst string) error {
		calls = append(calls, "copy:"+src+">"+dst)
		return nil
	}
	readSealedLog = func(ring, cold, key string) (string, error) {
		calls = append(calls, "log:"+ring+"|"+cold+"|"+key)
		return "boot 1: loader started\n", nil
	}
	return &calls, &added
}

func TestHomes(t *testing.T) {
	c, data := rescueCore(t)
	homes, err := c.Homes()
	if err != nil {
		t.Fatal(err)
	}
	if len(homes) != 2 || homes[0].Path != filepath.Join(data, "home/alex") || homes[1].Path != filepath.Join(data, "home/sam") {
		t.Fatalf("homes %+v", homes)
	}
}

func TestUnlockCopyAndLog(t *testing.T) {
	c, data := rescueCore(t)
	calls, _ := stubRescue(t)
	if _, err := c.CopyHome(1000); !errors.Is(err, errHomeLocked) {
		t.Fatalf("copied a locked home: %v", err)
	}
	if _, err := c.SealedLog(1000); !errors.Is(err, errHomeLocked) {
		t.Fatalf("read the log of a locked home: %v", err)
	}
	if err := c.UnlockHome(1000, "000000", false); err == nil {
		t.Fatal("wrong PIN opened the home")
	}
	if err := c.UnlockHome(1000, "bad\nline", false); err == nil {
		t.Fatal("multi-line secret accepted")
	}
	if err := c.UnlockHome(4242, "482915", false); !errors.Is(err, errNoHome) {
		t.Fatalf("unknown account: %v", err)
	}
	if err := c.UnlockHome(1000, "ABCD-EFGH", true); err != nil {
		t.Fatal(err)
	}
	homes, _ := c.Homes()
	if !homes[0].Open || homes[1].Open {
		t.Fatalf("open state %+v", homes)
	}
	dst, err := c.CopyHome(1000)
	if err != nil || !strings.HasPrefix(dst, c.cfg.RescueDir+"/alex-") {
		t.Fatalf("copy %q %v", dst, err)
	}
	if _, err := c.SealedLog(1000); err == nil {
		t.Fatal("log read without the reader key")
	}
	key := filepath.Join(data, "home/alex/.local/share/sealedlog/reader.key")
	os.MkdirAll(filepath.Dir(key), 0o700)
	os.WriteFile(key, []byte("00"), 0o600)
	text, err := c.SealedLog(1000)
	if err != nil || !strings.Contains(text, "loader started") {
		t.Fatalf("log %q %v", text, err)
	}
	want := []string{"pin:000000", "code:ABCD-EFGH", "add:" + filepath.Join(data, "home/alex")}
	for _, w := range want {
		if !strings.Contains(strings.Join(*calls, "\n"), w) {
			t.Fatalf("missing %q in %v", w, *calls)
		}
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "log:"+filepath.Join(data, "lib/sealedlog/ring")+"|"+filepath.Join(data, "log/sealedlog")+"|"+key) {
		t.Fatalf("log paths %v", *calls)
	}
}

func TestRescueOverHTTP(t *testing.T) {
	c, _ := rescueCore(t)
	stubRescue(t)
	srv := httptest.NewServer(newHandler(c))
	defer srv.Close()
	post := func(path, body string) map[string]any {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	if out := post("/unlock-home", `{"uid":1001,"secret":"482915"}`); out["ok"] != true {
		t.Fatalf("unlock %v", out)
	}
	resp, _ := http.Get(srv.URL + "/homes")
	var homes struct {
		Homes []Home `json:"homes"`
		Local bool   `json:"local"`
	}
	json.NewDecoder(resp.Body).Decode(&homes)
	resp.Body.Close()
	if len(homes.Homes) != 2 || !homes.Homes[1].Open || homes.Local {
		t.Fatalf("homes %+v", homes)
	}
	runtime := httptest.NewServer(newHandlerWithPolicy(c, HandlerPolicy{Runtime: true}))
	defer runtime.Close()
	r, _ := http.Get(runtime.URL + "/homes")
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("runtime mode serves homes: %d", r.StatusCode)
	}
}

func TestReinstallUsesLocalRelease(t *testing.T) {
	c, _ := rescueCore(t)
	c.cfg.LocalRelease = filepath.Join(t.TempDir(), "release")
	c.cfg.ManifestURL = "https://example.invalid/manifest.json"
	c.cfg.WALPath = filepath.Join(t.TempDir(), "deployment.json")
	_, err := c.Reinstall(context.Background())
	if err == nil || !strings.Contains(err.Error(), c.cfg.LocalRelease) {
		t.Fatalf("reinstall did not read the local release: %v", err)
	}
}
