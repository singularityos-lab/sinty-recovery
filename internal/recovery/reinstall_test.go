package recovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/atomloops/atom"
)

func TestReinstallUnreachableFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "deployment.json")
	if err := atom.NewDeployment("test-device", "v1").Save(wal); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}
	dirs := atom.StageDirs{
		Rootfs: filepath.Join(dir, "rootfs"),
		ESP:    filepath.Join(dir, "esp"),
	}
	_ = os.MkdirAll(dirs.Rootfs, 0o755)
	_ = os.MkdirAll(dirs.ESP, 0o755)

	// 127.0.0.1:1 is unroutable -> Stage's fetch fails.
	_, err := Reinstall(context.Background(), wal,
		"http://127.0.0.1:1/manifest.json", "", []byte("not-a-real-root-key"), dirs)
	if err == nil {
		t.Fatal("expected an error reinstalling from an unreachable server")
	}
	if !strings.Contains(err.Error(), "recovery reinstall") {
		t.Errorf("error should be wrapped with the action context, got: %v", err)
	}
}
