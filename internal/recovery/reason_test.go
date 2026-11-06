package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/atom"
)

func TestReasonIsReadOnceAndConsumed(t *testing.T) {
	esp := t.TempDir()
	os.MkdirAll(filepath.Join(esp, "state"), 0o755)
	p := filepath.Join(esp, "state", "recovery-reason")
	os.WriteFile(p, []byte("loader: the system kernel has an invalid signature\n"), 0o644)
	c := NewCore(Config{Dirs: atom.StageDirs{ESP: esp}})
	want := Reason{Code: "loader", Cause: "the system kernel has an invalid signature"}
	if got := c.Reason(); got != want {
		t.Fatalf("got %+v", got)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("reason file left behind: %v", err)
	}
	if got := c.Reason(); got != want {
		t.Fatalf("second read %+v", got)
	}
	if got := NewCore(Config{Dirs: atom.StageDirs{ESP: esp}}).Reason(); got != (Reason{}) {
		t.Fatalf("stale reason %+v", got)
	}
}
