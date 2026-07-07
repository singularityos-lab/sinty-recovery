package recovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/atomloops/atom"
)

func TestServeStatusContract(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "deployment.json")
	if err := atom.NewDeployment("dev", "v1").Save(wal); err != nil {
		t.Fatalf("seed WAL: %v", err)
	}
	core := NewCore(Config{WALPath: wal, Dirs: atom.StageDirs{Rootfs: dir, ESP: dir}})
	srv := httptest.NewServer(newHandler(core))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"online", "current", "rollback", "state", "progress", "message"} {
		if _, ok := s[k]; !ok {
			t.Errorf("status missing key %q (got %v)", k, s)
		}
	}
	if s["state"].(float64) != 0 {
		t.Errorf("fresh agent should be idle (state 0), got %v", s["state"])
	}
}
