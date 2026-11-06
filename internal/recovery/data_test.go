package recovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkobrombin/atomloops/atom"
	"github.com/mirkobrombin/atomloops/boot"
)

const (
	fsckClean      = "[FSCK] valid_node_count matching with CP (nat lookup) [Ok..] [0xcc]\n"
	fsckAccounting = "[FSCK] valid_node_count matching with CP (nat lookup) [Fail] [0xcc]\n"
	fsckRisky      = "[ASSERT] (sanity_check_nid: 429)  --> nid[0xa]\n[FSCK] Unreachable nat entries                        [Fail] [0x1]\n"
)

type fakeDisk struct {
	state string
	calls []string
}

func (d *fakeDisk) run(name string, args ...string) (string, int) {
	d.calls = append(d.calls, strings.Join(args, " "))
	if args[0] == "-f" && args[1] == "-y" {
		d.state = fsckClean
		return "fixed", 0
	}
	if d.state == fsckClean {
		return d.state, 0
	}
	return d.state, 1
}

func brokenCore(t *testing.T, state string) (*Core, *fakeDisk, string) {
	t.Helper()
	esp := t.TempDir()
	d := &fakeDisk{state: state}
	old, oldLog := runChecker, logRepair
	runChecker = d.run
	logRepair = func(boot.Repair) {}
	t.Cleanup(func() { runChecker, logRepair = old, oldLog })
	c := NewCore(Config{BrokenData: "/dev/vda2", Dirs: atom.StageDirs{ESP: esp}})
	return c, d, esp
}

func withVerifier(t *testing.T, esp, uid, pin string) {
	t.Helper()
	dir := filepath.Join(esp, "state", "pin")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, uid+".priv"), []byte("sealed"), 0o600)
	old := verifyVerifierPIN
	verifyVerifierPIN = func(u, p string) (bool, error) { return u == uid && p == pin, nil }
	t.Cleanup(func() { verifyVerifierPIN = old })
}

func TestAccountingDamageIsRepairedWithoutPIN(t *testing.T) {
	c, _, _ := brokenCore(t, fsckAccounting)
	ok, msg := c.DataRepair("", "")
	if !ok {
		t.Fatalf("accounting repair refused: %s", msg)
	}
	if r, _ := c.DataCheck(); r.Verdict != boot.CheckClean {
		t.Errorf("after repair: %s", r.Verdict)
	}
}

func TestRiskyRepairNeedsPINAndConfirmation(t *testing.T) {
	c, d, esp := brokenCore(t, fsckRisky)
	if ok, _ := c.DataRepair("1234", "REPAIR"); ok {
		t.Fatal("risky repair ran with no PIN verifier on the device")
	}
	withVerifier(t, esp, "1001", "1234")
	for _, tc := range []struct{ pin, confirm string }{{"9999", "REPAIR"}, {"1234", ""}, {"", "REPAIR"}} {
		if ok, msg := c.DataRepair(tc.pin, tc.confirm); ok {
			t.Errorf("pin=%q confirm=%q repaired: %s", tc.pin, tc.confirm, msg)
		}
	}
	for _, call := range d.calls {
		if strings.HasPrefix(call, "-f -y") {
			t.Fatalf("the disk was written before the PIN and confirmation: %v", d.calls)
		}
	}
	if ok, msg := c.DataRepair("1234", "REPAIR"); !ok {
		t.Fatalf("confirmed repair refused: %s", msg)
	}
}

func TestStartSystemOnlyAfterACleanCheck(t *testing.T) {
	c, _, esp := brokenCore(t, fsckRisky)
	if ok, _ := c.StartSystem(); ok {
		t.Fatal("the system was started on a damaged data partition")
	}
	os.WriteFile(filepath.Join(esp, "boot-state"), []byte("target=recovery\ntrial=0\nattempts=0\n"), 0o644)
	c2, _, esp2 := brokenCore(t, fsckClean)
	os.WriteFile(filepath.Join(esp2, "boot-state"), []byte("target=recovery\n"), 0o644)
	if ok, msg := c2.StartSystem(); !ok {
		t.Fatalf("clean partition: %s", msg)
	}
	b, _ := os.ReadFile(filepath.Join(esp2, "boot-state"))
	if !strings.HasPrefix(string(b), "target=active\n") {
		t.Errorf("boot-state %q", b)
	}
}

func TestSaveReportLandsOnTheESP(t *testing.T) {
	c, _, esp := brokenCore(t, fsckAccounting)
	path, err := c.SaveReport()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != filepath.Join(esp, "state") {
		t.Errorf("report at %s", path)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "verdict=accounting") {
		t.Errorf("report %q", b)
	}
}

func TestBrokenDataMenu(t *testing.T) {
	c, _, esp := brokenCore(t, fsckAccounting)
	var out strings.Builder
	if err := NewTTY(c, strings.NewReader("1\n2\n4\n"), &out).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"partizione dati danneggiata", "solo nei conteggi", "The data partition was repaired.", "Sinty OS will start at the next boot."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("menu output lacks %q:\n%s", want, out.String())
		}
	}
	b, _ := os.ReadFile(filepath.Join(esp, "boot-state"))
	if !strings.HasPrefix(string(b), "target=active") {
		t.Errorf("boot-state %q", b)
	}
}

func TestServeDataContract(t *testing.T) {
	c, _, esp := brokenCore(t, fsckRisky)
	withVerifier(t, esp, "1000", "246810")
	srv := httptest.NewServer(newHandler(c))
	defer srv.Close()

	get := func() map[string]any {
		resp, err := http.Get(srv.URL + "/data")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	m := get()
	if m["broken"] != "/dev/vda2" || m["pin"] != true || m["verdict"] != "" {
		t.Fatalf("data before check = %v", m)
	}
	post := func(path, body string) map[string]any {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	status := func() map[string]any {
		for i := 0; i < 200; i++ {
			resp, err := http.Get(srv.URL + "/status")
			if err != nil {
				t.Fatal(err)
			}
			var s map[string]any
			json.NewDecoder(resp.Body).Decode(&s)
			resp.Body.Close()
			if s["state"].(float64) != 2 {
				return s
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("action never finished")
		return nil
	}
	if r := post("/data-check", "{}"); r["started"] != true {
		t.Fatalf("data-check = %v", r)
	}
	status()
	if m := get(); m["verdict"] != "needs-user" {
		t.Fatalf("verdict after check = %v", m)
	}
	post("/data-repair", `{"pin":"111111","confirm":"REPAIR"}`)
	if s := status(); s["state"].(float64) != 4 || !strings.Contains(s["message"].(string), "Incorrect PIN") {
		t.Fatalf("wrong PIN status = %v", s)
	}
	if r := post("/data-start", "{}"); r["ok"] != false {
		t.Fatalf("start with damage = %v", r)
	}
	post("/data-repair", `{"pin":"246810","confirm":"REPAIR"}`)
	if s := status(); s["state"].(float64) != 3 {
		t.Fatalf("repair status = %v", s)
	}
	if m := get(); m["fixed"] != true {
		t.Fatalf("data after repair = %v", m)
	}
	if r := post("/data-report", "{}"); r["ok"] != true {
		t.Fatalf("report = %v", r)
	}
	if r := post("/data-start", "{}"); r["ok"] != true {
		t.Fatalf("start = %v", r)
	}
	b, _ := os.ReadFile(filepath.Join(esp, "boot-state"))
	if !strings.HasPrefix(string(b), "target=active") {
		t.Fatalf("boot-state = %q", b)
	}
}
