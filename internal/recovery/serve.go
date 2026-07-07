package recovery

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
)

// uiState tracks the async job the UI polls: which long action is running, its
// coarse progress, and whether the network is up. connect is synchronous; the
// reinstall/repair/rollback actions run in the background and the UI follows them
// through GET /status (state + progress + message).
type uiState struct {
	mu       sync.Mutex
	state    int // 0 idle, 1 connecting, 2 working, 3 done, 4 failed
	progress int // -1 indeterminate, else 0..100
	message  string
	online   bool
}

func (u *uiState) set(state, progress int, msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.state, u.progress, u.message = state, progress, msg
}

func (u *uiState) setOnline(v bool) {
	u.mu.Lock()
	u.online = v
	u.mu.Unlock()
}

func (u *uiState) working() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state == 2
}

func (u *uiState) snapshot() (state, progress int, message string, online bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state, u.progress, u.message, u.online
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// newHandler builds the routes wrapping Core (split from Serve so it is testable
// without a socket). It matches the contract the Cairo UI consumes.
func newHandler(core *Core) http.Handler {
	ui := &uiState{progress: -1}
	mux := http.NewServeMux()

	// GET /scan -> [{"ssid","signal","secure"}, ...]
	mux.HandleFunc("GET /scan", func(w http.ResponseWriter, r *http.Request) {
		nets, err := core.Scan(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out := make([]map[string]any, 0, len(nets))
		for _, n := range nets {
			out = append(out, map[string]any{"ssid": n.SSID, "signal": n.Signal, "secure": n.Secure})
		}
		writeJSON(w, http.StatusOK, out)
	})

	// POST /connect {"ssid","psk"} -> {"ok":bool,"error":str}  (synchronous)
	mux.HandleFunc("POST /connect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SSID string `json:"ssid"`
			PSK  string `json:"psk"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		ui.set(1, -1, "Connecting to "+req.SSID)
		if err := core.Connect(r.Context(), req.SSID, req.PSK); err != nil {
			ui.set(4, -1, err.Error())
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		ui.setOnline(true)
		ui.set(0, -1, "Connected")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// GET /status -> {online,current,rollback,state,progress,message}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		state, progress, message, online := ui.snapshot()
		cur, rb := "", ""
		if s, err := core.Status(); err == nil {
			cur, rb = s.Current, s.Rollback
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"online": online, "current": cur, "rollback": rb,
			"state": state, "progress": progress, "message": message,
		})
	})

	// POST /reinstall|/repair|/rollback {} -> {"started":bool}  (async; follow via /status)
	start := func(verb string, fn func(context.Context) (string, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if ui.working() {
				writeJSON(w, http.StatusOK, map[string]bool{"started": false})
				return
			}
			ui.set(2, -1, verb+"...")
			go func() {
				msg, err := fn(context.Background())
				if err != nil {
					ui.set(4, -1, err.Error())
					return
				}
				ui.set(3, 100, msg)
			}()
			writeJSON(w, http.StatusOK, map[string]bool{"started": true})
		}
	}
	mux.HandleFunc("POST /reinstall", start("Reinstalling", core.Reinstall))
	mux.HandleFunc("POST /repair", start("Repairing", func(context.Context) (string, error) { return core.Repair() }))
	mux.HandleFunc("POST /rollback", start("Rolling back", func(context.Context) (string, error) { return core.Rollback() }))

	return mux
}

// Serve exposes Core over a local HTTP API on a unix socket, for the Cairo UI
// (which drives the same Core the in-process text UI does). It runs until ctx is
// cancelled.
func Serve(ctx context.Context, core *Core, socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(socketPath, 0o660)

	srv := &http.Server{Handler: newHandler(core)}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
