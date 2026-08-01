package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxRequestBytes int64 = 4096

type HandlerPolicy struct {
	Runtime  bool
	OwnerUID int
}

type ServePolicy struct {
	Handler     HandlerPolicy
	SocketGroup string
}

type peerUIDKey struct{}

func peerUID(conn net.Conn) (int, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return 0, false
	}
	return int(cred.Uid), true
}

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
	return newHandlerWithPolicy(core, HandlerPolicy{})
}

func newHandlerWithPolicy(core *Core, policy HandlerPolicy) http.Handler {
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
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
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

	// GET /lock-state -> {"locked","unlock_armed","unlock_count"}  (fail-closed read)
	mux.HandleFunc("GET /lock-state", func(w http.ResponseWriter, r *http.Request) {
		s := core.LockState()
		writeJSON(w, http.StatusOK, map[string]any{
			"locked": s.Locked, "unlock_armed": s.UnlockArmed, "unlock_count": s.UnlockCount,
		})
	})

	// POST /arm-unlock {"armed","pin"} -> {"ok","message"}. Runtime mode
	// verifies the unix peer and PIN here before it changes the ESP consent flag.
	mux.HandleFunc("POST /arm-unlock", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Armed bool   `json:"armed"`
			PIN   string `json:"pin"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		ownerUID := 0
		if policy.Runtime && req.Armed {
			if !core.LockState().Locked {
				writeJSON(w, http.StatusOK, map[string]any{
					"ok": false, "message": "The bootloader is already unlocked.",
				})
				return
			}
			ownerUID = policy.OwnerUID
			if ownerUID < 1000 {
				var ok bool
				ownerUID, ok = r.Context().Value(peerUIDKey{}).(int)
				if !ok || ownerUID < 1000 {
					writeJSON(w, http.StatusOK, map[string]any{
						"ok": false, "message": "The owner account could not be verified. Nothing was changed.",
					})
					return
				}
			}
			if len(req.PIN) < 4 || len(req.PIN) > 256 || strings.ContainsAny(req.PIN, "\r\n") {
				writeJSON(w, http.StatusOK, map[string]any{
					"ok": false, "message": "Enter your PIN to allow bootloader unlock.",
				})
				return
			}
			valid, err := cryptoVerifyPIN(ownerUID, req.PIN)
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]any{
					"ok": false, "message": "Your PIN could not be checked right now. Nothing was changed.",
				})
				return
			}
			if !valid {
				writeJSON(w, http.StatusOK, map[string]any{
					"ok": false, "message": "Incorrect PIN. Bootloader unlock was not allowed.",
				})
				return
			}
		}
		var ok bool
		var msg string
		if policy.Runtime && req.Armed {
			ok, msg = core.ArmUnlockForOwner(true, ownerUID)
		} else {
			ok, msg = core.ArmUnlock(req.Armed)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "message": msg})
	})

	// POST /unlock-bootloader {"confirm"} -> {"ok","message"}  (fail-closed: needs
	// confirm=="UNLOCK" AND a live-armed flag, both re-checked server-side)
	mux.HandleFunc("POST /unlock-bootloader", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Confirm string `json:"confirm"`
			PIN     string `json:"pin"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		ok, msg := core.UnlockBootloader(req.Confirm, req.PIN)
		if ok {
			ui.set(3, 100, msg)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "message": msg})
	})

	if !policy.Runtime {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet && r.URL.Path == "/lock-state") ||
			(r.Method == http.MethodPost && r.URL.Path == "/arm-unlock") {
			mux.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// Serve exposes Core over a local HTTP API on a unix socket, for the Cairo UI
// (which drives the same Core the in-process text UI does). It runs until ctx is
// cancelled.
func Serve(ctx context.Context, core *Core, socketPath string) error {
	return ServeWithPolicy(ctx, core, socketPath, ServePolicy{})
}

func ServeWithPolicy(ctx context.Context, core *Core, socketPath string, policy ServePolicy) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if policy.SocketGroup == "" {
		if err := os.Chmod(socketPath, 0o600); err != nil {
			ln.Close()
			return err
		}
	} else {
		group, err := user.LookupGroup(policy.SocketGroup)
		if err != nil {
			ln.Close()
			return fmt.Errorf("recovery socket group %s: %w", policy.SocketGroup, err)
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			ln.Close()
			return fmt.Errorf("recovery socket group %s has invalid gid", policy.SocketGroup)
		}
		if err := os.Chown(socketPath, -1, gid); err != nil {
			ln.Close()
			return err
		}
		if err := os.Chmod(socketPath, 0o660); err != nil {
			ln.Close()
			return err
		}
	}

	srv := &http.Server{
		Handler:           newHandlerWithPolicy(core, policy.Handler),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if uid, ok := peerUID(conn); ok {
				return context.WithValue(ctx, peerUIDKey{}, uid)
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
