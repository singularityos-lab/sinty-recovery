# Sinty Recovery

The recovery for Sinty OS: a small, signed, always-present image that survives a
dead main system (a broken boot, a bad update, on-disk corruption) and lets you
re-download and reinstall a fresh, signed Sinty over wifi, or repair the current
one, with no desktop and no ethernet.

## What it does

- Brings up wifi with no NetworkManager and no compositor: it talks
  wpa_supplicant's control interface directly and leases with udhcpc.
- Reinstall: fetch a signed image from the update URL, verify it end to end with
  the recovery's embedded ROOT key, stage it and point the boot-state at it.
- Repair: roll back to last_known_good with no network.
- Two front-ends over one shared core: a text UI (the graphics-free
  fallback) and a Cairo UI (KMS-direct, reusing the shared singularity-loginui
  renderer).

## Build

```sh
go build ./...
go build -o atom-recovery ./cmd/atom-recovery
```

It depends on the Atom Loops library (the staging and verification pipeline and
the deployment WAL) through its public `atom` package.

## Layout

- `cmd/atom-recovery` -- the agent binary.
- `internal/recovery` -- the shared Core and the text UI.
- `internal/wifi` -- the wpa_supplicant + udhcpc wifi driver.
- `ui/cairo` -- the graphical recovery UI (KMS-direct, singularity-loginui).

## Local API

`atom-recovery --mode serve` exposes an HTTP/1.1 API over a unix socket
(`/run/atom-recovery.sock`, mode 0660), so the Cairo UI drives the same Core the
text UI uses in process.

| Method + path     | Request body     | Response (200)                                      |
|-------------------|------------------|-----------------------------------------------------|
| `GET /scan`       | --               | `[{"ssid","signal","secure"}, ...]`                 |
| `POST /connect`   | `{"ssid","psk"}` | `{"ok":true}`                                        |
| `GET /status`     | --               | deployment status (below)                           |
| `POST /reinstall` | --               | `{"started":true}`                                  |
| `POST /rollback`  | --               | `{"started":true}`                                  |
| `POST /repair`    | --               | `{"started":true}`                                  |

Errors return non-200 with `{"error":"..."}`. `signal` is dBm (more negative is
weaker); an empty `psk` means an open network. `POST /connect` blocks until
associated + DHCP. `reinstall`, `repair` and `rollback` start a job and return
at once: follow it on `GET /status`. `GET /status`:

```json
{
  "current": "...", "pending": "...", "rollback": "...", "last_known_good": "...",
  "boot_attempts": 3, "recovery": "...", "kernelcache": 0, "security_level": 0
}
```

```sh
curl --unix-socket /run/atom-recovery.sock http://localhost/status
curl --unix-socket /run/atom-recovery.sock -X POST http://localhost/connect \
  -d '{"ssid":"HomeNet","psk":"secret"}'
```

## License

GPL-3.0-only. See [LICENSE](LICENSE). Contributions are under the [CLA](CLA.md).
