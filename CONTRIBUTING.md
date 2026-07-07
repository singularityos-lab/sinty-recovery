# Contributing to Sinty Recovery

```bash
git clone https://github.com/singularityos-lab/sinty-recovery
cd sinty-recovery
go build ./...
go test ./...
```

The Go code depends on the Atom Loops library through its public `atom` package,
pinned in `go.mod`.

## Guidelines

- Keep the recovery minimal: it must boot and work when the main system does not.
- Never install an image without the two-tier verification: the trust is the
  signature, not the transport.
- Wifi and disk paths are exercised on real hardware; keep the pure logic (parsing,
  the menu, the deployment transitions) unit tested.

By contributing you agree to the [CLA](CLA.md). The project is GPL-3.0-only.
