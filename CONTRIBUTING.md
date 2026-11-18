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

## Device- and environment-specific code

Code that exists only because of a specific device, architecture, firmware or environment must be marked on the line above it:

```
DEVICE-FIX(<scope>): <what breaks without this>
```

- `<scope>` is one of: `arm64`, `x86_64`, `uno-q`, `jetson`, `msm`, `nvidia`, `intel`, `amd`, `no-tpm`, `vm`, `u-boot`, `uefi`. A new scope is added to this list in the same pull request that first uses it.
- The text states what fails on that device without the code, not what the code does.
- Use the comment syntax of the file's language.
- This covers driver names, hardware probes, architecture constants, firmware quirks, boot-chain differences and anything gated on a specific environment.
- A pull request that adds or changes such code without the marker is not merged.
- `git grep -n "DEVICE-FIX("` lists every marker in the repository.
