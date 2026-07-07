# Cairo recovery UI

The graphical recovery front-end: a KMS-direct wifi picker (scan, pick, on-screen
keyboard for the password), a progress view for download and verify, and the
Reinstall / Repair / Wipe menu. Written in **Zig**, it renders with Cairo through the shared `singularity-loginui`
renderer (the same one the greeter and the boot splash use), with no compositor,
exactly like `singularity-boot-splash`.

It drives the same recovery Core as the text UI, over the agent's local API.
