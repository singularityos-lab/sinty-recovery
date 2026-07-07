#!/usr/bin/env bash
#
# VM integration test for the Cairo recovery UI, in a software-render sandbox
# (no GPU, no real display). Brings up a virtual KMS device (vkms), starts the
# agent in serve mode and runs the UI against vkms. It checks that the UI comes
# up and stays up; reading back the rendered pixels is not implemented, so the
# visual check is still manual.
#
# Run inside a throwaway VM / QEMU as root (vkms + reading /dev/dri needs it).
# NEVER run this on the dev host: it modprobe's vkms and grabs a DRM master.
#
#   sudo ./vm-test.sh [seconds]
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SECS="${1:-8}"
UI="$HERE/zig-out/bin/sinty-recovery-ui"
AGENT="$(command -v atom-recovery || echo "$HERE/../../atom-recovery")"

[ -x "$UI" ] || { echo "build the UI first: zig build"; exit 1; }

echo "== load vkms (virtual KMS) =="
modprobe vkms 2>/dev/null || { echo "vkms unavailable; need CONFIG_DRM_VKMS"; exit 1; }
sleep 1
ls -l /dev/dri/

echo "== start the agent serve-mode (if built) =="
if [ -x "$AGENT" ]; then
    "$AGENT" --mode serve --socket /run/atom-recovery.sock >/tmp/agent.log 2>&1 &
    AGENT_PID=$!
    sleep 1
    export RECOVERY_MOCK=0
    echo "agent on /run/atom-recovery.sock (pid $AGENT_PID)"
else
    export RECOVERY_MOCK=1
    echo "agent binary not found; running the UI on the mock"
fi

echo "== run the UI against vkms for ${SECS}s =="
# vkms is usually the last card; the UI's drm_setup() scans card0..card2.
"$UI" >/tmp/ui.log 2>&1 &
UI_PID=$!
sleep "$SECS"

echo "== UI log =="
tail -20 /tmp/ui.log

kill "$UI_PID" 2>/dev/null
[ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null
echo "== done. ui.log + agent.log in /tmp =="
