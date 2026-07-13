#!/bin/sh
# FlowFang — uninstall script
# Stops all services, removes binaries, configs, and shared memory.

set -e

echo "FlowFang uninstaller"

# --- Stop services ---
if command -v systemctl >/dev/null 2>&1; then
    echo "Stopping systemd services..."
    systemctl stop flowfang-sampler flowfang-analyzer flowfang-processor 2>/dev/null || true
    systemctl disable flowfang-sampler flowfang-analyzer flowfang-processor 2>/dev/null || true
    rm -f /etc/systemd/system/flowfang-sampler.service
    rm -f /etc/systemd/system/flowfang-analyzer.service
    rm -f /etc/systemd/system/flowfang-processor.service
    systemctl daemon-reload
fi

# --- Remove binaries ---
INSTALL_DIR="/usr/local/bin"
for bin in flow-sampler flow-analyzer flow-analyzer-tui flow-processor; do
    rm -f "$INSTALL_DIR/$bin"
    rm -f "/usr/bin/$bin"
done

# --- Remove config ---
rm -rf /etc/flowfang

# --- Clean shared memory ---
rm -f /dev/shm/flowfang-*

# --- Clean bpffs ---
rm -rf /sys/fs/bpf/flowfang

# --- Clean socket ---
rm -f /var/run/flowfang.sock

echo "FlowFang uninstalled."