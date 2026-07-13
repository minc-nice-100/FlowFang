#!/bin/sh
# FlowFang — install script
# Detects the OS and architecture, downloads the corresponding musl
# static binaries, and installs systemd services.

set -e

ARCH=$(uname -m)
OS=$(uname -s)

case "$ARCH" in
    x86_64)  BIN_ARCH="x86_64" ;;
    aarch64) BIN_ARCH="aarch64" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "FlowFang installer"
echo "  OS: $OS, Arch: $BIN_ARCH"

# --- Install binaries ---
INSTALL_DIR="/usr/local/bin"
BINARIES="flow-sampler flow-analyzer flow-analyzer-tui flow-processor"

for bin in $BINARIES; do
    echo "Installing $bin..."
    cp "$bin" "$INSTALL_DIR/$bin"
    chmod 755 "$INSTALL_DIR/$bin"
    # Use hard link instead of symlink for Alpine/busybox compatibility
    ln -f "$INSTALL_DIR/$bin" "/usr/bin/$bin" 2>/dev/null || true
done

# --- Create config directory ---
CONFIG_DIR="/etc/flowfang"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    cat > "$CONFIG_DIR/config.toml" << 'EOF'
# FlowFang configuration
[analyzer]
listen = "unix:///var/run/flowfang.sock"

[sampler]
iface = "eth0"
shm_name = "flowfang-samples"
shm_capacity = 65536

[processor]
iface = "eth0"
rules_shm_name = "flowfang-rules"
rules_capacity = 1024
EOF
    echo "Default config created at $CONFIG_DIR/config.toml"
fi

# --- Mount bpffs ---
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    echo "Mounting bpffs..."
    mount -t bpf bpf /sys/fs/bpf
fi
mkdir -p /sys/fs/bpf/flowfang

# --- Install systemd services ---
if command -v systemctl >/dev/null 2>&1; then
    SERVICE_DIR="/etc/systemd/system"

    cat > "$SERVICE_DIR/flowfang-sampler.service" << EOF
[Unit]
Description=FlowFang Sampler
After=network.target
Requires=flowfang-analyzer.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/flow-sampler --config $CONFIG_DIR/config.toml
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SERVICE_DIR/flowfang-analyzer.service" << EOF
[Unit]
Description=FlowFang Analyzer
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/flow-analyzer --config $CONFIG_DIR/config.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SERVICE_DIR/flowfang-processor.service" << EOF
[Unit]
Description=FlowFang Processor
After=network.target
Requires=flowfang-analyzer.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/flow-processor --config $CONFIG_DIR/config.toml
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "Systemd services installed."
    echo ""
    echo "To start FlowFang:"
    echo "  systemctl start flowfang-analyzer"
    echo "  systemctl start flowfang-sampler"
    echo "  systemctl start flowfang-processor"
    echo ""
    echo "To enable at boot:"
    echo "  systemctl enable flowfang-analyzer flowfang-sampler flowfang-processor"
else
    echo "systemctl not found — skipping service installation."
    echo "Start binaries manually with:"
    echo "  flow-analyzer &"
    echo "  flow-sampler &"
    echo "  flow-processor &"
fi

echo "FlowFang installation complete."