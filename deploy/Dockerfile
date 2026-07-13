# FlowFang — multi-stage Dockerfile
# Builds musl-static binaries, runs on Alpine.

# Stage 1: Build
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY . .

# Build all binaries with musl target
RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runtime
FROM alpine:latest

RUN apk add --no-cache nftables

# Copy binaries
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/flow-sampler /usr/local/bin/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/flow-analyzer /usr/local/bin/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/flow-analyzer-tui /usr/local/bin/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/flow-processor /usr/local/bin/

# Copy install script
COPY deploy/install.sh /usr/local/bin/flowfang-install
RUN chmod +x /usr/local/bin/flowfang-install

# Copy default config
COPY config/flow-audit.toml /etc/flowfang/config.toml

# Mount bpffs
RUN mkdir -p /sys/fs/bpf/flowfang

# Run all three components (use supervisord or a simple init)
# For simplicity, we provide a start script
COPY deploy/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]