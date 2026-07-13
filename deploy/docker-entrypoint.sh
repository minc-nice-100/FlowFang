#!/bin/sh
# FlowFang — Docker entrypoint
# Starts all three components.

set -e

echo "Starting FlowFang..."

# Mount bpffs
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /sys/fs/bpf/flowfang

# Start analyzer first (creates shared memory)
flow-analyzer --listen unix:///var/run/flowfang.sock &
ANALYZER_PID=$!
sleep 1

# Start sampler
flow-sampler --iface eth0 &
SAMPLER_PID=$!

# Start processor
flow-processor --iface eth0 &
PROCESSOR_PID=$!

echo "FlowFang running:"
echo "  Analyzer:  PID $ANALYZER_PID"
echo "  Sampler:   PID $SAMPLER_PID"
echo "  Processor: PID $PROCESSOR_PID"

# Wait for any to exit
wait -n $ANALYZER_PID $SAMPLER_PID $PROCESSOR_PID
echo "A component exited, shutting down..."

kill $ANALYZER_PID $SAMPLER_PID $PROCESSOR_PID 2>/dev/null || true
wait