# flow-sampler — Domain Glossary

The user-space loader for the sampler eBPF program. Consumes ringbuf data from the kernel and writes it to the shared memory ring buffer.

## Glossary

### Sampler

The user-space binary that loads `sampler.bpf.o` and bridges kernel→user IPC. It:
1. Loads and attaches the sampler eBPF program to an interface's TC ingress
2. Reads `FlowSample` records from the kernel ringbuf
3. Writes them into the `ShmRingBuf<FlowSample>` shared memory buffer
4. Handles graceful shutdown (SIGTERM/SIGINT) by detaching and cleaning up

### Sampling Rate

A configurable 1/N ratio. When N=1, every packet is sampled. When N=100, one in 100 packets is sampled. Controls trade-off between visibility and CPU overhead.

### Loopback Whitelist

The sampler skips traffic on the `lo` interface and any traffic destined for internal management ports (e.g., the analyzer's own HTTP API port). This prevents the system from auditing its own traffic.

### Ringbuf Consumer

The loop that reads `FlowSample` records from the kernel ringbuf. The kernel writes records into the ringbuf; the consumer reads them out. If the consumer is too slow, the ringbuf fills up and the kernel drops the oldest records — this is intentional backpressure.

### Kernel Ringbuf

The eBPF ringbuf (`BPF_MAP_TYPE_RINGBUF`) is a shared-memory circular buffer between the eBPF program (kernel) and the loader (user). The kernel writes; the user reads. Unlike perfbuf, ringbuf is a single buffer (not per-CPU), has lower overhead, and supports configurable watermarks.

### TC Attach Point

The network interface and direction where the sampler eBPF program is attached. Default: `eth0` ingress. Configurable per deployment.