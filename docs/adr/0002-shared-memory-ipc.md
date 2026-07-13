# ADR-0002: Shared memory IPC between processes

## Status

Accepted (2026-07-13)

## Context

FlowFang consists of three independent processes (sampler, analyzer, processor) that must communicate:

- **Sampler → Analyzer**: high-frequency `FlowSample` records (up to millions per second)
- **Analyzer → Processor**: low-frequency `DpiFingerprint` rule updates (occasional)

The user explicitly rejected sockets as "too slow" and requested shared memory. The IPC mechanism must:
- Be zero-copy for the high-frequency path
- Work between independent processes (one crashing doesn't affect the other)
- Have minimal supply-chain attack surface
- Avoid complex serialization overhead

## Decision

We will use shared memory ring buffers via `memmap2` with a purpose-built SPSC (Single Producer Single Consumer) ring buffer implementation in `flow-common`.

- **Sampler → Analyzer**: `ShmRingBuf<FlowSample>` — writes to `/dev/shm/flowfang-samples`
- **Analyzer → Processor**: `ShmRingBuf<DpiFingerprint>` — writes to `/dev/shm/flowfang-rules`

The ring buffer is ~300 lines of Rust with `AtomicU64` read/write pointers. No external ring buffer crate is used.

## Consequences

### Positive

- **Zero-copy**: Data is written directly into shared memory. No serialization, no syscall overhead per record.
- **Process isolation**: Each process opens the shared memory region independently via `memmap2`. If the analyzer crashes, the sampler continues writing and the buffer fills up (controlled backpressure).
- **Minimal dependencies**: Only `memmap2` (from wasmtime team, well-audited). No third-party ring buffer crate.
- **Fixed-size records**: `FlowSample` is a fixed-size `Copy` type, making the ring buffer logic simple — no heap allocation, no variable-length serialization.

### Negative

- **No built-in backpressure**: If the consumer is too slow, records are silently dropped (oldest-first). The system must tolerate data loss.
- **No built-in observability**: Unlike a socket, there's no "connection refused" or "timeout" diagnostic. The producer has no way to know if a consumer exists.
- **`unsafe` code**: Direct memory manipulation requires `unsafe` blocks. Each is annotated with `// SAFETY:` comments, but the risk is non-zero.
- **Single consumer**: SPSC semantics mean only one process can consume each ring buffer. Future fan-out requires a different design.

## Alternatives considered

### Unix domain sockets (SOCK_DGRAM or SOCK_STREAM)

- Rejected: requires serialization per record, syscall overhead, kernel buffer copies. The user explicitly rejected this as too slow.

### Crossbeam channels

- Rejected: works within a single process only. Doesn't cross process boundaries.

### Third-party shared memory crate (e.g., `shmem`, `shared-memory`, `ipc-channel`)

- Rejected: adds supply-chain risk. The core logic is simple enough to implement directly.

### gRPC / HTTP between processes

- Rejected: massive overhead for the high-frequency sampler→analyzer path. The analyzer's HTTP API is for external consumers (TUI), not internal IPC.

## References

- [memmap2](https://crates.io/crates/memmap2)
- SPSC ring buffer pattern: [Linux kernel's `kfifo`](https://docs.kernel.org/core-api/kfifo.html)
- PRD: FlowFang eBPF 流量审计系统