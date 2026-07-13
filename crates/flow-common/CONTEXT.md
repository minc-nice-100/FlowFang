# flow-common — Domain Glossary

Shared types, IPC primitives, configuration, and error handling used by all other contexts.

## Glossary

### ShmRingBuf

A **Single-Producer Single-Consumer (SPSC) ring buffer** backed by shared memory. Built on `memmap2`, with no external dependencies. The producer writes items into a fixed-capacity circular buffer; the consumer reads them out. Both sides use `AtomicU64` read/write pointers to coordinate without locks. The buffer is identified by a name string, which maps to a shared memory file under `/dev/shm/`.

**Why not a crate:** to minimize supply-chain attack surface. The implementation is ~300 lines of Rust with `// SAFETY:` annotations on every `unsafe` block.

**Related terms:** [[flow-sampler]], [[flow-analyzer]], [[flow-processor]]

### FlowSample

A fixed-size record representing one sampled network packet. Contains:

| Field | Type | Description |
|---|---|---|
| `timestamp` | `u64` | Arrival time in nanoseconds |
| `src_ip` | `[u16; 8]` | Source IP (IPv4 mapped to IPv6, stored as 8×u16 words) |
| `dst_ip` | `[u16; 8]` | Destination IP (IPv4 mapped to IPv6) |
| `src_port` | `u16` | Source port |
| `dst_port` | `u16` | Destination port |
| `protocol` | `u8` | IP protocol number (6=TCP, 17=UDP, 1=ICMP) |
| `payload` | `[u8; 64]` | First 64 bytes of payload |
| `payload_len` | `u16` | Actual payload length (may be > 64) |
| `pkt_size` | `u32` | Total packet size in bytes |

**Why IPv6-only:** All IPv4 addresses are mapped to IPv6 (`::ffff:a.b.c.d`), keeping the type size fixed and simplifying the eBPF→user boundary.

### DpiFingerprint

A rule that identifies a specific traffic pattern. Contains an `id` (UUID), a `name`, a `DpiPattern`, and a `ProcessorAction`. Produced by the analyzer, consumed by the processor.

### RuleUpdate

A fixed-size, `Pod`-compatible representation of `DpiFingerprint` for shared memory transfer. All fields are fixed-size arrays or scalars — no heap allocations. The analyzer converts `DpiFingerprint` → `RuleUpdate` via `From`, writes to `ShmRingBuf<RuleUpdate>`, and the processor reads `RuleUpdate` directly. A sentinel `action = 0xFFFF_FFFF` signals deletion.

**Related terms:** [[DpiFingerprint]], [[ShmRingBuf]], [[flow-processor]]

### RuleUpdate

A fixed-size, `Pod`-compatible representation of `DpiFingerprint` for shared memory transfer. All fields are fixed-size arrays or scalars — no heap allocations. The analyzer converts `DpiFingerprint` → `RuleUpdate` via `From`, writes to shared memory, and the processor reads `RuleUpdate` directly. A sentinel `action = 0xFFFF_FFFF` signals deletion.

**Related terms:** [[DpiFingerprint]], [[ShmRingBuf]], [[flow-processor]]

### DpiPattern

The matching criteria for a fingerprint. Variants:

- **ExactMatch** — match specific bytes at a specific offset in the payload
- **ByteSeq** — match a byte sequence anywhere in the payload
- **Regex** — match payload against a regular expression
- **TlsSni** — match a TLS Server Name Indication value
- **TlsJa3** — match a JA3 hash (TLS client fingerprint)

### ProcessorAction

The action to take when a DpiFingerprint matches:

- **Pass** — allow the packet through
- **Drop** — silently discard the packet
- **Mark** — set an nfmark value on the packet (delegates to nftables for complex policy)

### FlowError

The canonical error type for the project. An enum covering:
- `Shm` — shared memory errors
- `Ebpf` — eBPF loading/attach errors
- `Config` — configuration parsing errors
- `Io` — wrapped `std::io::Error`

### Configuration

TOML or YAML files, loaded by file extension. Each binary has its own configuration struct. Resolution order:
1. CLI argument
2. `FLOWFANG_CONFIG` environment variable
3. `/etc/flowfang/config.{toml,yaml,yml}`
4. `./config/default.{toml,yaml}`