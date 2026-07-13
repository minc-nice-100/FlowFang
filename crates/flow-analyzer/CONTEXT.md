# flow-analyzer — Domain Glossary

The core analysis engine. Reads flow samples from shared memory, aggregates statistics, generates DPI fingerprints, and exposes an HTTP API for the TUI and other consumers.

## Glossary

### Analyzer

The central user-space binary. Responsibilities:
1. Consume `FlowSample` records from the `ShmRingBuf` (written by the sampler)
2. Aggregate traffic statistics (rates, totals, top-N)
3. Generate DPI fingerprints from observed traffic patterns
4. Expose HTTP API for the TUI and other consumers
5. Write fingerprint rules to the processor's BPF maps via bpffs

### Five-Tuple Aggregation

Grouping packets by `(src_ip, dst_ip, src_port, dst_port, protocol)` to form "flows". Each flow is a unidirectional stream of packets between two endpoints. Statistics are computed per-flow and aggregated globally.

### DPI Fingerprint Generation

The process of analyzing payload patterns to identify applications, protocols, or malware. The analyzer examines the first 64 bytes of payload across many flows, looking for recurring patterns (magic bytes, protocol headers, TLS SNI values, JA3 hashes). When a pattern is identified, it creates a `DpiFingerprint` and offers it to the user for confirmation.

### HTTP API

A RESTful API served by the analyzer. Supports two listen modes, like Docker daemon:
- **Unix socket** (default): `/var/run/flowfang.sock`
- **TCP port** (optional): configured via `listen = "0.0.0.0:9090"`

Endpoints:
- `GET /api/status` — system health and version
- `GET /api/stats` — current traffic statistics
- `GET /api/fingerprints` — list active fingerprint rules
- `POST /api/fingerprints` — create a new fingerprint rule
- `DELETE /api/fingerprints/{id}` — delete a fingerprint rule
- `GET /api/events` — Server-Sent Events stream of real-time alerts

### SSE (Server-Sent Events)

A unidirectional HTTP stream from the analyzer to the TUI. The TUI opens a long-lived `GET /api/events` connection and receives push events (new flow detected, fingerprint matched, alert triggered) without polling.

### Fingerprint Rule

A `DpiFingerprint` that has been confirmed and deployed. Rules are written to the processor's BPF maps via the pinned bpffs paths. The processor's eBPF program reads these maps and applies the rules to every packet.

### Traffic Statistics

Real-time metrics computed by the analyzer:
- **Packets per second (pps)** — current throughput
- **Bytes per second (bps)** — bandwidth usage
- **Active flows** — count of unique five-tuples
- **Top-N flows** — flows with the highest packet/byte counts
- **Fingerprint hits** — count of packets matching each active fingerprint