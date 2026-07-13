# ebpf — Domain Glossary

The eBPF kernel-space programs. Written in Rust, compiled to `bpfel-unknown-none` target, loaded by the user-space counterparts.

## Glossary

### eBPF Program

A sandboxed kernel-space program that runs in the eBPF virtual machine. Subject to the **verifier** — the kernel checks that the program is safe (no unbounded loops, no invalid pointer access, bounded stack usage) before allowing it to load.

### Sampler eBPF (`sampler.bpf.rs`)

The kernel-side sampler. Attached to TC ingress. For each packet:
1. Extract the five-tuple (IPs, ports, protocol)
2. Extract the first 64 bytes of payload
3. Build a `FlowSample` struct
4. Push it into the ringbuf for user-space consumption

Configurable sampling rate: skip N-1 out of every N packets.

### Processor eBPF (`processor.bpf.rs`)

The kernel-side processor. Attached to TC ingress. For each packet:
1. Look up active fingerprints in the `FINGERPRINTS` BPF map
2. Match the packet's payload against each fingerprint's DpiPattern
3. On match, look up the corresponding action in the `ACTIONS` map
4. Execute the action: pass, drop, or mark

### Verifier

The kernel's static analyzer for eBPF programs. It checks:
- No out-of-bounds memory access
- No use of uninitialized registers
- All code paths are reachable
- No unbounded loops
- Stack depth is bounded

If the verifier rejects the program, it returns a detailed error message. **Aya + Rust reduces verifier failures** because the compiler catches pointer errors before the verifier ever sees them.

### CO-RE (Compile Once, Run Everywhere)

A technique that allows eBPF programs to run on different kernel versions without recompilation. Uses BTF (BPF Type Format) to resolve kernel struct offsets at load time. Both Aya and libbpf support CO-RE.

### BPF Map Types Used

- **RingBuf** (`BPF_MAP_TYPE_RINGBUF`) — used by the sampler to export data to user space
- **HashMap** (`BPF_MAP_TYPE_HASH`) — used by the processor for fingerprint rules and actions

### Target Triple

`bpfel-unknown-none` — the Rust target for eBPF programs. `bpf` = BPF bytecode, `el` = little-endian, `unknown-none` = no OS, no std. This is a freestanding target: no `std`, no `alloc`.

### skb

**Socket Buffer** — the kernel's per-packet data structure. TC eBPF programs receive a `__sk_buff` context pointer, which gives access to the packet's headers and payload without directly dereferencing raw pointers (the verifier ensures safety).