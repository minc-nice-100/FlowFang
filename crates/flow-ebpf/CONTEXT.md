# flow-ebpf — Domain Glossary

eBPF program compilation and loading abstractions, wrapping the Aya framework.

## Glossary

### SamplerBpf

A struct that encapsulates loading and attaching the sampler eBPF program. Embedds the compiled `sampler.bpf.o` via `aya::include_bytes_aligned!`. Provides:
- `load()` — load the eBPF program into the kernel
- `attach(iface: &str)` — attach to the TC ingress hook on the given interface
- `detach()` — remove the TC hook and unload the program
- `ringbuf()` — return a handle to the ringbuf for consuming samples

### ProcessorBpf

A struct that encapsulates loading and attaching the processor eBPF program. Embedds the compiled `processor.bpf.o`. Provides:
- `load()` — load the eBPF program into the kernel
- `attach(iface: &str)` — attach to the TC ingress hook
- `detach()` — remove and unload
- `fingerprints_map()` — return a handle to the BPF map for writing fingerprint rules
- `actions_map()` — return a handle to the BPF map for writing actions

### BPF Object

A compiled eBPF program in ELF format (`.o` file). Contains the eBPF bytecode, map definitions, and license metadata. Produced by compiling the Rust eBPF source with `bpfel-unknown-none` target.

### Attach / Detach

**Attach** means hooking a loaded eBPF program to a kernel event source — in our case, the TC ingress hook on a network interface. **Detach** means removing the hook; the program is unloaded when no references remain.

### BPF Map

A key-value data structure shared between eBPF programs (kernel space) and user-space loaders. The processor uses two maps:
- `FINGERPRINTS: HashMap<u32, DpiPattern>` — fingerprint rules
- `ACTIONS: HashMap<u32, ProcessorAction>` — corresponding actions

Both maps are keyed by the same fingerprint ID. Maps are pinned to bpffs (`/sys/fs/bpf/flowfang/`) so the analyzer can write to them even though the processor is the one that loaded them.

### bpffs

The **BPF File System**, typically mounted at `/sys/fs/bpf/`. Pinning a BPF map to bpffs creates a file descriptor that other processes can open. This is how the analyzer writes fingerprint rules to maps that the processor's eBPF program reads — the two processes never need to share the same loader instance.

### Aya

The Rust eBPF framework. Two crates:
- `aya` — user-space library for loading and managing eBPF programs
- `aya-ebpf` — kernel-side library for writing eBPF programs in Rust

**Why Aya:** Rust's compiler catches pointer errors at compile time, avoiding the kernel verifier's rejection. No C toolchain, no libbpf dependency. See [[ADR-0001]].

### TC Ingress

The **Traffic Control** ingress hook — the point in the Linux kernel where packets arrive on a network interface before any routing decision. Both sampler and processor attach here. Chosen over XDP for broader compatibility (Docker, older kernels). See [[ADR-0002]].