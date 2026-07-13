# ADR-0001: Aya for eBPF development

## Status

Accepted (2026-07-13)

## Context

We need to write eBPF programs (sampler, processor) that run in the Linux kernel. The two viable Rust options are:

- **Aya**: Pure Rust — eBPF programs are written in Rust, compiled to `bpfel-unknown-none`. The user-space loader is Rust.
- **libbpf-rs**: Rust bindings over libbpf. eBPF programs are written in C, compiled with clang. The user-space loader is Rust.

The project is developed with AI assistance (vibe coding). eBPF kernel programming requires strict pointer management — the kernel verifier rejects any program with invalid pointer arithmetic, out-of-bounds access, or uninitialized stack variables.

## Decision

We will use **Aya** for all eBPF development.

## Consequences

### Positive

- **Compile-time pointer safety**: Rust's borrow checker and type system catch pointer errors at compile time, before the eBPF verifier ever sees them. This is critical for AI-assisted development where C's manual pointer management is error-prone.
- **Single language**: No C toolchain required. eBPF programs and user-space loaders are both Rust, sharing types and idioms.
- **Static linking**: No libbpf, libelf, or zlib runtime dependencies. Simplifies musl static builds and container images.
- **Smaller supply chain**: No dependency on libbpf's build system or C toolchain.

### Negative

- **Younger ecosystem**: Aya is newer than libbpf. Fewer examples, smaller community, more bugs.
- **eBPF feature lag**: New kernel eBPF features may take longer to land in Aya vs libbpf.
- **Verifier still runs**: Rust safety doesn't guarantee the verifier accepts the program — bounded loops, map access patterns, and program size limits still apply.

## Alternatives considered

### libbpf-rs

- C eBPF + Rust loader. More mature, more examples, CO-RE support via libbpf.
- Rejected: requires C toolchain, manual pointer safety in eBPF code, higher risk of verifier rejection during AI-assisted development.

### cilium/ebpf (Go)

- Go ecosystem. Not applicable — the project is Rust.

## References

- [Aya](https://aya-rs.dev/)
- [aya-ebpf](https://docs.rs/aya-ebpf/latest/aya_ebpf/)
- PRD: FlowFang eBPF 流量审计系统