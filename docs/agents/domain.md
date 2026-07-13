# Domain Docs

## Layout

**Multi-context.** A `CONTEXT-MAP.md` at the repo root points to per-context `CONTEXT.md` files. Each context has its own `docs/adr/` directory for Architecture Decision Records.

### Context map

| Context | Path | Description |
|---|---|---|
| flow-common | `crates/flow-common/` | 共享类型、ShmRingBuf、配置、错误 |
| flow-ebpf | `crates/flow-ebpf/` | eBPF 程序加载封装 |
| flow-sampler | `crates/flow-sampler/` | 采样器加载器 |
| flow-analyzer | `crates/flow-analyzer/` | 分析核心、HTTP API |
| flow-analyzer-tui | `crates/flow-analyzer-tui/` | TUI 仪表盘 |
| flow-processor | `crates/flow-processor/` | 处理器加载器 |
| ebpf | `ebpf/` | eBPF 内核态程序 |

## Consumer rules

Skills that read domain docs (`improve-codebase-architecture`, `diagnosing-bugs`, `tdd`, and others) follow these rules:

1. **Read `CONTEXT-MAP.md` first** — it lists all contexts and their paths. Determine which context(s) are relevant to the current task.
2. **Read the per-context `CONTEXT.md`** — it contains the context's ubiquitous language, core concepts, and domain terminology. Treat it as authoritative for naming and domain boundaries within that context.
3. **Read `docs/adr/` for past decisions** — check both the root-level and per-context `docs/adr/` directories. Before proposing a new architectural direction, verify whether an existing ADR covers the relevant trade-off.
4. **Contribute back** — if you discover a new domain term or make an architectural decision, propose adding it to the appropriate `CONTEXT.md` or `docs/adr/`.

## Bootstrap

These files do not exist yet. Run the `domain-modeling` skill to populate `CONTEXT-MAP.md` and each per-context `CONTEXT.md` with an initial domain model, and write ADRs as you make architectural decisions.