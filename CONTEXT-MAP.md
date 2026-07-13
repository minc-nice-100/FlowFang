# FlowFang Context Map

Multi-context project. Each context below has its own `CONTEXT.md` and `docs/adr/`.

| Context | Path | Description |
|---|---|---|
| flow-common | `crates/flow-common/` | 共享类型、共享内存 Ring Buffer、配置加载、错误类型 |
| flow-ebpf | `crates/flow-ebpf/` | eBPF 程序编译与加载封装 |
| flow-sampler | `crates/flow-sampler/` | 采样器用户态加载器 |
| flow-analyzer | `crates/flow-analyzer/` | 分析核心、DPI 指纹生成、HTTP API |
| flow-analyzer-tui | `crates/flow-analyzer-tui/` | TUI 终端仪表盘 |
| flow-processor | `crates/flow-processor/` | 处理器用户态加载器 |
| ebpf | `ebpf/` | eBPF 内核态程序 |

## How to use

1. Start here — determine which context(s) are relevant to the current task
2. Read the per-context `CONTEXT.md` for the ubiquitous language of that context
3. Read `docs/adr/` (root or per-context) for architectural decisions