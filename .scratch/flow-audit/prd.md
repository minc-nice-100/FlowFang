# PRD: Flow Audit — eBPF 流量审计系统

## Problem Statement

运维和安全团队需要对服务器流量进行实时审计，识别恶意流量、生成流量指纹，并对匹配指纹的流量执行策略动作。现有方案要么依赖内核模块（不稳定、安全风险），要么在用户态抓包（性能差、丢包严重）。需要一套高性能、内存安全、组件隔离的流量审计系统。

## Solution

基于 eBPF 的流量审计系统，由三个独立进程组成：

1. **eBPF 采样器** — 在内核态采样流量，通过 ringbuf 零拷贝导出到用户态
2. **用户态分析程序** — 处理采样数据，提供审计仪表盘，生成 DPI 流量指纹
3. **eBPF 处理器** — 根据分析程序下发的指纹和动作，在内核态匹配并处理流量

全 Rust 实现（Aya 框架），musl 静态编译，跨发行版分发。进程间通过共享内存通信，任何一个组件崩溃不影响其他组件。复杂流量策略卸载给 nftables。

## User Stories

### 部署与运维

1. 作为运维人员，我想要一个安装脚本一键部署所有组件，以便快速上线
2. 作为运维人员，我想要一个卸载脚本完全清理所有组件，以便安全移除
3. 作为运维人员，我想要容器镜像部署方式，以便在 Kubernetes 环境中运行
4. 作为运维人员，我想要系统在 Alpine Linux 上正常运行，以便在最小化镜像中部署
5. 作为运维人员，我想要单个组件崩溃时其他组件不受影响，以便保证系统可用性

### 流量采样

6. 作为安全工程师，我想要采样器在内核态捕获所有 ingress 流量，以便不遗漏任何数据包
7. 作为安全工程师，我想要采样器提取每个包的源/目的 IP、端口、协议和前 N 字节 payload，以便后续 DPI 分析
8. 作为运维人员，我想要配置采样率（1/N），以便在高流量场景下控制性能开销
9. 作为运维人员，我想要采样器跳过 lo 接口和内部管理流量，以便减少噪音数据

### 流量分析

10. 作为安全工程师，我想要实时查看流量统计（速率、总量、Top N 连接），以便快速发现异常
11. 作为安全工程师，我想要基于 payload 模式生成 DPI 指纹，以便识别特定应用/协议/恶意软件流量
12. 作为安全工程师，我想要支持多种指纹匹配模式（精确匹配、字节序列、正则、TLS SNI、JA3 哈希），以便覆盖不同识别场景
13. 作为安全工程师，我想要手动创建和删除指纹规则，以便灵活应对新威胁
14. 作为安全工程师，我想要将指纹规则下发到内核态处理器，以便实时拦截匹配流量

### 流量处理

15. 作为安全工程师，我想要处理器在内核态匹配 DPI 指纹后执行动作（pass/drop/mark），以便快速响应威胁
16. 作为安全工程师，我想要处理器打 mark 后将复杂策略交给 nftables 处理，以便复用现有内核能力
17. 作为运维人员，我想要处理器规则更新时无需重启进程，以便不影响在线流量

### 仪表盘

18. 作为安全工程师，我想要一个终端 TUI 仪表盘显示实时流量和告警，以便在 SSH 环境中快速查看
19. 作为安全工程师，我想要仪表盘能查看当前活跃的指纹规则和命中统计，以便了解防护状态
20. 作为架构师，我想要分析程序同时支持 Unix socket 和 TCP 端口监听（类似 Docker daemon），以便在本地开发和远程部署场景间灵活切换

### 配置

21. 作为运维人员，我想要支持 TOML 和 YAML 两种配置格式，以便适配不同的运维习惯
22. 作为运维人员，我想要通过命令行参数、环境变量或配置文件指定配置，以便灵活部署

## Implementation Decisions

### 架构

- **三个独立进程**：sampler、analyzer、processor。每个独立加载、独立崩溃、独立重启
- **进程间 IPC 使用共享内存**：基于 memmap2 自建 SPSC ring buffer，零拷贝，最小依赖，供应链攻击面可控
- **analyzer 暴露 HTTP API，支持 Unix socket 和 TCP 端口**：类似 Docker daemon（`-H unix:///var/run/flow-audit.sock` / `-H tcp://0.0.0.0:9090`），默认 Unix socket，可通过配置切换到 TCP 端口。TUI 作为独立二进制通过 HTTP 通信，GUI 未来可替换

### eBPF 框架

- **Aya**：纯 Rust eBPF 框架。编译器在编译期拦截指针错误，避免内核 verifier 拒绝。无需 C 工具链，无需 libbpf 依赖
- 挂载点：TC ingress（通用性优于 XDP，兼容性更好）

### 数据模型

```rust
// 采样器导出的原始流量记录
pub struct FlowSample {
    pub timestamp: u64,       // ns
    pub src_ip: Ipv6Addr,     // IPv4 映射到 IPv6
    pub dst_ip: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,         // TCP/UDP/ICMP
    pub payload: [u8; 64],    // 前 64 字节
    pub payload_len: u16,
    pub pkt_size: u32,
}

// DPI 指纹匹配模式
pub enum DpiPattern {
    ExactMatch { offset: u16, bytes: Vec<u8> },
    ByteSeq { sequence: Vec<u8> },
    Regex { expression: String },
    TlsSni { sni: String },
    TlsJa3 { ja3_hash: String },
}

// 处理器动作
pub enum ProcessorAction {
    Pass,
    Drop,
    Mark { mark: u32 },
}
```

### 模块划分

- **flow-common**：共享类型、ShmRingBuf 封装、配置加载、错误类型
- **flow-ebpf**：eBPF 程序编译与加载封装（SamplerBpf、ProcessorBpf）
- **flow-sampler**：sampler 加载器，ringbuf 消费者，写入共享内存
- **flow-analyzer**：流量统计、DPI 指纹生成、HTTP API（axum，支持 Unix socket 和 TCP 端口，类似 Docker daemon 行为）
- **flow-analyzer-tui**：Ratatui 终端仪表盘，通过 HTTP API 获取数据
- **flow-processor**：processor 加载器，从共享内存读取规则，写入 BPF maps

### HTTP API 端点

默认监听 Unix socket：`/var/run/flow-audit.sock`，可通过配置切换到 TCP 端口（如 `0.0.0.0:9090`），行为与 Docker daemon 一致。

```
GET  /api/status              # 系统状态
GET  /api/stats               # 流量统计
GET  /api/fingerprints        # 当前指纹列表
POST /api/fingerprints        # 手动添加指纹
DELETE /api/fingerprints/{id} # 删除指纹
GET  /api/events              # SSE 实时事件流
```

### 配置

- 格式：TOML + YAML 双支持，按文件扩展名自动选择解析器
- 优先级：CLI 参数 > `FLOW_AUDIT_CONFIG` 环境变量 > `/etc/flow-audit/config.{toml,yaml,yml}` > `./config/default.{toml,yaml}`
- 每个 binary 有独立配置结构体

### 分发

- musl 静态编译二进制（x86_64 + aarch64）
- install.sh：硬链接到 `/usr/local/bin/`（避免 Alpine/busybox symlink 兼容问题）
- uninstall.sh：停止服务、删除二进制、清理配置和共享内存
- Dockerfile：multi-stage（rust:alpine builder → alpine:latest runtime）

### 供应链安全

- 最小依赖原则：flow-common 仅依赖 memmap2 + serde + uuid
- 自建 SPSC ring buffer 而非引入第三方 crate
- 所有 unsafe 块用 `// SAFETY:` 注释证明正确性

## Testing Decisions

### 测试原则

- 只测试外部行为，不测试内部实现细节
- 每个 crate 独立可测
- 共享内存 ring buffer 在单进程内测试正确性，在双进程集成测试中验证 IPC

### 测试接缝（Seams）

| 接缝 | 级别 | 测试方式 |
|---|---|---|
| `ShmRingBuf<T>` 公共 API | 单元 | 单进程内 create/open/push/pop 循环 |
| `ShmRingBuf` 跨进程 | 集成 | 两个进程通过相同 shm 名称通信 |
| HTTP API | 集成 | reqwest 分别连接 Unix socket 和 TCP 端口，验证 JSON 响应一致 |
| BPF maps (bpffs) | 集成 | VM 中加载 eBPF 程序，验证 map 读写 |
| 端到端 | E2E | tcpreplay 回放 pcap，验证采样→分析→指纹→处理的完整链路 |

### 静态分析

- `cargo clippy` 全 workspace
- `cargo miri` 对 flow-common 中的 unsafe 代码
- eBPF verifier 在目标内核上加载确认

## Out of Scope

- GUI 仪表盘（保留 HTTP API 接口，社区可自行实现）
- deb/rpm 原生包（当知名度上去后由社区贡献）
- XDP 挂载点（先实现 TC，Docker 兼容性更好）
- 分布式部署（单机场景）
- 流量回放/重放功能
- 加密流量解密（MITM 代理）

## Further Notes

- 项目代号：FlowFang
- 仓库地址：https://github.com/minc-nice-100/FlowFang
- 语言：Rust（stable channel）
- 许可证：待定
- 第一个里程碑：sampler + shared memory + analyzer 的端到端数据流可运行