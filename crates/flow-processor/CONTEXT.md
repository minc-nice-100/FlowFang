# flow-processor — Domain Glossary

The user-space loader for the processor eBPF program. Reads fingerprint rules from shared memory and writes them to BPF maps for the kernel to enforce.

## Glossary

### Processor

The user-space binary that loads `processor.bpf.o` and manages the rule pipeline. It:
1. Loads and attaches the processor eBPF program to the interface's TC ingress
2. Reads `DpiFingerprint` rules from the shared memory buffer (written by the analyzer)
3. Writes rules into the BPF maps (`FINGERPRINTS` and `ACTIONS`)
4. Handles graceful shutdown

### Rule Sync

The process of keeping the kernel's BPF maps in sync with the analyzer's rule set. When the analyzer creates, updates, or deletes a fingerprint, it writes the change to shared memory. The processor polls this shared memory region and applies the delta to the BPF maps — no restart required.

### nftables

The Linux kernel's packet filtering framework. The processor's eBPF program only does DPI matching and sets `mark` values. All complex policy (rate limiting, DNAT, logging, connection tracking) is handled by nftables rules that match on the mark. This follows the Unix philosophy — each component does one thing well.

**Example nftables rule:**
```
table inet flowfang {
    chain input {
        mark 0x00000001 drop     # Drop packets marked by processor
        mark 0x00000002 limit rate 100/second accept  # Rate-limit marked packets
    }
}
```

### Mark Action

The processor's primary action for complex policies. Instead of directly dropping or modifying packets, the processor sets a 32-bit nfmark (netfilter mark) on the packet's skb. nftables then reads this mark and applies the actual policy. This keeps the eBPF program simple and delegates policy to a battle-tested kernel subsystem.

### Pass / Drop Actions

Simple actions that the processor can apply directly without involving nftables:
- **Pass** — return `TC_ACT_OK`, the packet continues normally
- **Drop** — return `TC_ACT_SHOT`, the packet is silently discarded

### BPF Map Write Path

The processor writes to BPF maps via the pinned bpffs file descriptors. The flow is:
1. Analyzer writes `DpiFingerprint` to shared memory
2. Processor reads from shared memory, deserializes the rule
3. Processor writes to `FINGERPRINTS` map (pattern data) and `ACTIONS` map (action)
4. Kernel eBPF program reads both maps on every packet, matches, and executes

### Graceful Shutdown

On SIGTERM/SIGINT, the processor:
1. Stops reading from shared memory
2. Detaches the eBPF program from TC (packets pass through unmodified)
3. Unpins and cleans up bpffs entries
4. Closes shared memory handles