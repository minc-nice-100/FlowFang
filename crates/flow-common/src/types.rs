//! Shared data types for FlowFang.
//!
//! All types crossing the eBPF↔user or shared-memory boundaries are
//! `#[repr(C)]`, `Copy`, `Clone`, and implement `Pod` for safe placement
//! in shared memory.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::shm::Pod;

/// A sampled network packet record.
///
/// This is the fixed-size record that flows from the sampler eBPF program
/// through the kernel ringbuf and into shared memory. The layout must match
/// the eBPF-side `FlowSample` exactly.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct FlowSample {
    /// Arrival time in nanoseconds.
    pub timestamp: u64,
    /// Source IP address. IPv4 addresses are stored as IPv6-mapped
    /// (`::ffff:a.b.c.d`), stored as `[u16; 8]` for fixed-size layout.
    pub src_ip: [u16; 8],
    /// Destination IP address (IPv6-mapped for IPv4).
    pub dst_ip: [u16; 8],
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP).
    pub protocol: u8,
    /// Padding for C-struct alignment (matches eBPF layout).
    #[allow(dead_code)]
    pub pad: [u8; 3],
    /// First 64 bytes of payload.
    #[serde(with = "serde_big_array::BigArray")]
    pub payload: [u8; 64],
    /// Actual payload length (may be > 64).
    pub payload_len: u16,
    /// Total packet size in bytes.
    pub pkt_size: u32,
}

// SAFETY: FlowSample is #[repr(C)], Copy, Clone, and contains no pointers.
unsafe impl Pod for FlowSample {}

impl FlowSample {
    /// Get the source IP as a string.
    pub fn src_ip_str(&self) -> String {
        ipv6_array_to_string(&self.src_ip)
    }

    /// Get the destination IP as a string.
    pub fn dst_ip_str(&self) -> String {
        ipv6_array_to_string(&self.dst_ip)
    }
}

/// A DPI fingerprint rule that identifies specific traffic patterns.
///
/// This is the high-level type used by the analyzer and HTTP API.
/// For shared memory transfer to the processor, it is serialized to
/// `RuleUpdate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiFingerprint {
    pub id: Uuid,
    pub name: String,
    pub pattern: DpiPattern,
    pub action: ProcessorAction,
}

/// Fixed-size rule update for shared memory transfer to the processor.
///
/// All fields are fixed-size so the type can be `Pod` and live in shared memory.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RuleUpdate {
    /// UUID as raw bytes.
    pub id: [u8; 16],
    /// Rule name, truncated to 64 bytes.
    pub name: [u8; 64],
    /// Name length.
    pub name_len: u8,
    /// Pattern type: 0=Exact, 1=ByteSeq, 2=Regex, 3=TlsSni, 4=TlsJa3, 0xFF=delete
    pub pattern_type: u8,
    /// Offset for ExactMatch.
    pub offset: u16,
    /// Length of pattern data.
    pub pattern_len: u16,
    /// Pattern data (truncated to 64 bytes).
    pub pattern_data: [u8; 64],
    /// Action: 0=Pass, 1=Drop, 2+=Mark value. 0xFFFFFFFF = delete.
    pub action: u32,
}

// SAFETY: RuleUpdate is #[repr(C)], Copy, Clone, and contains no pointers.
unsafe impl Pod for RuleUpdate {}

impl RuleUpdate {
    /// Sentinel action value meaning "delete this rule".
    pub const DELETE: u32 = 0xFFFF_FFFF;

    /// Create a RuleUpdate that deletes the rule with the given UUID.
    pub fn delete(id: Uuid) -> Self {
        Self {
            id: *id.as_bytes(),
            name: [0u8; 64],
            name_len: 0,
            pattern_type: 0xFF,
            offset: 0,
            pattern_len: 0,
            pattern_data: [0u8; 64],
            action: Self::DELETE,
        }
    }
}

impl From<&DpiFingerprint> for RuleUpdate {
    fn from(fp: &DpiFingerprint) -> Self {
        let (pattern_type, offset, pattern_data, pattern_len) = match &fp.pattern {
            DpiPattern::ExactMatch { offset, bytes } => {
                let mut data = [0u8; 64];
                let len = bytes.len().min(64);
                data[..len].copy_from_slice(&bytes[..len]);
                (0u8, *offset, data, len as u16)
            }
            DpiPattern::ByteSeq { sequence } => {
                let mut data = [0u8; 64];
                let len = sequence.len().min(64);
                data[..len].copy_from_slice(&sequence[..len]);
                (1u8, 0u16, data, len as u16)
            }
            DpiPattern::Regex { expression } => {
                let mut data = [0u8; 64];
                let bytes = expression.as_bytes();
                let len = bytes.len().min(64);
                data[..len].copy_from_slice(&bytes[..len]);
                (2u8, 0u16, data, len as u16)
            }
            DpiPattern::TlsSni { sni } => {
                let mut data = [0u8; 64];
                let bytes = sni.as_bytes();
                let len = bytes.len().min(64);
                data[..len].copy_from_slice(&bytes[..len]);
                (3u8, 0u16, data, len as u16)
            }
            DpiPattern::TlsJa3 { ja3_hash } => {
                let mut data = [0u8; 64];
                let bytes = ja3_hash.as_bytes();
                let len = bytes.len().min(64);
                data[..len].copy_from_slice(&bytes[..len]);
                (4u8, 0u16, data, len as u16)
            }
        };

        let mut name = [0u8; 64];
        let name_bytes = fp.name.as_bytes();
        let name_len = name_bytes.len().min(64);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let action = fp.action.to_code();

        Self {
            id: *fp.id.as_bytes(),
            name,
            name_len: name_len as u8,
            pattern_type,
            offset,
            pattern_len,
            pattern_data,
            action,
        }
    }
}

/// DPI matching criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DpiPattern {
    /// Match bytes at a specific offset in the payload.
    ExactMatch { offset: u16, bytes: Vec<u8> },
    /// Match a byte sequence anywhere in the payload.
    ByteSeq { sequence: Vec<u8> },
    /// Match payload against a regular expression.
    Regex { expression: String },
    /// Match a TLS Server Name Indication value.
    TlsSni { sni: String },
    /// Match a JA3 hash (TLS client fingerprint).
    TlsJa3 { ja3_hash: String },
}

/// Action to take when a DPI fingerprint matches.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProcessorAction {
    /// Allow the packet through.
    Pass,
    /// Silently discard the packet.
    Drop,
    /// Set an nfmark on the packet for nftables.
    Mark { mark: u32 },
}

impl ProcessorAction {
    /// Convert to the u32 code used in BPF maps.
    /// 0=Pass, 1=Drop, 2+=Mark value.
    pub fn to_code(self) -> u32 {
        match self {
            ProcessorAction::Pass => 0,
            ProcessorAction::Drop => 1,
            ProcessorAction::Mark { mark } => mark,
        }
    }

    /// Convert from a u32 code from BPF maps.
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => ProcessorAction::Pass,
            1 => ProcessorAction::Drop,
            mark => ProcessorAction::Mark { mark },
        }
    }
}

/// Convert an IPv6 address stored as `[u16; 8]` to a string.
pub fn ipv6_array_to_string(addr: &[u16; 8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(39);
    for (i, segment) in addr.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        write!(s, "{:x}", segment).unwrap();
    }
    s
}