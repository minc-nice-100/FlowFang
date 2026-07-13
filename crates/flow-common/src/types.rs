//! Shared data types for FlowFang.

use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use uuid::Uuid;

/// A sampled network packet record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct FlowSample {
    /// Arrival time in nanoseconds.
    pub timestamp: u64,
    /// Source IP address (IPv4 mapped to IPv6).
    pub src_ip: Ipv6Addr,
    /// Destination IP address (IPv4 mapped to IPv6).
    pub dst_ip: Ipv6Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP).
    pub protocol: u8,
    /// First 64 bytes of payload.
    pub payload: [u8; 64],
    /// Actual payload length (may be > 64).
    pub payload_len: u16,
    /// Total packet size in bytes.
    pub pkt_size: u32,
}

/// A DPI fingerprint rule that identifies specific traffic patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiFingerprint {
    pub id: Uuid,
    pub name: String,
    pub pattern: DpiPattern,
    pub action: ProcessorAction,
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