//! Traffic statistics aggregation.

use flow_common::types::FlowSample;
use std::collections::HashMap;

/// Aggregated traffic statistics.
#[derive(Debug, Default, Clone)]
pub struct TrafficStats {
    /// Total packets processed.
    pub total_packets: u64,
    /// Total bytes processed.
    pub total_bytes: u64,
    /// Number of active flows (five-tuple groups).
    pub active_flows: usize,
    /// Per-flow statistics.
    pub flows: HashMap<FlowKey, FlowStats>,
    /// Start time (monotonic).
    start: std::time::Instant,
}

/// A five-tuple flow identifier.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: [u16; 8],
    pub dst_ip: [u16; 8],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Get the source IP as a string.
    pub fn src_ip_str(&self) -> String {
        flow_common::types::ipv6_array_to_string(&self.src_ip)
    }

    /// Get the destination IP as a string.
    pub fn dst_ip_str(&self) -> String {
        flow_common::types::ipv6_array_to_string(&self.dst_ip)
    }
}

/// Per-flow statistics.
#[derive(Debug, Default, Clone)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

impl TrafficStats {
    /// Create a new stats collector.
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            ..Default::default()
        }
    }

    /// Record a sampled flow.
    pub fn record_sample(&mut self, sample: &FlowSample) {
        self.total_packets += 1;
        self.total_bytes += sample.pkt_size as u64;

        let key = FlowKey {
            src_ip: sample.src_ip,
            dst_ip: sample.dst_ip,
            src_port: sample.src_port,
            dst_port: sample.dst_port,
            protocol: sample.protocol,
        };

        let flow = self.flows.entry(key).or_default();
        flow.packets += 1;
        flow.bytes += sample.pkt_size as u64;
        flow.last_seen = sample.timestamp;
    }

    /// Get packets per second since start.
    pub fn packets_per_second(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_packets as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get bytes per second since start.
    pub fn bytes_per_second(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_bytes as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get the top-N flows by packet count.
    pub fn top_flows(&self, n: usize) -> Vec<(&FlowKey, &FlowStats)> {
        let mut flows: Vec<_> = self.flows.iter().collect();
        flows.sort_by(|a, b| b.1.packets.cmp(&a.1.packets));
        flows.truncate(n);
        flows
    }
}