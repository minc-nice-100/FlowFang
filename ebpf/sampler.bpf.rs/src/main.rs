#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};

/// Sampled flow record — must match the user-space FlowSample exactly.
#[repr(C)]
#[derive(Copy, Clone)]
struct FlowSample {
    timestamp: u64,
    /// IPv4-in-IPv6 mapped addresses
    src_ip: [u16; 8],
    dst_ip: [u16; 8],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad: [u8; 3],
    payload: [u8; 64],
    payload_len: u16,
    pkt_size: u32,
}

#[map]
static SAMPLES: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256KB ring buffer

#[classifier]
pub fn sampler(ctx: TcContext) -> i32 {
    // Try to reserve space in the ring buffer
    let Some(mut entry) = SAMPLES.reserve::<FlowSample>(0) else {
        // Ring buffer full, drop sample
        return TC_ACT_OK;
    };

    // Build flow sample from packet context
    let mut sample = FlowSample {
        timestamp: 0, // TODO: bpf_ktime_get_ns()
        src_ip: [0u16; 8],
        dst_ip: [0u16; 8],
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        _pad: [0u8; 3],
        payload: [0u8; 64],
        payload_len: 0,
        pkt_size: 0,
    };

    // Extract L3/L4 headers and payload
    // SAFETY: TcContext provides safe accessors; we check bounds.
    if let Ok(proto) = ctx.protocol() {
        sample.protocol = proto;
    }

    // Read source IP
    if let Ok(src) = ctx.src() {
        // Convert u32 IPv4 to IPv6-mapped representation
        let ip = src.to_be();
        sample.src_ip[5] = 0xFFFF;
        sample.src_ip[6] = ((ip >> 16) & 0xFFFF) as u16;
        sample.src_ip[7] = (ip & 0xFFFF) as u16;
    }

    // Read destination IP
    if let Ok(dst) = ctx.dst() {
        let ip = dst.to_be();
        sample.dst_ip[5] = 0xFFFF;
        sample.dst_ip[6] = ((ip >> 16) & 0xFFFF) as u16;
        sample.dst_ip[7] = (ip & 0xFFFF) as u16;
    }

    // Read source port
    if let Ok(port) = ctx.src_port() {
        sample.src_port = port;
    }

    // Read destination port
    if let Ok(port) = ctx.dst_port() {
        sample.dst_port = port;
    }

    // Read packet size
    if let Ok(len) = ctx.len() {
        sample.pkt_size = len;
    }

    // Read payload (first 64 bytes)
    // SAFETY: ctx.load reads at most the packet length
    if let Ok(bytes) = ctx.load(0) {
        let payload_len = bytes.len().min(64);
        sample.payload[..payload_len].copy_from_slice(&bytes[..payload_len]);
        sample.payload_len = payload_len as u16;
    }

    // Submit the sample to the ring buffer
    entry.write(&sample);
    entry.submit(0);

    TC_ACT_OK
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}