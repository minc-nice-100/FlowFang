#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};

/// Sampled flow record — must match the user-space FlowSample exactly.
/// Layout: timestamp(8) + src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2)
///          + protocol(1) + _pad(3) + payload(64) + payload_len(2) + pkt_size(4)
#[repr(C)]
#[derive(Copy, Clone)]
struct FlowSample {
    timestamp: u64,
    /// IPv4-in-IPv6 mapped addresses, stored as [u16; 8] for fixed size.
    src_ip: [u16; 8],
    dst_ip: [u16; 8],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    /// Padding to match userspace alignment.
    pad: [u8; 3],
    payload: [u8; 64],
    payload_len: u16,
    pkt_size: u32,
}

#[map]
static SAMPLES: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256KB ring buffer

#[classifier]
pub fn sampler(ctx: TcContext) -> i32 {
    let Some(mut entry) = SAMPLES.reserve::<FlowSample>(0) else {
        return TC_ACT_OK;
    };

    let mut sample = FlowSample {
        timestamp: bpf_ktime_get_ns(),
        src_ip: [0u16; 8],
        dst_ip: [0u16; 8],
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        pad: [0u8; 3],
        payload: [0u8; 64],
        payload_len: 0,
        pkt_size: 0,
    };

    if let Ok(proto) = ctx.protocol() {
        sample.protocol = proto;
    }

    if let Ok(src) = ctx.src() {
        let ip = src.to_be();
        sample.src_ip[5] = 0xFFFF;
        sample.src_ip[6] = ((ip >> 16) & 0xFFFF) as u16;
        sample.src_ip[7] = (ip & 0xFFFF) as u16;
    }

    if let Ok(dst) = ctx.dst() {
        let ip = dst.to_be();
        sample.dst_ip[5] = 0xFFFF;
        sample.dst_ip[6] = ((ip >> 16) & 0xFFFF) as u16;
        sample.dst_ip[7] = (ip & 0xFFFF) as u16;
    }

    if let Ok(port) = ctx.src_port() {
        sample.src_port = port;
    }
    if let Ok(port) = ctx.dst_port() {
        sample.dst_port = port;
    }
    if let Ok(len) = ctx.len() {
        sample.pkt_size = len;
    }

    if let Ok(bytes) = ctx.load(0) {
        let payload_len = bytes.len().min(64);
        sample.payload[..payload_len].copy_from_slice(&bytes[..payload_len]);
        sample.payload_len = payload_len as u16;
    }

    entry.write(&sample);
    entry.submit(0);

    TC_ACT_OK
}

/// Get the current time in nanoseconds.
/// Uses the aya-ebpf helper; falls back to 0 on older kernels.
fn bpf_ktime_get_ns() -> u64 {
    // SAFETY: bpf_ktime_get_ns is always available on kernels >= 5.5
    unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}