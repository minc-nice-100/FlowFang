#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};

const MAX_FINGERPRINTS: u32 = 256;

/// DPI pattern stored in BPF map (fixed-size representation).
#[repr(C)]
#[derive(Copy, Clone)]
struct DpiPatternBytes {
    pattern_type: u8,  // 0=Exact, 1=ByteSeq, 2=Regex, 3=TlsSni, 4=TlsJa3
    offset: u16,
    length: u16,
    data: [u8; 64],
}

/// Fingerprint lookup table: ID → Pattern.
#[map]
static FINGERPRINTS: HashMap<u32, DpiPatternBytes> = HashMap::with_max_entries(MAX_FINGERPRINTS);

/// Action lookup table: ID → Action (0=Pass, 1=Drop, 2+=Mark value).
#[map]
static ACTIONS: HashMap<u32, u32> = HashMap::with_max_entries(MAX_FINGERPRINTS);

#[classifier]
pub fn processor(ctx: TcContext) -> i32 {
    let mut result = TC_ACT_OK;

    let payload_bytes = match ctx.load(0) {
        Ok(bytes) => bytes,
        Err(_) => return TC_ACT_OK,
    };

    for id in 0..MAX_FINGERPRINTS {
        let Some(pattern) = FINGERPRINTS.get(&id) else {
            continue;
        };

        let matched = match (*pattern).pattern_type {
            0 => match_exact(&payload_bytes, (*pattern).offset, &(*pattern).data, (*pattern).length),
            1 => match_byte_seq(&payload_bytes, &(*pattern).data, (*pattern).length),
            _ => false,
        };

        if matched {
            let Some(action) = ACTIONS.get(&id) else {
                continue;
            };

            match *action {
                0 => result = TC_ACT_OK,             // Pass
                1 => result = TC_ACT_SHOT,           // Drop
                mark => {
                    // Set skb->mark for nftables to handle
                    ctx.set_mark(mark);
                    result = TC_ACT_OK;
                }
            }
            break;
        }
    }

    result
}

fn match_exact(payload: &[u8], offset: u16, pattern: &[u8], len: u16) -> bool {
    let offset = offset as usize;
    let len = len as usize;
    if offset + len > payload.len() || len > pattern.len() {
        return false;
    }
    let pat = &pattern[..len];
    let data = &payload[offset..offset + len];
    pat == data
}

fn match_byte_seq(payload: &[u8], pattern: &[u8], len: u16) -> bool {
    let len = len as usize;
    if len == 0 || len > payload.len() || len > pattern.len() {
        return false;
    }
    let pat = &pattern[..len];
    payload.windows(len).any(|window| window == pat)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}