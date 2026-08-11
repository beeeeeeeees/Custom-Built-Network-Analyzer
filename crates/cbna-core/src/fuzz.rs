//! Shared fuzz entry points.
//!
//! Each function here is the body of one libFuzzer target in `fuzz/`, and is
//! also driven by the deterministic harness in `tests/fuzz_smoke.rs`. They live
//! in the library rather than in the targets so the two cannot drift: the
//! nightly-only fuzzer and the stable test suite exercise identical code.
//!
//! Every one of these takes arbitrary bytes and must return normally. That is
//! the whole contract — no panics, no unbounded loops, no allocation driven by
//! an unchecked length.

use crate::packet::{decode, LinkType, PacketMeta};
use crate::Timestamp;
use std::hint::black_box;

/// A deterministic mutator, so the stable harnesses in both crates explore the
/// same corpus on every machine and a failure is reproducible from the seed
/// alone. xorshift64*, chosen for being short enough to audit.
pub struct Mutator(u64);

impl Mutator {
    pub fn new(seed: u64) -> Self {
        // Zero is a fixed point for xorshift; anything else is fine.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() >> 33) as usize % n
        }
    }

    /// Bit flips, byte splices, truncations, extensions, and extreme 16-bit
    /// field overwrites — the mutations that actually find length-handling
    /// bugs. Truncation is the most productive of them against any parser that
    /// reads a length and then trusts it.
    pub fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut buf = seed.to_vec();
        let rounds = 1 + self.below(8);
        for _ in 0..rounds {
            match self.below(6) {
                0 if !buf.is_empty() => {
                    let i = self.below(buf.len());
                    let bit = self.below(8);
                    buf[i] ^= 1 << bit;
                }
                1 if !buf.is_empty() => {
                    let i = self.below(buf.len());
                    buf[i] = self.byte();
                }
                2 if !buf.is_empty() => {
                    let n = self.below(buf.len());
                    buf.truncate(n);
                }
                3 => {
                    let n = self.below(64);
                    for _ in 0..n {
                        let b = self.byte();
                        buf.push(b);
                    }
                }
                4 if buf.len() >= 2 => {
                    let i = self.below(buf.len() - 1);
                    let v: u16 = match self.below(4) {
                        0 => 0,
                        1 => 1,
                        2 => u16::MAX,
                        _ => 0x7fff,
                    };
                    buf[i..i + 2].copy_from_slice(&v.to_be_bytes());
                }
                _ => {
                    let i = self.below(buf.len().max(1)).min(buf.len());
                    let b = self.byte();
                    buf.insert(i, b);
                }
            }
        }
        buf
    }

    /// Unstructured bytes, for the part of the run that should not start from
    /// anything valid.
    pub fn noise(&mut self, max_len: usize) -> Vec<u8> {
        let n = self.below(max_len);
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            let b = self.byte();
            buf.push(b);
        }
        buf
    }
}

const LINK_TYPES: [LinkType; 6] = [
    LinkType::Null,
    LinkType::Ethernet,
    LinkType::Raw,
    LinkType::LinuxSll,
    LinkType::LinuxSll2,
    LinkType::Loop,
];

/// Full frame decode, L2 through L7. The leading byte selects the link type so
/// a single corpus covers every one we claim to read.
pub fn decode_frame(data: &[u8]) {
    let (link, frame) = match data.split_first() {
        Some((sel, rest)) => (LINK_TYPES[*sel as usize % LINK_TYPES.len()], rest),
        None => (LinkType::Ethernet, data),
    };

    let meta = PacketMeta {
        index: 0,
        timestamp: Timestamp::new(0, 0),
        captured_len: frame.len() as u32,
        // Overstated for part of the corpus, so truncation handling is
        // exercised rather than only the whole-frame path.
        wire_len: frame.len() as u32 + (frame.len() as u32 % 64),
    };

    let pkt = decode(meta, frame, link);
    black_box(pkt.warnings.len());
}

/// DNS owns the nastiest structure in the tool: compression pointers can point
/// backwards, forwards, or at themselves. Reading the decoded names is part of
/// the target — a loop that survives parsing but explodes on read is the same
/// bug, just later.
pub fn dns_message(data: &[u8]) {
    if let Some(msg) = crate::proto::dns::parse(data) {
        for q in &msg.questions {
            black_box(q.name.len());
        }
        for r in &msg.answers {
            black_box(r.name.len());
        }
    }
    black_box(crate::proto::dns::parse_strict(data).is_ok());
}

/// TLS nests attacker-chosen lengths four deep: record, handshake, extension
/// list, individual extension. JA3 is computed from the parsed lists, so
/// touching it covers the formatting path too.
pub fn tls_hello(data: &[u8]) {
    if let Some(hello) = crate::proto::tls::parse(data) {
        black_box(hello.ja3.len());
        black_box(hello.ja3_md5.len());
        black_box(hello.version_name());
        black_box(hello.is_obsolete_version());
        for a in &hello.alpn {
            black_box(a.len());
        }
    }
}

/// The stream reassembler, driven by a script of segments the input controls.
///
/// This is the only stateful decoder in the tool, and the state is indexed by
/// sequence numbers an attacker picks: overlapping writes, segments that
/// arrive before the stream's own start, offsets that wrap the 32-bit sequence
/// space. The arithmetic that places those into a buffer is where an
/// out-of-bounds write would live, so it gets its own target rather than being
/// reached incidentally through the frame decoder.
pub fn tcp_stream(data: &[u8]) {
    use crate::reassembly::Reassembler;

    /// Records are 8 bytes of header then payload; stop well before a large
    /// input turns one iteration into a long run.
    const MAX_SEGMENTS: usize = 512;

    let mut r = Reassembler::new();
    let mut cur = data;
    let mut n = 0;

    while cur.len() >= 8 && n < MAX_SEGMENTS {
        let seq = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
        let flags = cur[4];
        // One byte of port selector, so a single input can open several streams
        // and reach the tracking cap.
        let port = 40000u16.wrapping_add(cur[5] as u16);
        let len = u16::from_be_bytes([cur[6], cur[7]]) as usize;
        cur = &cur[8..];

        let take = len.min(cur.len());
        let (payload, rest) = cur.split_at(take);
        cur = rest;

        let frame = tcp_frame(port, seq, flags, payload);
        let meta = PacketMeta {
            index: n as u64,
            timestamp: Timestamp::new(0, 0),
            captured_len: frame.len() as u32,
            wire_len: frame.len() as u32,
        };
        let pkt = decode(meta, &frame, LinkType::Ethernet);
        black_box(r.push(&pkt, &frame).is_some());
        n += 1;
    }

    let stats = r.stats();
    black_box(stats.recovered);
    black_box(stats.conflicting_overlaps);
}

/// Ethernet + IPv4 + TCP around `payload`.
fn tcp_frame(sport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&80u16.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0]);
    t.extend_from_slice(&[0x50, flags]);
    t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);

    let total = (20 + t.len()) as u16;
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    ip.extend_from_slice(&t);

    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    eth
}

/// Text protocols fail differently from binary ones: unbounded header counts,
/// enormous single values, header lines that never terminate.
pub fn http_message(data: &[u8]) {
    if let Some(msg) = crate::proto::http::parse(data) {
        black_box(msg.kind);
        if let Some(h) = &msg.host {
            black_box(h.len());
        }
        if let Some(u) = &msg.user_agent {
            black_box(u.len());
        }
        black_box(msg.has_authorization);
    }
}
