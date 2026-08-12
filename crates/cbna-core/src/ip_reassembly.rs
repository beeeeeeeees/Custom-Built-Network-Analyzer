//! IP fragment reassembly (IPv4 and IPv6).
//!
//! A datagram larger than a path MTU is split at layer 3 into fragments: the
//! first carries the transport header and the leading bytes, later ones carry
//! only more payload placed at a byte offset. Decoding a single fragment
//! therefore recovers, at best, a truncated transport payload from the first
//! fragment and nothing at all from the rest — so a fragmented DNS response, an
//! ICMP tunnel, or a datagram a sender fragmented deliberately to walk past an
//! inspector all lose their transport and application detail.
//!
//! This module rebuilds the datagram from its fragments, then re-runs the
//! ordinary transport and application decoders over the result, exactly as
//! [`crate::reassembly`] does for TCP streams. It is the sibling stateful
//! decoder: same first-writer-wins overlap handling, same eager release, same
//! insistence that growth stay bounded.
//!
//! # Overlap is the interesting case
//!
//! Two fragments that claim the same offset with *different* bytes are the
//! fragment-based analogue of the TCP overlap trick (teardrop and its
//! descendants): an inspector that reassembles one way and the destination host
//! another see different datagrams. Overlaps are resolved first-writer-wins and
//! a disagreement is counted, surfacing as `ip-fragment-overlap`. It is not
//! "fixed" by letting the later fragment win — which side wins is the whole
//! substance of the evasion.
//!
//! # Bounds
//!
//! Unbounded growth is a bug (CLAUDE.md), and a reassembler is where that is
//! easiest to break. Three caps hold, plus eager release:
//!
//! - [`MAX_DATAGRAM_BYTES`] per datagram — a reassembled datagram cannot exceed
//!   the 16-bit IP length field, and offsets beyond it are dropped.
//! - [`MAX_TRACKED_DATAGRAMS`] in flight, so a flood of distinct fragment ids
//!   (or lost final fragments that never complete) cannot allocate without
//!   limit. New datagrams past the cap are counted and dropped, never queued.
//! - [`MAX_RANGES`] holes per datagram, so a sender that transmits every other
//!   fragment out of order cannot grow the bookkeeping without limit.
//! - The buffer is freed the moment the datagram completes or hits any cap.
//!
//! Worst case is `MAX_TRACKED_DATAGRAMS * MAX_DATAGRAM_BYTES`, and only for a
//! capture engineered to hit it.

use crate::net::{self, proto_num};
use crate::packet::{app_from_payload, AppLayer, DecodedPacket, NetworkLayer, TransportLayer};
use crate::transport;
use std::collections::HashMap;
use std::net::IpAddr;

/// Largest datagram we will reassemble: the IPv4 total-length field is 16 bits,
/// so no legitimate datagram exceeds this, and it caps one datagram's buffer.
pub const MAX_DATAGRAM_BYTES: usize = 65_535;

/// Datagrams tracked at once, across all endpoints.
pub const MAX_TRACKED_DATAGRAMS: usize = 1024;

/// Disjoint filled ranges per datagram before it is abandoned.
const MAX_RANGES: usize = 16;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IpReassemblyStats {
    /// Datagrams reassembled from more than one fragment and re-decoded. If this
    /// is zero on a capture full of fragments, the module is not earning its
    /// keep.
    pub reassembled: u64,
    /// Datagrams never tracked because the table was already full.
    pub dropped_datagrams: u64,
    /// Fragments that rewrote already-buffered bytes with *different* content —
    /// the teardrop / fragment-overlap evasion shape.
    pub conflicting_overlaps: u64,
}

/// Everything needed to route a fragment to its datagram: fragments of one
/// original share the source, destination, protocol, and identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
}

/// The per-fragment view the reassembler needs, pulled out of a decoded packet.
struct FragInfo {
    key: FragKey,
    offset: usize,
    more_fragments: bool,
}

/// Read fragment metadata from a decoded packet, or `None` if it is not a piece
/// of a fragmented IP datagram.
fn frag_info(pkt: &DecodedPacket) -> Option<FragInfo> {
    let (src, dst, protocol) = (pkt.src_ip()?, pkt.dst_ip()?, pkt.ip_protocol()?);
    let (id, offset, more_fragments) = match &pkt.network {
        NetworkLayer::Ipv4(h) if h.fragmented => (
            h.identification as u32,
            h.fragment_offset as usize,
            h.more_fragments,
        ),
        NetworkLayer::Ipv6(h) if h.fragmented => (
            h.identification,
            h.fragment_offset as usize,
            h.more_fragments,
        ),
        _ => return None,
    };
    Some(FragInfo {
        key: FragKey {
            src,
            dst,
            protocol,
            id,
        },
        offset,
        more_fragments,
    })
}

#[derive(Debug)]
struct Datagram {
    buf: Vec<u8>,
    /// Sorted, merged, non-overlapping `[start, end)` ranges of `buf` that hold
    /// real data.
    filled: Vec<(usize, usize)>,
    /// Total datagram length, known once the last fragment (MF=0) arrives.
    total_len: Option<usize>,
    /// Fragments contributing so far.
    fragments: u32,
    done: bool,
}

impl Datagram {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            filled: Vec::new(),
            total_len: None,
            fragments: 0,
            done: false,
        }
    }

    /// Release the buffer but keep the entry, so late or duplicate fragments on
    /// a finished datagram are ignored cheaply instead of starting it over.
    fn finish(&mut self) {
        self.done = true;
        self.buf = Vec::new();
        self.buf.shrink_to_fit();
        self.filled = Vec::new();
    }

    /// Length of the contiguous run starting at offset 0.
    fn contiguous(&self) -> usize {
        match self.filled.first() {
            Some(&(0, end)) => end,
            _ => 0,
        }
    }

    /// Write `payload` at `offset`, first-writer-wins. Returns true if any
    /// already-present byte disagreed with what was written over it.
    fn write(&mut self, offset: usize, payload: &[u8]) -> bool {
        let end = (offset + payload.len()).min(MAX_DATAGRAM_BYTES);
        if end <= offset {
            return false;
        }
        let payload = &payload[..end - offset];

        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }

        // Compare against bytes already held before overwriting anything, so a
        // disagreeing overlap is visible rather than silently resolved.
        let mut conflict = false;
        for (i, b) in payload.iter().enumerate() {
            let at = offset + i;
            if self.is_filled(at) {
                if self.buf[at] != *b {
                    conflict = true;
                }
            } else {
                self.buf[at] = *b;
            }
        }

        self.add_range(offset, end);
        conflict
    }

    fn is_filled(&self, at: usize) -> bool {
        self.filled.iter().any(|&(s, e)| at >= s && at < e)
    }

    /// Insert `[start, end)` and merge with any ranges it touches, keeping the
    /// list sorted and disjoint.
    fn add_range(&mut self, start: usize, end: usize) {
        let mut merged = (start, end);
        let mut out: Vec<(usize, usize)> = Vec::with_capacity(self.filled.len() + 1);
        for &(s, e) in &self.filled {
            if e < merged.0 || s > merged.1 {
                out.push((s, e));
            } else {
                merged.0 = merged.0.min(s);
                merged.1 = merged.1.max(e);
            }
        }
        out.push(merged);
        out.sort_unstable();
        self.filled = out;
    }
}

/// Rebuilds fragmented IP datagrams so the transport and application decoders
/// see the whole thing.
#[derive(Debug, Default)]
pub struct IpReassembler {
    datagrams: HashMap<FragKey, Datagram>,
    stats: IpReassemblyStats,
}

impl IpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> IpReassemblyStats {
        self.stats
    }

    pub fn tracked(&self) -> usize {
        self.datagrams.len()
    }

    /// Feed one decoded packet in. Returns a synthetic [`DecodedPacket`] for the
    /// fully reassembled datagram — transport and application layers decoded
    /// afresh — only when this fragment completed it. Everything else, including
    /// every non-fragment, returns `None`.
    ///
    /// A completed datagram always drew on more than one fragment (a single
    /// unfragmented datagram is never marked fragmented and never reaches here),
    /// so the recovered message is one single-fragment decoding could not have
    /// produced; the caller indexes it without double-counting.
    pub fn push(&mut self, pkt: &DecodedPacket, frame: &[u8]) -> Option<DecodedPacket> {
        let info = frag_info(pkt)?;
        let bytes = pkt.fragment_bytes(frame);

        // A fragment starting past the largest datagram we will hold is noise or
        // an attack; drop it without allocating.
        if info.offset >= MAX_DATAGRAM_BYTES {
            return None;
        }

        let dg = match self.datagrams.get_mut(&info.key) {
            Some(dg) => dg,
            None => {
                if self.datagrams.len() >= MAX_TRACKED_DATAGRAMS {
                    self.stats.dropped_datagrams += 1;
                    return None;
                }
                self.datagrams.entry(info.key).or_insert_with(Datagram::new)
            }
        };

        if dg.done {
            return None;
        }

        if dg.write(info.offset, bytes) {
            self.stats.conflicting_overlaps += 1;
        }
        dg.fragments += 1;

        // The last fragment fixes the total length. First writer wins, so a
        // later fragment disagreeing about where the datagram ends cannot shrink
        // it out from under data already placed beyond that point.
        if !info.more_fragments {
            dg.total_len.get_or_insert(info.offset + bytes.len());
        }

        if dg.filled.len() > MAX_RANGES {
            dg.finish();
            return None;
        }

        // Complete only when the last fragment has been seen and the run from
        // offset 0 reaches it with no holes.
        let total = dg.total_len?;
        if total == 0 || dg.contiguous() < total {
            return None;
        }

        let (transport, app) = decode_datagram(info.key.protocol, &dg.buf[..total]);
        dg.finish();
        self.stats.reassembled += 1;

        Some(DecodedPacket {
            meta: pkt.meta,
            link: None,
            network: pkt.network.clone(),
            transport,
            app,
            payload_len: 0,
            payload_offset: 0,
            ip_payload: None,
            warnings: Vec::new(),
        })
    }
}

/// Decode the transport header and any application message out of a reassembled
/// datagram, reusing the same public parsers a single packet goes through so a
/// split datagram is classified identically to an unsplit one.
fn decode_datagram(protocol: u8, buf: &[u8]) -> (TransportLayer, AppLayer) {
    match protocol {
        proto_num::TCP => match transport::parse_tcp(buf) {
            Ok((tcp, payload)) => {
                let ports = (tcp.src_port, tcp.dst_port);
                let app = app_from_payload(ports, payload, true);
                (TransportLayer::Tcp(tcp), app)
            }
            Err(_) => (TransportLayer::None, AppLayer::None),
        },
        proto_num::UDP => match transport::parse_udp(buf) {
            Ok((udp, payload)) => {
                let ports = (udp.src_port, udp.dst_port);
                let app = app_from_payload(ports, payload, false);
                (TransportLayer::Udp(udp), app)
            }
            Err(_) => (TransportLayer::None, AppLayer::None),
        },
        proto_num::ICMP | proto_num::ICMPV6 => {
            match net::parse_icmp(buf, protocol == proto_num::ICMPV6) {
                Ok(icmp) => (TransportLayer::Icmp(icmp), AppLayer::None),
                Err(_) => (TransportLayer::None, AppLayer::None),
            }
        }
        _ => (TransportLayer::None, AppLayer::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{decode, LinkType, PacketMeta};
    use crate::proto::dns::parse as parse_dns;
    use crate::Timestamp;

    fn meta() -> PacketMeta {
        PacketMeta {
            index: 1,
            timestamp: Timestamp::new(1_000, 0),
            captured_len: 0,
            wire_len: 0,
        }
    }

    /// A DNS response for `name` — enough bytes to be worth fragmenting.
    fn dns_response(name: &str) -> Vec<u8> {
        let mut b = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        b.extend_from_slice(&[0xc0, 0x0c]); // answer: pointer to the question name
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        b.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // ttl 300
        b.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]);
        b
    }

    /// UDP header (src 53 → dst 40000) wrapping `payload`, with an honest length.
    fn udp_l3(payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&40000u16.to_be_bytes());
        udp.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]);
        udp.extend_from_slice(payload);
        udp
    }

    /// Ethernet + IPv4 fragment: `l3` placed at `offset_bytes`, MF as given,
    /// sharing identification `id`. `protocol` is the transport protocol.
    fn v4_frag(id: u16, protocol: u8, offset_bytes: u16, mf: bool, l3: &[u8]) -> Vec<u8> {
        let flags_frag = (offset_bytes / 8) | if mf { 0x2000 } else { 0 };
        let total = (20 + l3.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&id.to_be_bytes());
        ip.extend_from_slice(&flags_frag.to_be_bytes());
        ip.extend_from_slice(&[0x40, protocol, 0x00, 0x00]);
        ip.extend_from_slice(&[192, 168, 1, 50]);
        ip.extend_from_slice(&[198, 51, 100, 9]);
        ip.extend_from_slice(l3);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// Ethernet + IPv6 fragment with a fragment extension header.
    fn v6_frag(id: u32, protocol: u8, offset_bytes: u16, mf: bool, l3: &[u8]) -> Vec<u8> {
        let off_flags = ((offset_bytes / 8) << 3) | if mf { 1 } else { 0 };
        let payload_len = (8 + l3.len()) as u16;
        let mut ip = vec![0x60, 0x00, 0x00, 0x00];
        ip.extend_from_slice(&payload_len.to_be_bytes());
        ip.push(proto_num::IPV6_FRAG);
        ip.push(64);
        ip.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // fragment extension header
        ip.push(protocol);
        ip.push(0);
        ip.extend_from_slice(&off_flags.to_be_bytes());
        ip.extend_from_slice(&id.to_be_bytes());
        ip.extend_from_slice(l3);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x86, 0xdd]);
        eth.extend_from_slice(&ip);
        eth
    }

    fn push_frame(r: &mut IpReassembler, frame: &[u8]) -> Option<DecodedPacket> {
        let pkt = decode(meta(), frame, LinkType::Ethernet);
        r.push(&pkt, frame)
    }

    /// Split an L3 payload into two IPv4 fragments at `split` bytes (a multiple
    /// of 8), returning (first-with-MF, last).
    fn split_v4(id: u16, proto: u8, l3: &[u8], split: usize) -> (Vec<u8>, Vec<u8>) {
        (
            v4_frag(id, proto, 0, true, &l3[..split]),
            v4_frag(id, proto, split as u16, false, &l3[split..]),
        )
    }

    #[test]
    fn two_fragment_udp_dns_reassembles() {
        let l3 = udp_l3(&dns_response("big.example.com"));
        let (f0, f1) = split_v4(0x0001, proto_num::UDP, &l3, 16);

        let mut r = IpReassembler::new();
        assert!(
            push_frame(&mut r, &f0).is_none(),
            "first fragment is not complete"
        );
        let out = push_frame(&mut r, &f1).expect("second fragment completes the datagram");

        match &out.app {
            AppLayer::Dns(d) => assert_eq!(d.primary_name(), Some("big.example.com")),
            other => panic!("expected reassembled DNS, got {other:?}"),
        }
        assert_eq!(out.ports(), Some((53, 40000)));
        assert_eq!(r.stats().reassembled, 1);
    }

    #[test]
    fn fragments_reassemble_out_of_order() {
        let l3 = udp_l3(&dns_response("ooo.example.com"));
        let (f0, f1) = split_v4(0x0002, proto_num::UDP, &l3, 24);

        let mut r = IpReassembler::new();
        // Last fragment first: total is known but nothing is contiguous from 0.
        assert!(push_frame(&mut r, &f1).is_none());
        let out = push_frame(&mut r, &f0).expect("the missing head completes it");
        match &out.app {
            AppLayer::Dns(d) => assert_eq!(d.primary_name(), Some("ooo.example.com")),
            other => panic!("expected DNS, got {other:?}"),
        }
    }

    #[test]
    fn overlapping_fragments_are_first_writer_wins_and_counted() {
        // Same datagram id, overlapping offsets, disagreeing bytes.
        let a = v4_frag(0x0003, proto_num::UDP, 0, true, &[0xaa; 16]);
        let b = v4_frag(0x0003, proto_num::UDP, 8, true, &[0xbb; 16]);

        let mut r = IpReassembler::new();
        assert!(push_frame(&mut r, &a).is_none());
        assert!(push_frame(&mut r, &b).is_none());
        assert_eq!(r.stats().conflicting_overlaps, 1);
    }

    #[test]
    fn incomplete_datagram_never_emits() {
        // Only the first fragment (MF set) ever arrives.
        let l3 = udp_l3(&dns_response("gone.example.com"));
        let f0 = v4_frag(0x0004, proto_num::UDP, 0, true, &l3[..16]);

        let mut r = IpReassembler::new();
        assert!(push_frame(&mut r, &f0).is_none());
        assert_eq!(r.stats().reassembled, 0);
        assert_eq!(r.tracked(), 1);
    }

    #[test]
    fn datagram_table_is_capped() {
        let mut r = IpReassembler::new();
        // Each id opens one incomplete datagram (MF, never completed).
        for i in 0..(MAX_TRACKED_DATAGRAMS as u16) {
            let f = v4_frag(i, proto_num::UDP, 0, true, &[0x11; 8]);
            push_frame(&mut r, &f);
        }
        assert_eq!(r.tracked(), MAX_TRACKED_DATAGRAMS);
        // One more distinct id is dropped, not queued.
        let f = v4_frag(0xffff, proto_num::UDP, 0, true, &[0x11; 8]);
        push_frame(&mut r, &f);
        assert_eq!(r.stats().dropped_datagrams, 1);
        assert_eq!(r.tracked(), MAX_TRACKED_DATAGRAMS);
    }

    #[test]
    fn ipv6_two_fragment_datagram_reassembles() {
        let dns = dns_response("v6.example.com");
        let l3 = udp_l3(&dns);
        let split = 16;
        let f0 = v6_frag(0xabcddcba, proto_num::UDP, 0, true, &l3[..split]);
        let f1 = v6_frag(
            0xabcddcba,
            proto_num::UDP,
            split as u16,
            false,
            &l3[split..],
        );

        let mut r = IpReassembler::new();
        assert!(push_frame(&mut r, &f0).is_none());
        let out = push_frame(&mut r, &f1).expect("v6 datagram reassembles");
        match &out.app {
            AppLayer::Dns(d) => assert_eq!(d.primary_name(), Some("v6.example.com")),
            other => panic!("expected DNS, got {other:?}"),
        }
        // Sanity: the assembled bytes are a whole DNS message on their own.
        assert!(parse_dns(&dns).is_some());
    }

    #[test]
    fn non_fragmented_packet_is_ignored() {
        // A plain (DF) UDP frame must not be buffered.
        let l3 = udp_l3(&dns_response("plain.example.com"));
        let frame = v4_frag(0x0005, proto_num::UDP, 0, false, &l3); // MF=0, offset 0
        let pkt = decode(meta(), &frame, LinkType::Ethernet);
        assert_eq!(
            pkt.ip_payload, None,
            "offset-0 MF-0 datagram is not a fragment"
        );
        let mut r = IpReassembler::new();
        assert!(r.push(&pkt, &frame).is_none());
        assert_eq!(r.tracked(), 0);
    }
}
