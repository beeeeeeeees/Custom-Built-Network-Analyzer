//! Head-of-stream TCP reassembly.
//!
//! Decoding a single segment covers the first request or response of most
//! connections, but not all of them, and the exceptions are the interesting
//! ones. A request line split across two segments, a ClientHello pushed out in
//! pieces, or a sender that simply writes small — each of those hides the
//! headers this tool reads, and splitting a request across segments is a
//! textbook way to walk past an inspection layer that only looks at one packet
//! at a time.
//!
//! # Why only the head
//!
//! Every consumer here wants the *beginning* of a direction's byte stream: the
//! request line and headers, the TLS hello, the length-prefixed DNS message.
//! Nothing wants segment forty thousand. So each direction buffers a bounded
//! prefix, and the buffer is released the moment a message parses out of it or
//! the cap is reached. That is what keeps this from becoming a second copy of
//! the capture: it is not a general-purpose TCP stack, and it is not trying to
//! be one.
//!
//! # Bounds
//!
//! Per CLAUDE.md, unbounded growth is a bug, and a reassembler is where that
//! rule is easiest to break. Four separate caps hold:
//!
//! - [`MAX_STREAM_BYTES`] per direction, so one connection cannot buffer a
//!   capture's worth of data.
//! - [`MAX_TRACKED_STREAMS`] in total, so a scan across a million ports cannot
//!   allocate a million buffers. New streams past the limit are counted and
//!   dropped, never queued.
//! - [`MAX_RANGES`] holes per stream, so a sender that transmits every other
//!   byte out of order cannot grow the bookkeeping without limit.
//! - Buffers are freed on FIN, on RST, on a successful parse, and on hitting
//!   any of the above.
//!
//! Worst case is `MAX_TRACKED_STREAMS * MAX_STREAM_BYTES` = 16 MiB, and only
//! for a capture engineered to hit it; the ordinary case is a few hundred bytes
//! per connection, held for two or three segments.

use crate::flow::{Direction, FlowKey};
use crate::packet::{app_from_payload, AppLayer, DecodedPacket, TransportLayer};
use std::collections::HashMap;

/// Bytes buffered per direction. Matches the header limit in `proto::http`, on
/// the grounds that a request whose headers do not fit in 16 KiB is not one
/// this tool is going to make sense of anyway.
pub const MAX_STREAM_BYTES: usize = 16 * 1024;

/// Directions tracked at once, across all flows.
pub const MAX_TRACKED_STREAMS: usize = 1024;

/// Disjoint filled ranges per stream before the stream is abandoned.
const MAX_RANGES: usize = 16;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyStats {
    /// Application messages recovered that single-segment decoding missed.
    /// This is the whole point of the module; if it is zero on a real capture,
    /// reassembly is not earning its keep.
    pub recovered: u64,
    /// Streams never tracked because the table was already full.
    pub dropped_streams: u64,
    /// Segments that rewrote already-buffered bytes with *different* content.
    ///
    /// Retransmissions are normal and agree with what they replace. A
    /// disagreement means two different payloads claimed the same sequence
    /// range, which is either a badly broken middlebox or a deliberate attempt
    /// to make an inspector and the destination host see different bytes.
    pub conflicting_overlaps: u64,
}

#[derive(Debug)]
struct Stream {
    /// Sequence number that corresponds to offset 0.
    base: u32,
    buf: Vec<u8>,
    /// Sorted, merged, non-overlapping `[start, end)` ranges of `buf` that hold
    /// real data.
    filled: Vec<(usize, usize)>,
    /// Segments contributing so far. Parsing is not attempted until a second
    /// segment arrives, because the first one was already tried by `decode`.
    segments: u32,
    /// `base` came from a SYN, so it is authoritative and must not be moved by
    /// a stray segment carrying an older sequence number.
    syn_based: bool,
    done: bool,
}

impl Stream {
    fn new(base: u32) -> Self {
        Self {
            base,
            buf: Vec::new(),
            filled: Vec::new(),
            segments: 0,
            syn_based: false,
            done: false,
        }
    }

    /// Release the buffer but keep the entry, so late segments on a finished
    /// stream are ignored cheaply instead of starting it over.
    fn finish(&mut self) {
        self.done = true;
        self.buf = Vec::new();
        self.buf.shrink_to_fit();
        self.filled = Vec::new();
    }

    /// Move the stream start `delta` bytes earlier, shifting everything already
    /// buffered along with it.
    ///
    /// Needed because the first segment we see is not necessarily the first the
    /// sender sent. On a capture that starts mid-connection, or simply on
    /// reordering, an earlier segment can arrive after a later one; without
    /// this, that earlier data lands at a negative offset and is discarded —
    /// which loses precisely the head of the stream everything here wants.
    fn rebase(&mut self, delta: usize) {
        let keep = MAX_STREAM_BYTES.saturating_sub(delta);
        let mut buf = vec![0u8; delta.min(MAX_STREAM_BYTES)];
        buf.extend_from_slice(&self.buf[..self.buf.len().min(keep)]);
        self.buf = buf;
        self.filled = self
            .filled
            .iter()
            .filter_map(|&(s, e)| {
                let s = s + delta;
                let e = (e + delta).min(MAX_STREAM_BYTES);
                (s < e).then_some((s, e))
            })
            .collect();
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
        let end = (offset + payload.len()).min(MAX_STREAM_BYTES);
        if end <= offset {
            return false;
        }
        let payload = &payload[..end - offset];

        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }

        // Compare against bytes we already hold before overwriting anything, so
        // an overlap that disagrees is visible rather than silently resolved.
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

/// Whether single-segment decoding already got the whole message.
///
/// "Decoded something" is not the same as "decoded all of it". `http::parse`
/// succeeds on any valid start line, so half a request still returns a message
/// — one whose last header is cut mid-value and whose later headers are simply
/// missing. Treating that as finished is exactly how a request split across two
/// segments hides an `Authorization` header. DNS is all-or-nothing, so a
/// message that parsed at all is whole.
fn is_complete(app: &AppLayer) -> bool {
    match app {
        AppLayer::None => false,
        AppLayer::Http(h) => h.complete,
        AppLayer::Tls(t) => t.complete,
        AppLayer::Dns(_) => true,
    }
}

/// Rebuilds the leading bytes of each TCP direction so the application
/// decoders see whole messages.
#[derive(Debug, Default)]
pub struct Reassembler {
    streams: HashMap<(FlowKey, Direction), Stream>,
    stats: ReassemblyStats,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    pub fn tracked(&self) -> usize {
        self.streams.len()
    }

    /// Feed one decoded packet in. Returns an application message only when
    /// reassembly recovered something single-segment decoding could not.
    ///
    /// A packet whose own payload already decoded is not buffered at all: that
    /// message is accounted for, and buffering it would double-count it. So
    /// this only ever fires on the gap it exists to close.
    pub fn push(&mut self, pkt: &DecodedPacket, frame: &[u8]) -> Option<AppLayer> {
        let TransportLayer::Tcp(tcp) = &pkt.transport else {
            return None;
        };
        let (key, dir) = FlowKey::from_packet(pkt)?;
        let payload = pkt.payload(frame);

        // A connection that is closing, resetting, or already fully understood
        // needs no buffer. Drop it eagerly rather than waiting for a cap.
        if tcp.flags.fin() || tcp.flags.rst() || is_complete(&pkt.app) {
            if let Some(s) = self.streams.get_mut(&(key, dir)) {
                s.finish();
            }
            return None;
        }

        if tcp.flags.syn() {
            // The SYN consumes one sequence number, so data starts after it.
            // Re-seat the stream on it: a SYN is the one authoritative
            // statement of where this direction's stream begins.
            let s = self
                .streams
                .entry((key, dir))
                .or_insert_with(|| Stream::new(tcp.seq.wrapping_add(1)));
            if !s.done {
                s.base = tcp.seq.wrapping_add(1);
                s.syn_based = true;
            }
            return None;
        }

        if payload.is_empty() {
            return None;
        }

        let entry = self.streams.get_mut(&(key, dir));
        let stream = match entry {
            Some(s) => s,
            None => {
                if self.streams.len() >= MAX_TRACKED_STREAMS {
                    self.stats.dropped_streams += 1;
                    return None;
                }
                // No SYN seen — the capture started mid-conversation, which is
                // the norm for live capture. Treat this segment as the start.
                self.streams
                    .entry((key, dir))
                    .or_insert_with(|| Stream::new(tcp.seq))
            }
        };

        if stream.done {
            return None;
        }

        // A segment that precedes everything seen so far moves the start of the
        // stream, unless a SYN already settled it. `wrapping_sub` keeps this
        // correct across a sequence-number rollover.
        if !stream.syn_based {
            let back = stream.base.wrapping_sub(tcp.seq) as usize;
            if back > 0 && back <= MAX_STREAM_BYTES {
                stream.rebase(back);
                stream.base = tcp.seq;
            }
        }

        // Relative offset. Wrapping handles the u32 sequence rolling over;
        // anything landing beyond the window we care about is discarded, which
        // also disposes of the wrapped-around garbage case.
        let offset = tcp.seq.wrapping_sub(stream.base) as usize;
        if offset >= MAX_STREAM_BYTES {
            return None;
        }

        if stream.write(offset, payload) {
            self.stats.conflicting_overlaps += 1;
        }
        stream.segments += 1;

        if stream.filled.len() > MAX_RANGES {
            stream.finish();
            return None;
        }

        // The first segment was already run through the decoders by `decode`;
        // re-running it here would just fail again.
        if stream.segments < 2 {
            return None;
        }

        let contiguous = stream.contiguous();
        if contiguous == 0 {
            return None;
        }

        let ports = pkt.ports().unwrap_or((0, 0));
        let app = app_from_payload(ports, &stream.buf[..contiguous], true);
        // Only a whole message is worth emitting. A partial one would be no
        // better than what the single segment already produced, and stopping
        // here would give up on the bytes still to come.
        if is_complete(&app) {
            stream.finish();
            self.stats.recovered += 1;
            return Some(app);
        }

        if contiguous >= MAX_STREAM_BYTES {
            stream.finish();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{decode, LinkType, PacketMeta};
    use crate::transport::TcpFlags;
    use crate::Timestamp;

    /// Ethernet + IPv4 + TCP, with the sequence number and flags under test
    /// control. Returns the frame; callers decode it themselves so the
    /// reassembler is driven exactly as `Analyzer` drives it.
    fn seg(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 0]); // ack
        t.extend_from_slice(&[0x50, flags]);
        t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        t.extend_from_slice(payload);

        let total = (20 + t.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[192, 168, 1, 10]);
        ip.extend_from_slice(&[93, 184, 216, 34]);
        ip.extend_from_slice(&t);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    fn feed(r: &mut Reassembler, frame: &[u8]) -> Option<AppLayer> {
        let meta = PacketMeta {
            index: 0,
            timestamp: Timestamp::new(0, 0),
            captured_len: frame.len() as u32,
            wire_len: frame.len() as u32,
        };
        let pkt = decode(meta, frame, LinkType::Ethernet);
        r.push(&pkt, frame)
    }

    const PSH_ACK: u8 = TcpFlags::PSH | TcpFlags::ACK;

    #[test]
    fn recovers_a_request_split_across_segments() {
        // The exact evasion the module exists for: neither half decodes alone.
        let a = b"GET /admin HTTP/1.1\r\nHost: inter";
        let b = b"nal.corp\r\nAuthorization: Basic c2VjcmV0\r\n\r\n";

        let f1 = seg(40000, 80, 1000, PSH_ACK, a);
        let f2 = seg(40000, 80, 1000 + a.len() as u32, PSH_ACK, b);

        let mut r = Reassembler::new();
        assert!(feed(&mut r, &f1).is_none(), "half a request must not parse");
        let app = feed(&mut r, &f2).expect("the pair should reassemble");
        match app {
            AppLayer::Http(h) => {
                assert_eq!(h.host.as_deref(), Some("internal.corp"));
                assert!(h.has_authorization, "credentials must survive the split");
            }
            other => panic!("expected HTTP, got {other:?}"),
        }
        assert_eq!(r.stats().recovered, 1);
    }

    #[test]
    fn recovers_when_segments_arrive_out_of_order() {
        let a = b"GET / HTTP/1.1\r\nHost: ex";
        let b = b"ample.com\r\n\r\n";
        let f1 = seg(40001, 80, 500, PSH_ACK, a);
        let f2 = seg(40001, 80, 500 + a.len() as u32, PSH_ACK, b);

        let mut r = Reassembler::new();
        // Second half first: nothing is contiguous from offset 0 yet.
        assert!(feed(&mut r, &f2).is_none());
        let app = feed(&mut r, &f1).expect("the hole should close");
        match app {
            AppLayer::Http(h) => assert_eq!(h.host.as_deref(), Some("example.com")),
            other => panic!("expected HTTP, got {other:?}"),
        }
    }

    #[test]
    fn recovers_a_tls_hello_split_across_segments() {
        let mut hello = vec![0x16, 0x03, 0x01];
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0x42; 32]);
        hs.push(0x00);
        hs.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hs.extend_from_slice(&[0x01, 0x00]);
        let host = b"split.example.com";
        let mut sni_list = vec![0x00];
        sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(host);
        let mut sni_ext = (sni_list.len() as u16).to_be_bytes().to_vec();
        sni_ext.extend_from_slice(&sni_list);
        let mut exts = vec![0x00, 0x00];
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);
        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);
        hello.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        hello.extend_from_slice(&handshake);

        // Split inside the extension block, where a single segment cannot see
        // the SNI at all.
        let cut = hello.len() - 12;
        let f1 = seg(40002, 443, 7000, PSH_ACK, &hello[..cut]);
        let f2 = seg(40002, 443, 7000 + cut as u32, PSH_ACK, &hello[cut..]);

        let mut r = Reassembler::new();
        assert!(feed(&mut r, &f1).is_none());
        match feed(&mut r, &f2).expect("hello should reassemble") {
            AppLayer::Tls(t) => assert_eq!(t.sni.as_deref(), Some("split.example.com")),
            other => panic!("expected TLS, got {other:?}"),
        }
    }

    #[test]
    fn a_message_that_fits_one_segment_is_not_recovered_twice() {
        // decode() already handled this one, so the reassembler must stay out
        // of the way or the finding counts would double.
        let whole = b"GET / HTTP/1.1\r\nHost: whole.example\r\n\r\n";
        let f = seg(40003, 80, 10, PSH_ACK, whole);
        let mut r = Reassembler::new();
        assert!(feed(&mut r, &f).is_none());
        assert_eq!(r.stats().recovered, 0);
    }

    #[test]
    fn identical_retransmission_is_not_a_conflict() {
        let a = b"GET / HTTP/1.1\r\nHost: re";
        let f1 = seg(40004, 80, 900, PSH_ACK, a);
        let mut r = Reassembler::new();
        feed(&mut r, &f1);
        feed(&mut r, &f1); // exact retransmit
        assert_eq!(r.stats().conflicting_overlaps, 0);
    }

    #[test]
    fn overlapping_segments_that_disagree_are_counted() {
        // Same sequence range, different bytes: the inspector and the endpoint
        // would disagree about what was sent.
        let f1 = seg(40005, 80, 300, PSH_ACK, b"GET /public ");
        let f2 = seg(40005, 80, 300, PSH_ACK, b"GET /secret ");
        let mut r = Reassembler::new();
        feed(&mut r, &f1);
        feed(&mut r, &f2);
        assert_eq!(r.stats().conflicting_overlaps, 1);
        // First writer wins, so the recorded stream matches what a
        // first-fragment-wins host would have seen.
        let s = r.streams.values().next().unwrap();
        assert_eq!(&s.buf[..11], b"GET /public");
    }

    #[test]
    fn syn_reseats_the_stream_base() {
        // A SYN says where the stream really starts; data seen before it
        // should not permanently misalign the offsets.
        let syn = seg(40006, 80, 5000, TcpFlags::SYN, &[]);
        let a = b"GET / HTTP/1.1\r\nHost: sy";
        let b = b"n.example\r\n\r\n";
        let f1 = seg(40006, 80, 5001, PSH_ACK, a);
        let f2 = seg(40006, 80, 5001 + a.len() as u32, PSH_ACK, b);

        let mut r = Reassembler::new();
        feed(&mut r, &syn);
        assert!(feed(&mut r, &f1).is_none());
        match feed(&mut r, &f2).expect("should reassemble after a SYN") {
            AppLayer::Http(h) => assert_eq!(h.host.as_deref(), Some("syn.example")),
            other => panic!("expected HTTP, got {other:?}"),
        }
    }

    #[test]
    fn fin_releases_the_buffer() {
        let f1 = seg(40007, 80, 20, PSH_ACK, b"GET /x HTTP/1.1\r\nHos");
        let fin = seg(40007, 80, 40, TcpFlags::FIN | TcpFlags::ACK, &[]);
        let mut r = Reassembler::new();
        feed(&mut r, &f1);
        assert!(!r.streams.values().next().unwrap().buf.is_empty());
        feed(&mut r, &fin);
        let s = r.streams.values().next().unwrap();
        assert!(s.done && s.buf.is_empty(), "FIN must free the buffer");
    }

    #[test]
    fn stream_table_is_capped() {
        let mut r = Reassembler::new();
        // Every port is a distinct flow, so this walks past the cap.
        for i in 0..(MAX_TRACKED_STREAMS as u32 + 50) {
            let f = seg(20000 + (i % 40000) as u16, 80, 1, PSH_ACK, b"partial da");
            // Vary the port so each is a new stream.
            let f = if i < 40000 {
                seg(20000 + i as u16, 80, 1, PSH_ACK, b"partial da")
            } else {
                f
            };
            feed(&mut r, &f);
        }
        assert!(
            r.tracked() <= MAX_TRACKED_STREAMS,
            "tracked {} streams, cap is {MAX_TRACKED_STREAMS}",
            r.tracked()
        );
        assert!(
            r.stats().dropped_streams > 0,
            "hitting the cap must be reported, not silent"
        );
    }

    #[test]
    fn a_stream_that_never_parses_stops_growing() {
        // Opaque bytes that will never look like HTTP, TLS or DNS.
        let mut r = Reassembler::new();
        let chunk = vec![0x5a; 1400];
        let mut seq = 1u32;
        for _ in 0..40 {
            let f = seg(40008, 9999, seq, PSH_ACK, &chunk);
            feed(&mut r, &f);
            seq = seq.wrapping_add(chunk.len() as u32);
        }
        let s = r.streams.values().next().unwrap();
        assert!(s.done, "stream should have been abandoned at the cap");
        assert!(s.buf.is_empty(), "and its buffer released");
    }

    #[test]
    fn offsets_beyond_the_window_are_ignored() {
        // A segment far into a long transfer must not allocate a buffer sized
        // to its offset.
        let f1 = seg(40009, 80, 100, PSH_ACK, b"GET /");
        let far = seg(40009, 80, 100 + 5_000_000, PSH_ACK, b"junk");
        let mut r = Reassembler::new();
        feed(&mut r, &f1);
        feed(&mut r, &far);
        let s = r.streams.values().next().unwrap();
        assert!(
            s.buf.len() <= MAX_STREAM_BYTES,
            "buffer grew to {} bytes",
            s.buf.len()
        );
    }
}
