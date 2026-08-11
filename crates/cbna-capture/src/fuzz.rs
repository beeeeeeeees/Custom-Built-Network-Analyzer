//! Shared fuzz entry point for the capture-file readers.
//!
//! See `cbna_core::fuzz` for why these live in the library. This is the target
//! that matters most: a pcap or pcapng is the artifact an analyst is handed by
//! someone else, and the readers walk a block chain whose every length and
//! count comes from the file.

use crate::{FileSource, Source};
use cbna_core::packet::decode;
use std::hint::black_box;

/// Bound the loop. A valid header followed by a cheap repeating block can
/// describe millions of packets in a few hundred bytes, and a fuzz iteration
/// that runs for a minute finds nothing.
const MAX_PACKETS: usize = 4096;

/// Parse a whole capture from memory and decode every packet it yields.
///
/// Driving the decoder from the reader's own output is deliberate: it keeps the
/// two layers wired together, so a length the reader lets through cannot
/// quietly become a decoder crash.
pub fn capture_file(data: &[u8]) {
    let Ok(mut src) = FileSource::from_bytes(data) else {
        return;
    };
    let link = src.link_type();
    let mut seen = 0usize;
    while let Some(next) = src.next_packet() {
        let Ok(pkt) = next else { break };
        let decoded = decode(pkt.meta, &pkt.data, link);
        black_box(decoded.warnings.len());
        seen += 1;
        if seen >= MAX_PACKETS {
            break;
        }
    }
}
