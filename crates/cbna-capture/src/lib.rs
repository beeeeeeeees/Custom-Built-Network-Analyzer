//! Packet sources.
//!
//! Everything downstream consumes a [`Source`], so the analysis pipeline is
//! identical whether bytes arrive from a file on disk or a live NIC.
//!
//! The pcap and pcapng readers are implemented here rather than pulled from a
//! crate: file parsing is the part most exposed to untrusted input, and keeping
//! it in-tree means the bounds checks are ours to audit.

pub mod file;
pub mod writer;

#[cfg(feature = "live")]
pub mod live;

pub use file::{FileFormat, FileSource};
pub use writer::PcapWriter;

use cbna_core::packet::{LinkType, PacketMeta};
use cbna_core::Timestamp;

/// One captured frame plus its metadata.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub meta: PacketMeta,
    pub data: Vec<u8>,
}

impl RawPacket {
    pub fn new(index: u64, timestamp: Timestamp, wire_len: u32, data: Vec<u8>) -> Self {
        Self {
            meta: PacketMeta {
                index,
                timestamp,
                captured_len: data.len() as u32,
                wire_len,
            },
            data,
        }
    }
}

/// A stream of packets with a known link layer.
pub trait Source {
    fn link_type(&self) -> LinkType;

    /// Next packet, or `None` at end of stream.
    fn next_packet(&mut self) -> Option<Result<RawPacket, CaptureError>>;

    /// Human description of where these packets came from.
    fn description(&self) -> String;
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0} is not a pcap or pcapng file (bad magic {1:#010x})")]
    UnknownFormat(String, u32),

    #[error("malformed capture file: {0}")]
    Malformed(String),

    /// A packet claiming an absurd length is rejected rather than allocated.
    #[error("packet {index} declares {len} captured bytes, above the {limit} byte limit")]
    ImplausibleLength { index: u64, len: u32, limit: u32 },

    #[error("live capture is not compiled in; rebuild with --features live")]
    LiveUnavailable,

    #[cfg(feature = "live")]
    #[error("libpcap error: {0}")]
    Pcap(#[from] pcap::Error),
}

/// Upper bound on a single packet, well above jumbo frames. Guards against a
/// corrupt or hostile length field turning into a huge allocation.
pub const MAX_PACKET_BYTES: u32 = 262_144;

/// Open a capture file, detecting pcap vs pcapng from the magic number.
pub fn open_file(path: impl AsRef<std::path::Path>) -> Result<FileSource, CaptureError> {
    FileSource::open(path)
}
