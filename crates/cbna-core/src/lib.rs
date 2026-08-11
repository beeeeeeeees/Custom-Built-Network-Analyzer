//! Decoding and analysis engine.
//!
//! The engine is deliberately I/O-free: it takes raw bytes plus a timestamp and
//! produces [`packet::DecodedPacket`] values, which are fed into an
//! [`analysis::Analyzer`] that owns the flow table and protocol indexes. Both
//! the offline (pcap file) and live (npcap) front-ends drive the same path, so
//! findings are identical regardless of where the bytes came from.

pub mod analysis;
pub mod bytes;
pub mod error;
pub mod flow;
pub mod fuzz;
pub mod link;
pub mod net;
pub mod packet;
pub mod proto;
pub mod time;
pub mod transport;

pub use error::{DecodeError, Result};
pub use packet::{decode, DecodedPacket, LinkType, PacketMeta};
pub use time::Timestamp;
