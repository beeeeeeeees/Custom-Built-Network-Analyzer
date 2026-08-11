//! Classic pcap writer, used to save live capture to disk.
//!
//! Nanosecond-resolution magic is used so timestamps survive the round trip
//! without being rounded to microseconds.

use crate::{CaptureError, RawPacket};
use cbna_core::packet::LinkType;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

const PCAP_MAGIC_NS: u32 = 0xa1b2_3c4d;
const SNAPLEN: u32 = 262_144;

pub struct PcapWriter {
    out: BufWriter<File>,
    packets: u64,
    bytes: u64,
}

impl PcapWriter {
    pub fn create(path: impl AsRef<Path>, link_type: LinkType) -> Result<Self, CaptureError> {
        let file = File::create(path)?;
        let mut out = BufWriter::with_capacity(1 << 20, file);

        let link = match link_type {
            LinkType::Null => 0,
            LinkType::Ethernet => 1,
            LinkType::Raw => 101,
            LinkType::Loop => 108,
            LinkType::LinuxSll => 113,
            LinkType::LinuxSll2 => 276,
            LinkType::Other(v) => v,
        };

        out.write_all(&PCAP_MAGIC_NS.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?; // version major
        out.write_all(&4u16.to_le_bytes())?; // version minor
        out.write_all(&0i32.to_le_bytes())?; // GMT offset
        out.write_all(&0u32.to_le_bytes())?; // timestamp accuracy
        out.write_all(&SNAPLEN.to_le_bytes())?;
        out.write_all(&link.to_le_bytes())?;

        Ok(Self {
            out,
            packets: 0,
            bytes: 0,
        })
    }

    pub fn write(&mut self, pkt: &RawPacket) -> Result<(), CaptureError> {
        let ts = pkt.meta.timestamp;
        self.out.write_all(&(ts.secs as u32).to_le_bytes())?;
        self.out.write_all(&ts.nanos.to_le_bytes())?;
        self.out.write_all(&(pkt.data.len() as u32).to_le_bytes())?;
        self.out.write_all(&pkt.meta.wire_len.to_le_bytes())?;
        self.out.write_all(&pkt.data)?;
        self.packets += 1;
        self.bytes += pkt.data.len() as u64;
        Ok(())
    }

    pub fn packets_written(&self) -> u64 {
        self.packets
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }

    pub fn flush(&mut self) -> Result<(), CaptureError> {
        self.out.flush()?;
        Ok(())
    }
}

impl Drop for PcapWriter {
    fn drop(&mut self) {
        // A capture file that was never flushed is worse than useless, so make
        // the attempt even on an unwind.
        let _ = self.out.flush();
    }
}
