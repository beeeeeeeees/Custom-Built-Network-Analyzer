//! pcap and pcapng file readers.
//!
//! Both formats are read incrementally from a buffered reader so a multi-GB
//! capture never has to fit in memory. Every length taken from the file is
//! bounds-checked before it is used to allocate.

use crate::{CaptureError, RawPacket, Source, MAX_PACKET_BYTES};
use cbna_core::packet::LinkType;
use cbna_core::Timestamp;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;
/// Same as above but timestamps are nanosecond-resolution.
const PCAP_MAGIC_NS_LE: u32 = 0xa1b2_3c4d;
const PCAP_MAGIC_NS_BE: u32 = 0x4d3c_b2a1;
const PCAPNG_BLOCK_SHB: u32 = 0x0a0d_0d0a;

const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_SPB: u32 = 0x0000_0003;
const BLOCK_EPB: u32 = 0x0000_0006;

/// Refuse pcapng blocks larger than this; the spec allows more but nothing
/// legitimate needs it, and the value drives an allocation.
const MAX_BLOCK_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Pcap,
    PcapNg,
}

/// Per-interface state from a pcapng IDB.
#[derive(Debug, Clone)]
struct Interface {
    link_type: LinkType,
    /// Divisor turning raw timestamp units into seconds.
    ts_resolution: u64,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            link_type: LinkType::Ethernet,
            ts_resolution: 1_000_000,
        }
    }
}

#[derive(Debug)]
pub struct FileSource {
    path: PathBuf,
    format: FileFormat,
    reader: BufReader<File>,
    /// pcap: byte order of the file. pcapng: byte order of the current section.
    big_endian: bool,
    /// pcap only.
    nanosecond_ts: bool,
    link_type: LinkType,
    interfaces: Vec<Interface>,
    index: u64,
    finished: bool,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let mut reader = BufReader::with_capacity(1 << 20, file);

        let mut magic_bytes = [0u8; 4];
        reader.read_exact(&mut magic_bytes)?;
        let magic = u32::from_le_bytes(magic_bytes);

        let mut src = FileSource {
            path,
            format: FileFormat::Pcap,
            reader,
            big_endian: false,
            nanosecond_ts: false,
            link_type: LinkType::Ethernet,
            interfaces: Vec::new(),
            index: 0,
            finished: false,
        };

        match magic {
            PCAP_MAGIC_LE => src.read_pcap_header(false, false)?,
            PCAP_MAGIC_NS_LE => src.read_pcap_header(false, true)?,
            PCAP_MAGIC_BE => src.read_pcap_header(true, false)?,
            PCAP_MAGIC_NS_BE => src.read_pcap_header(true, true)?,
            m if m.swap_bytes() == PCAPNG_BLOCK_SHB || m == PCAPNG_BLOCK_SHB => {
                src.format = FileFormat::PcapNg;
                src.read_pcapng_section_header()?;
            }
            other => {
                return Err(CaptureError::UnknownFormat(
                    src.path.display().to_string(),
                    other,
                ))
            }
        }

        Ok(src)
    }

    pub fn format(&self) -> FileFormat {
        self.format
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // --- pcap ------------------------------------------------------------

    fn read_pcap_header(&mut self, big_endian: bool, nanosecond: bool) -> Result<(), CaptureError> {
        self.big_endian = big_endian;
        self.nanosecond_ts = nanosecond;
        // Remaining 20 bytes of the 24-byte global header.
        let mut rest = [0u8; 20];
        self.reader.read_exact(&mut rest)?;
        let link = u32::from_le_bytes([rest[16], rest[17], rest[18], rest[19]]);
        let link = if big_endian { link.swap_bytes() } else { link };
        self.link_type = LinkType::from_u32(link);
        Ok(())
    }

    fn next_pcap(&mut self) -> Option<Result<RawPacket, CaptureError>> {
        let mut hdr = [0u8; 16];
        match self.reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.finished = true;
                return None;
            }
            Err(e) => return Some(Err(e.into())),
        }

        let get = |o: usize| {
            let v = u32::from_le_bytes([hdr[o], hdr[o + 1], hdr[o + 2], hdr[o + 3]]);
            if self.big_endian {
                v.swap_bytes()
            } else {
                v
            }
        };
        let ts_sec = get(0);
        let ts_frac = get(4);
        let caplen = get(8);
        let wirelen = get(12);

        self.index += 1;
        if caplen > MAX_PACKET_BYTES {
            self.finished = true;
            return Some(Err(CaptureError::ImplausibleLength {
                index: self.index,
                len: caplen,
                limit: MAX_PACKET_BYTES,
            }));
        }

        let mut data = vec![0u8; caplen as usize];
        if let Err(e) = self.reader.read_exact(&mut data) {
            self.finished = true;
            // A capture cut off mid-packet (killed process, full disk) is
            // common enough that it should not look like corruption.
            return if e.kind() == std::io::ErrorKind::UnexpectedEof {
                None
            } else {
                Some(Err(e.into()))
            };
        }

        let timestamp = if self.nanosecond_ts {
            Timestamp::new(ts_sec as i64, ts_frac)
        } else {
            Timestamp::from_micros(ts_sec as i64, ts_frac)
        };
        Some(Ok(RawPacket::new(
            self.index,
            timestamp,
            wirelen.max(caplen),
            data,
        )))
    }

    // --- pcapng ----------------------------------------------------------

    fn read_pcapng_section_header(&mut self) -> Result<(), CaptureError> {
        // The SHB magic has already been consumed; read length + byte-order
        // magic, which tells us how to interpret everything after it.
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        let byte_order = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        self.big_endian = match byte_order {
            0x1a2b_3c4d => false,
            0x4d3c_2b1a => true,
            other => {
                return Err(CaptureError::Malformed(format!(
                    "section header byte-order magic {other:#010x} is not recognised"
                )))
            }
        };
        let total_len = self.u32_from(&buf[0..4]);
        if !(12..=MAX_BLOCK_BYTES).contains(&total_len) {
            return Err(CaptureError::Malformed(format!(
                "section header block length {total_len} is out of range"
            )));
        }
        // Skip the rest of the SHB (version, section length, options) plus the
        // trailing length field. 12 bytes are already consumed.
        self.skip(total_len as usize - 12)?;
        Ok(())
    }

    fn next_pcapng(&mut self) -> Option<Result<RawPacket, CaptureError>> {
        loop {
            let mut head = [0u8; 8];
            match self.reader.read_exact(&mut head) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.finished = true;
                    return None;
                }
                Err(e) => return Some(Err(e.into())),
            }
            let block_type = self.u32_from(&head[0..4]);
            let total_len = self.u32_from(&head[4..8]);

            if !(12..=MAX_BLOCK_BYTES).contains(&total_len) || total_len % 4 != 0 {
                self.finished = true;
                return Some(Err(CaptureError::Malformed(format!(
                    "block {block_type:#010x} declares an invalid length of {total_len}"
                ))));
            }
            // Body excludes the 8 bytes read and the 4-byte trailing length.
            let body_len = total_len as usize - 12;
            let mut body = vec![0u8; body_len];
            if let Err(e) = self.reader.read_exact(&mut body) {
                self.finished = true;
                return if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    None
                } else {
                    Some(Err(e.into()))
                };
            }
            if let Err(e) = self.skip(4) {
                self.finished = true;
                return Some(Err(e));
            }

            match block_type {
                PCAPNG_BLOCK_SHB => {
                    // A new section may change byte order; re-read from the
                    // body we already consumed.
                    if body_len >= 4 {
                        let bom = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                        self.big_endian = bom == 0x4d3c_2b1a;
                    }
                    self.interfaces.clear();
                }
                BLOCK_IDB => match self.parse_idb(&body) {
                    Ok(iface) => {
                        if self.interfaces.is_empty() {
                            self.link_type = iface.link_type;
                        }
                        self.interfaces.push(iface);
                    }
                    Err(e) => return Some(Err(e)),
                },
                BLOCK_EPB => match self.parse_epb(&body) {
                    Ok(pkt) => return Some(Ok(pkt)),
                    Err(e) => {
                        self.finished = true;
                        return Some(Err(e));
                    }
                },
                BLOCK_SPB => {
                    // Simple packet block: original length only, no timestamp.
                    if body_len < 4 {
                        continue;
                    }
                    let orig_len = self.u32_from(&body[0..4]);
                    let data = body[4..].to_vec();
                    self.index += 1;
                    return Some(Ok(RawPacket::new(
                        self.index,
                        Timestamp::ZERO,
                        orig_len.max(data.len() as u32),
                        data,
                    )));
                }
                // Name resolution, statistics, decryption secrets and custom
                // blocks carry no packets; skip them.
                _ => continue,
            }
        }
    }

    fn parse_idb(&self, body: &[u8]) -> Result<Interface, CaptureError> {
        if body.len() < 8 {
            return Err(CaptureError::Malformed(
                "interface description block is too short".into(),
            ));
        }
        let link = self.u16_from(&body[0..2]) as u32;
        let mut iface = Interface {
            link_type: LinkType::from_u32(link),
            ts_resolution: 1_000_000,
        };

        // Options start after linktype(2) + reserved(2) + snaplen(4).
        let mut off = 8;
        while off + 4 <= body.len() {
            let code = self.u16_from(&body[off..off + 2]);
            let len = self.u16_from(&body[off + 2..off + 4]) as usize;
            let val_start = off + 4;
            let val_end = val_start + len;
            if val_end > body.len() {
                break;
            }
            // if_tsresol: one byte. High bit set means power of two, else ten.
            if code == 9 && len == 1 {
                let raw = body[val_start];
                let exp = (raw & 0x7F) as u32;
                iface.ts_resolution = if raw & 0x80 != 0 {
                    2u64.saturating_pow(exp.min(63))
                } else {
                    10u64.checked_pow(exp.min(18)).unwrap_or(1_000_000)
                };
            }
            if code == 0 {
                break; // opt_endofopt
            }
            // Options are padded to a 4-byte boundary.
            off = val_start + len.div_ceil(4) * 4;
        }
        if iface.ts_resolution == 0 {
            iface.ts_resolution = 1_000_000;
        }
        Ok(iface)
    }

    fn parse_epb(&mut self, body: &[u8]) -> Result<RawPacket, CaptureError> {
        if body.len() < 20 {
            return Err(CaptureError::Malformed(
                "enhanced packet block is too short".into(),
            ));
        }
        let iface_id = self.u32_from(&body[0..4]) as usize;
        let ts_high = self.u32_from(&body[4..8]) as u64;
        let ts_low = self.u32_from(&body[8..12]) as u64;
        let caplen = self.u32_from(&body[12..16]);
        let wirelen = self.u32_from(&body[16..20]);

        self.index += 1;
        if caplen > MAX_PACKET_BYTES {
            return Err(CaptureError::ImplausibleLength {
                index: self.index,
                len: caplen,
                limit: MAX_PACKET_BYTES,
            });
        }
        let end = 20 + caplen as usize;
        if end > body.len() {
            return Err(CaptureError::Malformed(format!(
                "packet {} claims {caplen} bytes but its block holds {}",
                self.index,
                body.len() - 20
            )));
        }

        let resolution = self
            .interfaces
            .get(iface_id)
            .map(|i| i.ts_resolution)
            .unwrap_or(1_000_000);
        let ticks = (ts_high << 32) | ts_low;
        let secs = (ticks / resolution) as i64;
        let frac = ticks % resolution;
        // Scale the fractional part to nanoseconds without overflowing.
        let nanos = ((frac as u128 * 1_000_000_000u128) / resolution as u128) as u32;

        Ok(RawPacket::new(
            self.index,
            Timestamp::new(secs, nanos),
            wirelen.max(caplen),
            body[20..end].to_vec(),
        ))
    }

    // --- helpers ---------------------------------------------------------

    fn u32_from(&self, b: &[u8]) -> u32 {
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if self.big_endian {
            v.swap_bytes()
        } else {
            v
        }
    }

    fn u16_from(&self, b: &[u8]) -> u16 {
        let v = u16::from_le_bytes([b[0], b[1]]);
        if self.big_endian {
            v.swap_bytes()
        } else {
            v
        }
    }

    fn skip(&mut self, n: usize) -> Result<(), CaptureError> {
        let mut remaining = n;
        let mut buf = [0u8; 4096];
        while remaining > 0 {
            let take = remaining.min(buf.len());
            self.reader.read_exact(&mut buf[..take])?;
            remaining -= take;
        }
        Ok(())
    }
}

impl Source for FileSource {
    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn next_packet(&mut self) -> Option<Result<RawPacket, CaptureError>> {
        if self.finished {
            return None;
        }
        match self.format {
            FileFormat::Pcap => self.next_pcap(),
            FileFormat::PcapNg => self.next_pcapng(),
        }
    }

    fn description(&self) -> String {
        format!(
            "{} ({}, {})",
            self.path.display(),
            match self.format {
                FileFormat::Pcap => "pcap",
                FileFormat::PcapNg => "pcapng",
            },
            self.link_type.name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::PcapWriter;
    use std::io::Write;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cbna-test-{}-{name}", std::process::id()));
        p
    }

    fn sample_frame(n: u8) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, n]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        f.extend_from_slice(&[0; 16]);
        f
    }

    #[test]
    fn round_trips_a_written_pcap() {
        let path = temp_path("roundtrip.pcap");
        {
            let mut w = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            for i in 0..5u8 {
                w.write(&RawPacket::new(
                    i as u64,
                    Timestamp::new(1_786_365_296 + i as i64, 500_000_000),
                    64,
                    sample_frame(i),
                ))
                .unwrap();
            }
        }

        let mut src = FileSource::open(&path).unwrap();
        assert_eq!(src.format(), FileFormat::Pcap);
        assert_eq!(src.link_type(), LinkType::Ethernet);

        let packets: Vec<RawPacket> = std::iter::from_fn(|| src.next_packet())
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0].meta.index, 1);
        assert_eq!(packets[0].meta.timestamp.secs, 1_786_365_296);
        assert_eq!(packets[0].meta.timestamp.nanos, 500_000_000);
        assert_eq!(packets[4].data, sample_frame(4));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reads_big_endian_pcap() {
        let path = temp_path("be.pcap");
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PCAP_MAGIC_BE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes()); // version major
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_be_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_be_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_be_bytes()); // ethernet
        let frame = sample_frame(7);
        buf.extend_from_slice(&100u32.to_be_bytes()); // ts sec
        buf.extend_from_slice(&250_000u32.to_be_bytes()); // ts usec
        buf.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        buf.extend_from_slice(&frame);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&buf)
            .unwrap();

        let mut src = FileSource::open(&path).unwrap();
        let pkt = src.next_packet().unwrap().unwrap();
        assert_eq!(pkt.meta.timestamp.secs, 100);
        assert_eq!(pkt.meta.timestamp.nanos, 250_000_000);
        assert_eq!(pkt.data, frame);
        assert!(src.next_packet().is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reads_pcapng_with_nanosecond_resolution() {
        let path = temp_path("ng.pcapng");
        let mut buf: Vec<u8> = Vec::new();

        // Section header block
        buf.extend_from_slice(&PCAPNG_BLOCK_SHB.to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());

        // Interface description block with if_tsresol = 9 (nanoseconds)
        buf.extend_from_slice(&BLOCK_IDB.to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // ethernet
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&9u16.to_le_bytes()); // opt if_tsresol
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&[9, 0, 0, 0]); // value + padding
        buf.extend_from_slice(&28u32.to_le_bytes());

        // Enhanced packet block
        let frame = sample_frame(3);
        let padded = frame.len().div_ceil(4) * 4;
        let epb_len = 32 + padded as u32;
        let ticks: u64 = 1_786_365_296_000_000_000 + 125_000_000;
        buf.extend_from_slice(&BLOCK_EPB.to_le_bytes());
        buf.extend_from_slice(&epb_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // interface id
        buf.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        buf.extend_from_slice(&(ticks as u32).to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(&frame);
        buf.extend_from_slice(&vec![0u8; padded - frame.len()]);
        buf.extend_from_slice(&epb_len.to_le_bytes());

        std::fs::File::create(&path)
            .unwrap()
            .write_all(&buf)
            .unwrap();

        let mut src = FileSource::open(&path).unwrap();
        assert_eq!(src.format(), FileFormat::PcapNg);
        assert_eq!(src.link_type(), LinkType::Ethernet);
        let pkt = src.next_packet().unwrap().unwrap();
        assert_eq!(pkt.meta.timestamp.secs, 1_786_365_296);
        assert_eq!(pkt.meta.timestamp.nanos, 125_000_000);
        assert_eq!(pkt.data, frame);
        assert!(src.next_packet().is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_a_file_that_is_not_a_capture() {
        let path = temp_path("notacapture.bin");
        std::fs::write(&path, b"this is just some text, not a capture at all").unwrap();
        let err = FileSource::open(&path).unwrap_err();
        assert!(matches!(err, CaptureError::UnknownFormat(_, _)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_an_implausible_packet_length() {
        let path = temp_path("huge.pcap");
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&[2, 0, 4, 0]);
        buf.extend_from_slice(&[0; 8]);
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // caplen
        buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&buf)
            .unwrap();

        let mut src = FileSource::open(&path).unwrap();
        let err = src.next_packet().unwrap().unwrap_err();
        assert!(matches!(err, CaptureError::ImplausibleLength { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_final_packet_ends_the_stream_cleanly() {
        let path = temp_path("cutoff.pcap");
        {
            let mut w = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            w.write(&RawPacket::new(
                1,
                Timestamp::new(1, 0),
                64,
                sample_frame(1),
            ))
            .unwrap();
            w.write(&RawPacket::new(
                2,
                Timestamp::new(2, 0),
                64,
                sample_frame(2),
            ))
            .unwrap();
        }
        // Lop off the tail of the second packet.
        let mut data = std::fs::read(&path).unwrap();
        data.truncate(data.len() - 10);
        std::fs::write(&path, &data).unwrap();

        let mut src = FileSource::open(&path).unwrap();
        let mut count = 0;
        while let Some(r) = src.next_packet() {
            r.expect("no error should surface for a clean cut-off");
            count += 1;
        }
        assert_eq!(count, 1);
        let _ = std::fs::remove_file(&path);
    }
}
