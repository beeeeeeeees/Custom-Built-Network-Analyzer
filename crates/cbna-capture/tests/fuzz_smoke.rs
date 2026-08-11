//! Deterministic stand-in for the `capture_file` libFuzzer target.
//!
//! Same arrangement as `cbna-core`'s: it drives `cbna_capture::fuzz::capture_file`,
//! the exact body the nightly fuzzer runs, over a fixed corpus so the contract
//! is checked on stable.
//!
//! The seeds are hand-built rather than produced by `PcapWriter`, because the
//! point is to mutate the header fields — magic, byte order, snaplen, block
//! lengths, `if_tsresol` — and a writer will only ever emit consistent ones.

use cbna_capture::fuzz::capture_file;
use cbna_core::fuzz::Mutator;

/// A 20-byte Ethernet frame, big enough to reach the IPv4 decoder.
fn frame() -> Vec<u8> {
    let mut f = vec![0xff; 12];
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&[0x45, 0x00, 0x00, 0x14, 0x00, 0x01]);
    f
}

/// Classic pcap. `big_endian` swaps the magic so the reader's byte-order
/// handling is in the corpus, and `nanos` selects the ns-resolution magic.
fn pcap(big_endian: bool, nanos: bool) -> Vec<u8> {
    let magic: u32 = match (big_endian, nanos) {
        (false, false) => 0xa1b2_c3d4,
        (false, true) => 0xa1b2_3c4d,
        (true, false) => 0xd4c3_b2a1,
        (true, true) => 0x4d3c_b2a1,
    };
    let mut out = magic.to_le_bytes().to_vec();

    let data = frame();
    let put16 = |o: &mut Vec<u8>, v: u16| {
        o.extend_from_slice(&if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        })
    };
    let put32 = |o: &mut Vec<u8>, v: u32| {
        o.extend_from_slice(&if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        })
    };

    put16(&mut out, 2); // version major
    put16(&mut out, 4); // version minor
    put32(&mut out, 0); // thiszone
    put32(&mut out, 0); // sigfigs
    put32(&mut out, 65535); // snaplen
    put32(&mut out, 1); // Ethernet

    for i in 0..3u32 {
        put32(&mut out, 1_786_365_296 + i); // ts secs
        put32(&mut out, 500_000); // ts frac
        put32(&mut out, data.len() as u32); // captured
        put32(&mut out, data.len() as u32 + 40); // wire — deliberately larger
        out.extend_from_slice(&data);
    }
    out
}

/// pcapng: section header, interface description, then enhanced packet blocks.
/// Every one of those carries a total-length field that appears twice and must
/// agree, which is exactly the kind of thing mutation breaks productively.
fn pcapng() -> Vec<u8> {
    let mut out = Vec::new();
    let data = frame();

    // Section Header Block
    out.extend_from_slice(&0x0a0d_0d0au32.to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());
    out.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes()); // byte-order magic
    out.extend_from_slice(&1u16.to_le_bytes()); // major
    out.extend_from_slice(&0u16.to_le_bytes()); // minor
    out.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
    out.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&20u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&20u32.to_le_bytes());

    // Enhanced Packet Blocks. Data is padded to a 4-byte boundary.
    for i in 0..3u32 {
        let pad = (4 - data.len() % 4) % 4;
        let total = 32 + data.len() + pad;
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // interface id
        out.extend_from_slice(&0u32.to_le_bytes()); // ts high
        out.extend_from_slice(&(1_000_000u32 + i).to_le_bytes()); // ts low
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // captured
        out.extend_from_slice(&(data.len() as u32 + 40).to_le_bytes()); // wire
        out.extend_from_slice(&data);
        out.extend(std::iter::repeat_n(0u8, pad));
        out.extend_from_slice(&(total as u32).to_le_bytes());
    }
    out
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        pcap(false, false),
        pcap(false, true),
        pcap(true, false),
        pcap(true, true),
        pcapng(),
        // Truncated mid-header, and a plausible magic with nothing behind it.
        pcap(false, false)[..12].to_vec(),
        0xa1b2_c3d4u32.to_le_bytes().to_vec(),
        Vec::new(),
    ]
}

#[test]
fn capture_file_never_panics() {
    let seeds = seeds();
    let mut rng = Mutator::new(0x243F_6A88_85A3_08D3);

    for s in &seeds {
        capture_file(s);
    }

    for _ in 0..20_000 {
        let seed = &seeds[rng.below(seeds.len())];
        let input = rng.mutate(seed);
        capture_file(&input);
    }

    for _ in 0..5_000 {
        capture_file(&rng.noise(2048));
    }
}

#[test]
fn well_formed_seeds_actually_parse() {
    // Guards the corpus itself: if a seed stops being a valid capture, the
    // mutation run above quietly degrades into testing the magic check and
    // nothing else.
    use cbna_capture::{FileSource, Source};

    for (i, s) in [pcap(false, false), pcap(true, false), pcapng()]
        .iter()
        .enumerate()
    {
        let mut src = FileSource::from_bytes(s).unwrap_or_else(|e| panic!("seed {i}: {e}"));
        let mut n = 0;
        while let Some(p) = src.next_packet() {
            p.unwrap_or_else(|e| panic!("seed {i} packet {n}: {e}"));
            n += 1;
        }
        assert_eq!(n, 3, "seed {i} should yield three packets");
    }
}
