//! Deterministic stand-in for the libFuzzer targets in `fuzz/`.
//!
//! Real coverage-guided fuzzing needs nightly and a sanitizer, which is not
//! something every contributor has set up. This runs the exact same entry
//! points — `cbna_core::fuzz::*` — over a fixed pseudo-random corpus so the
//! panic-freedom contract is checked on every `cargo test`, on stable, on any
//! platform.
//!
//! It is a smoke test, not a substitute: it explores far less than a real fuzz
//! run and it never grows its corpus. What it does buy is that a crash found by
//! the fuzzer can be pinned here as a seed and stay fixed forever.

use cbna_core::fuzz::{self, Mutator};

/// Seeds shaped like the real thing, so mutation starts from structure that
/// already reaches deep into the parsers instead of bouncing off the first
/// length check.
fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    // A DNS query with a compression pointer in the answer section.
    out.push(vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w',
        b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ]);

    // A pointer that points at itself — the classic decompression bomb.
    out.push(vec![
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01,
    ]);

    // A TLS record header with a ClientHello underneath.
    let mut tls = vec![
        0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x2a, 0x03, 0x03,
    ];
    tls.extend_from_slice(&[0x42; 32]);
    tls.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00]);
    out.push(tls);

    // An HTTP request with the headers the analyzer looks for.
    out.push(
        b"GET /a HTTP/1.1\r\nHost: h.example\r\nUser-Agent: x\r\nAuthorization: Basic dQ==\r\n\r\n"
            .to_vec(),
    );

    // An Ethernet + IPv4 + TCP frame, link-type byte in front.
    let mut eth = vec![0x01];
    eth.extend_from_slice(&[0xff; 12]);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 50,
        93, 184, 216, 34,
    ]);
    eth.extend_from_slice(&[
        0x9c, 0x40, 0x01, 0xbb, 0, 0, 0x10, 0, 0, 0, 0x20, 0, 0x50, 0x18, 0xfa, 0xf0, 0, 0, 0, 0,
    ]);
    out.push(eth);

    // An IPv6 frame with an extension-header chain to walk.
    let mut v6 = vec![0x01];
    v6.extend_from_slice(&[0xff; 12]);
    v6.extend_from_slice(&[0x86, 0xdd]);
    v6.extend_from_slice(&[0x60, 0, 0, 0, 0, 0x10, 0x2b, 0x40]);
    v6.extend_from_slice(&[0x20; 16]);
    v6.extend_from_slice(&[0x30; 16]);
    v6.extend_from_slice(&[0x06, 0x00, 0, 0, 0, 0, 0, 0]);
    out.push(v6);

    // Degenerate inputs that have historically broken length arithmetic.
    out.push(Vec::new());
    out.push(vec![0x00]);
    out.push(vec![0xff; 3]);
    out
}

fn run(target: fn(&[u8])) {
    let seeds = seeds();
    let mut rng = Mutator::new(0x9E37_79B9_7F4A_7C15);

    // Every seed verbatim first: these must pass before any mutation matters.
    for s in &seeds {
        target(s);
    }

    for _ in 0..20_000 {
        let seed = &seeds[rng.below(seeds.len())];
        let input = rng.mutate(seed);
        target(&input);
    }

    // Pure noise, including lengths that tempt an allocation.
    for _ in 0..5_000 {
        target(&rng.noise(1500));
    }
}

#[test]
fn decode_frame_never_panics() {
    run(fuzz::decode_frame);
}

#[test]
fn dns_message_never_panics() {
    run(fuzz::dns_message);
}

#[test]
fn tls_hello_never_panics() {
    run(fuzz::tls_hello);
}

#[test]
fn http_message_never_panics() {
    run(fuzz::http_message);
}
