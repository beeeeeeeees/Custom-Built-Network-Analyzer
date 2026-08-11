//! Writes a synthetic pcap exercising every detector, so the analyzer can be
//! demonstrated and regression-checked without needing a real capture.
//!
//!     cargo run -p cbna --example make-sample -- samples/demo.pcap

use cbna_capture::{PcapWriter, RawPacket};
use cbna_core::packet::LinkType;
use cbna_core::Timestamp;

const BASE: i64 = 1_786_365_296; // 2026-08-10T12:34:56Z

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "samples/demo.pcap".to_string());
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut packets: Vec<(f64, Vec<u8>)> = Vec::new();

    // 1. Ordinary browsing: DNS lookup then a TLS session.
    for (i, host) in ["www.example.com", "cdn.example.net", "api.example.org"]
        .iter()
        .enumerate()
    {
        let t = i as f64 * 0.4;
        packets.push((
            t,
            dns_query(0x1000 + i as u16, host, [192, 168, 1, 50], [192, 168, 1, 1]),
        ));
        packets.push((
            t + 0.02,
            dns_response(
                0x1000 + i as u16,
                host,
                [192, 168, 1, 1],
                [192, 168, 1, 50],
                [93, 184, 216, 34],
            ),
        ));
        packets.push((
            t + 0.05,
            tcp(
                &[192, 168, 1, 50],
                40000 + i as u16,
                &[93, 184, 216, 34],
                443,
                SYN,
                &[],
            ),
        ));
        packets.push((
            t + 0.07,
            tcp(
                &[93, 184, 216, 34],
                443,
                &[192, 168, 1, 50],
                40000 + i as u16,
                SYN | ACK,
                &[],
            ),
        ));
        packets.push((
            t + 0.09,
            tcp(
                &[192, 168, 1, 50],
                40000 + i as u16,
                &[93, 184, 216, 34],
                443,
                PSH | ACK,
                &client_hello(host),
            ),
        ));
        for chunk in 0..12 {
            packets.push((
                t + 0.2 + chunk as f64 * 0.01,
                tcp(
                    &[93, 184, 216, 34],
                    443,
                    &[192, 168, 1, 50],
                    40000 + i as u16,
                    PSH | ACK,
                    &[0x17; 1200],
                ),
            ));
        }
    }

    // 2. A beacon: 60-second check-ins with light jitter, to 203.0.113.10.
    for i in 0..25 {
        let t = 5.0 + i as f64 * 60.0 + if i % 2 == 0 { 1.5 } else { -1.4 };
        packets.push((
            t,
            tcp(
                &[192, 168, 1, 77],
                51000,
                &[203, 0, 113, 10],
                8443,
                PSH | ACK,
                &[0xAB; 128],
            ),
        ));
        packets.push((
            t + 0.15,
            tcp(
                &[203, 0, 113, 10],
                8443,
                &[192, 168, 1, 77],
                51000,
                PSH | ACK,
                &[0xCD; 64],
            ),
        ));
    }

    // 3. DNS tunnelling: many high-entropy subdomains under one parent.
    for i in 0..60 {
        let label = format!(
            "k{:x}v{:x}z{:x}q{:x}",
            i * 7919,
            i * 104729,
            i * 15485863u64,
            i * 3
        );
        let name = format!("{label}.exfil.example");
        packets.push((
            300.0 + i as f64 * 0.5,
            dns_query(
                0x4000 + i as u16,
                &name,
                [192, 168, 1, 77],
                [192, 168, 1, 1],
            ),
        ));
    }

    // 4. A port scan: SYNs across many ports on one host, none answered.
    for (i, port) in [
        21u16, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432,
        5985, 8080,
    ]
    .iter()
    .enumerate()
    {
        packets.push((
            700.0 + i as f64 * 0.05,
            tcp(
                &[192, 168, 1, 66],
                44000 + i as u16,
                &[192, 168, 1, 20],
                *port,
                SYN,
                &[],
            ),
        ));
    }

    // 5. Cleartext HTTP with Basic auth.
    let req = b"GET /admin/config HTTP/1.1\r\n\
                Host: legacy.corp.local\r\n\
                User-Agent: python-requests/2.31.0\r\n\
                Authorization: Basic YWRtaW46aHVudGVyMg==\r\n\
                Accept: */*\r\n\r\n";
    packets.push((
        800.0,
        tcp(&[192, 168, 1, 50], 45000, &[192, 168, 1, 30], 80, SYN, &[]),
    ));
    packets.push((
        800.02,
        tcp(
            &[192, 168, 1, 30],
            80,
            &[192, 168, 1, 50],
            45000,
            SYN | ACK,
            &[],
        ),
    ));
    packets.push((
        800.04,
        tcp(
            &[192, 168, 1, 50],
            45000,
            &[192, 168, 1, 30],
            80,
            PSH | ACK,
            req,
        ),
    ));
    packets.push((
        800.1,
        tcp(
            &[192, 168, 1, 30],
            80,
            &[192, 168, 1, 50],
            45000,
            PSH | ACK,
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.6\r\nContent-Length: 42\r\n\r\n",
        ),
    ));

    // 6. Upload-heavy outbound flow.
    packets.push((
        900.0,
        tcp(&[192, 168, 1, 88], 46000, &[198, 51, 100, 5], 443, SYN, &[]),
    ));
    packets.push((
        900.02,
        tcp(
            &[198, 51, 100, 5],
            443,
            &[192, 168, 1, 88],
            46000,
            SYN | ACK,
            &[],
        ),
    ));
    for i in 0..4600 {
        packets.push((
            900.1 + i as f64 * 0.002,
            tcp(
                &[192, 168, 1, 88],
                46000,
                &[198, 51, 100, 5],
                443,
                PSH | ACK,
                &[0x5A; 1400],
            ),
        ));
    }
    for i in 0..120 {
        packets.push((
            900.2 + i as f64 * 0.05,
            tcp(
                &[198, 51, 100, 5],
                443,
                &[192, 168, 1, 88],
                46000,
                ACK,
                &[0x00; 60],
            ),
        ));
    }

    // 7. ARP conflict: two MACs answering for the gateway.
    packets.push((
        950.0,
        arp_reply([192, 168, 1, 1], [0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc]),
    ));
    packets.push((
        951.0,
        arp_reply([192, 168, 1, 1], [0x00, 0x0c, 0x29, 0xde, 0xad, 0xbe]),
    ));

    // 8. A legacy appliance still negotiating TLS 1.0.
    packets.push((
        960.0,
        tcp(&[192, 168, 1, 50], 47000, &[192, 168, 1, 40], 443, SYN, &[]),
    ));
    packets.push((
        960.02,
        tcp(
            &[192, 168, 1, 40],
            443,
            &[192, 168, 1, 50],
            47000,
            SYN | ACK,
            &[],
        ),
    ));
    packets.push((
        960.04,
        tcp(
            &[192, 168, 1, 50],
            47000,
            &[192, 168, 1, 40],
            443,
            PSH | ACK,
            &client_hello("legacy-vpn.corp.local"),
        ),
    ));
    packets.push((
        960.08,
        tcp(
            &[192, 168, 1, 40],
            443,
            &[192, 168, 1, 50],
            47000,
            PSH | ACK,
            // TLS_RSA_WITH_AES_128_CBC_SHA over TLS 1.0.
            &server_hello(0x0301, 0x002f),
        ),
    ));
    for i in 0..6 {
        packets.push((
            960.1 + i as f64 * 0.02,
            tcp(
                &[192, 168, 1, 40],
                443,
                &[192, 168, 1, 50],
                47000,
                PSH | ACK,
                &[0x17; 512],
            ),
        ));
    }

    // 9. Capture-quality caveats: a fragmented datagram the tool will not
    //    reassemble, and a burst that a short snaplen cut off mid-frame.
    let mut udp_frag = Vec::new();
    udp_frag.extend_from_slice(&40100u16.to_be_bytes());
    udp_frag.extend_from_slice(&9000u16.to_be_bytes());
    udp_frag.extend_from_slice(&1480u16.to_be_bytes());
    udp_frag.extend_from_slice(&[0x00, 0x00]);
    udp_frag.extend_from_slice(&[0x6b; 1472]);
    packets.push((
        970.0,
        ipv4_frag(&[192, 168, 1, 50], &[198, 51, 100, 9], 17, udp_frag, MF),
    ));
    // Offset 1480 bytes = 185 eight-byte units, and no MF: the last fragment.
    packets.push((
        970.001,
        ipv4_frag(
            &[192, 168, 1, 50],
            &[198, 51, 100, 9],
            17,
            vec![0x6b; 200],
            185,
        ),
    ));

    // Frames captured under a 96-byte snaplen: the wire length is honest, the
    // captured bytes stop short. Everything else in this file is captured whole.
    let mut clipped: Vec<(f64, Vec<u8>, u32)> = Vec::new();
    for i in 0..8 {
        let full = tcp(
            &[93, 184, 216, 34],
            443,
            &[192, 168, 1, 50],
            40000,
            PSH | ACK,
            &[0x17; 1400],
        );
        let wire_len = full.len() as u32;
        clipped.push((980.0 + i as f64 * 0.01, full[..96].to_vec(), wire_len));
    }

    let mut all: Vec<(f64, Vec<u8>, u32)> = packets
        .into_iter()
        .map(|(at, frame)| {
            let wire_len = frame.len() as u32;
            (at, frame, wire_len)
        })
        .chain(clipped)
        .collect();
    all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    let mut writer = PcapWriter::create(&path, LinkType::Ethernet)?;
    for (i, (offset, frame, wire_len)) in all.iter().enumerate() {
        let secs = BASE + offset.trunc() as i64;
        let nanos = (offset.fract() * 1e9) as u32;
        writer.write(&RawPacket::new(
            i as u64 + 1,
            Timestamp::new(secs, nanos),
            *wire_len,
            frame.clone(),
        ))?;
    }
    writer.flush()?;

    println!("Wrote {} packets to {path}", all.len());
    Ok(())
}

// --- frame builders -------------------------------------------------------

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;

fn ethernet(payload: Vec<u8>, ethertype: u16, src_last: u8) -> Vec<u8> {
    let mut f = vec![0x00, 0x50, 0x56, 0xc0, 0x00, 0x01];
    f.extend_from_slice(&[0x00, 0x0c, 0x29, 0x11, 0x22, src_last]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(&payload);
    f
}

fn ipv4(src: &[u8], dst: &[u8], protocol: u8, payload: Vec<u8>) -> Vec<u8> {
    ipv4_frag(src, dst, protocol, payload, DF)
}

/// Flags-and-fragment-offset word: `DF` for the ordinary case, `MF` for a
/// fragment with more to come, or a bare offset (in 8-byte units) for a
/// continuation fragment, which carries no transport header at all.
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;

fn ipv4_frag(src: &[u8], dst: &[u8], protocol: u8, payload: Vec<u8>, flags_frag: u16) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01]); // identification, shared by fragments
    ip.extend_from_slice(&flags_frag.to_be_bytes());
    ip.extend_from_slice(&[0x40, protocol, 0x00, 0x00]);
    ip.extend_from_slice(src);
    ip.extend_from_slice(dst);
    ip.extend_from_slice(&payload);
    ethernet(ip, 0x0800, src[3])
}

fn tcp(src: &[u8], sport: u16, dst: &[u8], dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // seq
    t.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]); // ack
    t.extend_from_slice(&[0x50, flags]);
    t.extend_from_slice(&[0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    t.extend_from_slice(payload);
    ipv4(src, dst, 6, t)
}

fn udp(src: &[u8], sport: u16, dst: &[u8], dport: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    u.extend_from_slice(&[0x00, 0x00]);
    u.extend_from_slice(&payload);
    ipv4(src, dst, 17, u)
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn dns_query(id: u16, name: &str, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&id.to_be_bytes());
    d.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    d.extend_from_slice(&encode_name(name));
    d.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    udp(&src, 53124, &dst, 53, d)
}

fn dns_response(id: u16, name: &str, src: [u8; 4], dst: [u8; 4], answer: [u8; 4]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&id.to_be_bytes());
    d.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    d.extend_from_slice(&encode_name(name));
    d.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    d.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
    d.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04]);
    d.extend_from_slice(&answer);
    udp(&src, 53, &dst, 53124, d)
}

fn arp_reply(ip: [u8; 4], mac: [u8; 6]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    a.extend_from_slice(&mac);
    a.extend_from_slice(&ip);
    a.extend_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x01]);
    a.extend_from_slice(&[192, 168, 1, 50]);
    ethernet(a, 0x0806, mac[5])
}

/// A ServerHello selecting `version` and one cipher, with no extensions — the
/// shape a pre-TLS-1.3 server actually sends. Because there is no
/// supported_versions extension to override it, the legacy version field is
/// the negotiated version, which is what `obsolete-tls` keys on.
fn server_hello(version: u16, cipher: u16) -> Vec<u8> {
    let mut hs = version.to_be_bytes().to_vec();
    hs.extend_from_slice(&[0x7a; 32]); // random
    hs.push(0x00); // empty session id
    hs.extend_from_slice(&cipher.to_be_bytes());
    hs.push(0x00); // null compression

    let mut handshake = vec![0x02];
    handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hs);

    let mut record = vec![0x16];
    record.extend_from_slice(&version.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A TLS 1.3 ClientHello carrying the given SNI, enough for JA3 extraction.
fn client_hello(sni: &str) -> Vec<u8> {
    let mut hs = vec![0x03, 0x03];
    hs.extend_from_slice(&[0x42; 32]);
    hs.push(0x00);
    hs.extend_from_slice(&[0x00, 0x08]);
    hs.extend_from_slice(&[0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
    hs.extend_from_slice(&[0x01, 0x00]);

    let mut exts = Vec::new();
    let host = sni.as_bytes();
    let mut sni_list = vec![0x00];
    sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(host);
    let mut sni_ext = (sni_list.len() as u16).to_be_bytes().to_vec();
    sni_ext.extend_from_slice(&sni_list);
    exts.extend_from_slice(&[0x00, 0x00]);
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);

    let mut alpn = vec![2u8];
    alpn.extend_from_slice(b"h2");
    alpn.push(8);
    alpn.extend_from_slice(b"http/1.1");
    let mut alpn_ext = (alpn.len() as u16).to_be_bytes().to_vec();
    alpn_ext.extend_from_slice(&alpn);
    exts.extend_from_slice(&[0x00, 0x10]);
    exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&alpn_ext);

    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

    hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs.extend_from_slice(&exts);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hs);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
