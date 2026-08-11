//! DNS message decoding, including name decompression.

use crate::bytes::Reader;
use crate::error::{DecodeError, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    /// Rendered rdata for the types we understand, else a byte-length note.
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub recursion_desired: bool,
    pub truncated: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    /// Authority and additional counts, kept as counts only.
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsMessage {
    /// The name being asked about, which is what analysis keys on.
    pub fn primary_name(&self) -> Option<&str> {
        self.questions.first().map(|q| q.name.as_str())
    }

    pub fn rcode_name(&self) -> &'static str {
        match self.rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "OTHER",
        }
    }
}

pub fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        48 => "DNSKEY",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        _ => "TYPE",
    }
}

/// Parse a DNS message from a complete UDP payload (or a TCP payload with the
/// 2-byte length prefix already stripped).
///
/// Returns `None` when the buffer is clearly not DNS, so callers can fall
/// through to other decoders.
pub fn parse(buf: &[u8]) -> Option<DnsMessage> {
    parse_strict(buf).ok()
}

pub fn parse_strict(buf: &[u8]) -> Result<DnsMessage> {
    let mut r = Reader::new(buf, "dns");
    let transaction_id = r.be_u16()?;
    let flags = r.be_u16()?;
    let qdcount = r.be_u16()?;
    let ancount = r.be_u16()?;
    let nscount = r.be_u16()?;
    let arcount = r.be_u16()?;

    let opcode = ((flags >> 11) & 0x0F) as u8;
    if opcode > 5 {
        return Err(DecodeError::malformed("dns", "reserved opcode"));
    }
    // Sanity bound: a legitimate message will not claim thousands of records
    // in a single datagram, and this stops us allocating on random payloads.
    if qdcount > 64 || ancount > 512 {
        return Err(DecodeError::malformed("dns", "implausible record counts"));
    }

    let mut offset = r.position();
    let mut questions = Vec::with_capacity(qdcount.min(8) as usize);
    for _ in 0..qdcount {
        let (name, next) = read_name(buf, offset)?;
        let mut q = Reader::new(&buf[next..], "dns question");
        let qtype = q.be_u16()?;
        let qclass = q.be_u16()?;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
        offset = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount.min(8) as usize);
    for _ in 0..ancount {
        match read_record(buf, offset) {
            Ok((rec, next)) => {
                answers.push(rec);
                offset = next;
            }
            // A truncated answer section is common with snaplen-limited
            // captures; keep whatever parsed cleanly.
            Err(_) => break,
        }
    }

    Ok(DnsMessage {
        transaction_id,
        is_response: flags & 0x8000 != 0,
        opcode,
        rcode: (flags & 0x000F) as u8,
        recursion_desired: flags & 0x0100 != 0,
        truncated: flags & 0x0200 != 0,
        questions,
        answers,
        authority_count: nscount,
        additional_count: arcount,
    })
}

fn read_record(msg: &[u8], offset: usize) -> Result<(DnsRecord, usize)> {
    let (name, after_name) = read_name(msg, offset)?;
    let mut r = Reader::new(&msg[after_name.min(msg.len())..], "dns record");
    let rtype = r.be_u16()?;
    let _class = r.be_u16()?;
    let ttl = r.be_u32()?;
    let rdlength = r.be_u16()? as usize;
    let rdata_start = after_name + 10;
    let rdata = r.take(rdlength)?;

    let data = render_rdata(msg, rtype, rdata, rdata_start);
    Ok((
        DnsRecord {
            name,
            rtype,
            ttl,
            data,
        },
        rdata_start + rdlength,
    ))
}

fn render_rdata(msg: &[u8], rtype: u16, rdata: &[u8], rdata_start: usize) -> String {
    match rtype {
        1 if rdata.len() == 4 => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        28 if rdata.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rdata);
            Ipv6Addr::from(o).to_string()
        }
        // Names in rdata may use compression pointers into the whole message,
        // so resolve them against `msg` rather than the rdata slice.
        2 | 5 | 12 => read_name(msg, rdata_start)
            .map(|(n, _)| n)
            .unwrap_or_else(|_| "<malformed>".into()),
        15 if rdata.len() > 2 => read_name(msg, rdata_start + 2)
            .map(|(n, _)| format!("{} pref={}", n, u16::from_be_bytes([rdata[0], rdata[1]])))
            .unwrap_or_else(|_| "<malformed>".into()),
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rdata.len() {
                let len = rdata[i] as usize;
                if i + 1 + len > rdata.len() {
                    break;
                }
                parts.push(String::from_utf8_lossy(&rdata[i + 1..i + 1 + len]).into_owned());
                i += 1 + len;
            }
            parts.join(" ")
        }
        _ => format!("<{} bytes>", rdata.len()),
    }
}

/// Read a (possibly compressed) domain name, returning the name and the offset
/// just past the name in the *original* position — i.e. past the pointer if one
/// was taken, per RFC 1035 §4.1.4.
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut offset = start;
    let mut after_first_pointer: Option<usize> = None;
    let mut jumps = 0;

    loop {
        if offset >= msg.len() {
            return Err(DecodeError::Truncated {
                layer: "dns name",
                need: 1,
                have: 0,
            });
        }
        let len = msg[offset];

        if len & 0xC0 == 0xC0 {
            if offset + 1 >= msg.len() {
                return Err(DecodeError::malformed("dns name", "truncated pointer"));
            }
            let target = (((len & 0x3F) as usize) << 8) | msg[offset + 1] as usize;
            after_first_pointer.get_or_insert(offset + 2);
            jumps += 1;
            // Bound both the jump count and the target so a self-referential
            // or cyclic pointer chain terminates.
            if jumps > 16 || target >= msg.len() || target >= offset {
                return Err(DecodeError::malformed(
                    "dns name",
                    "cyclic compression pointer",
                ));
            }
            offset = target;
            continue;
        }

        if len & 0xC0 != 0 {
            return Err(DecodeError::malformed("dns name", "reserved label type"));
        }

        if len == 0 {
            offset += 1;
            break;
        }

        let l = len as usize;
        if offset + 1 + l > msg.len() {
            return Err(DecodeError::Truncated {
                layer: "dns name",
                need: l,
                have: msg.len().saturating_sub(offset + 1),
            });
        }
        labels.push(&msg[offset + 1..offset + 1 + l]);
        offset += 1 + l;

        if labels.len() > 127 {
            return Err(DecodeError::malformed("dns name", "too many labels"));
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels
            .iter()
            .map(|l| String::from_utf8_lossy(l))
            .collect::<Vec<_>>()
            .join(".")
    };

    Ok((name, after_first_pointer.unwrap_or(offset)))
}

/// Registrable-ish suffix: the last two labels. Not PSL-accurate, but enough to
/// group `a.b.evil.com` and `c.d.evil.com` for subdomain-volume analysis.
pub fn parent_domain(name: &str) -> String {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Query for www.example.com A.
    fn query() -> Vec<u8> {
        let mut b = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        b.push(3);
        b.extend_from_slice(b"www");
        b.push(7);
        b.extend_from_slice(b"example");
        b.push(3);
        b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        b
    }

    #[test]
    fn parses_query() {
        let m = parse(&query()).unwrap();
        assert_eq!(m.transaction_id, 0x1234);
        assert!(!m.is_response);
        assert!(m.recursion_desired);
        assert_eq!(m.questions.len(), 1);
        assert_eq!(m.primary_name(), Some("www.example.com"));
        assert_eq!(m.questions[0].qtype, 1);
    }

    #[test]
    fn parses_response_with_compression() {
        let mut b = query();
        b[2] = 0x81; // response
        b[3] = 0x80;
        b[7] = 0x01; // ancount = 1
                     // answer: pointer to offset 12, A, IN, ttl 300, 4 bytes 93.184.216.34
        b.extend_from_slice(&[0xc0, 0x0c]);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        b.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
        b.extend_from_slice(&[0x00, 0x04]);
        b.extend_from_slice(&[93, 184, 216, 34]);

        let m = parse(&b).unwrap();
        assert!(m.is_response);
        assert_eq!(m.rcode_name(), "NOERROR");
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].name, "www.example.com");
        assert_eq!(m.answers[0].data, "93.184.216.34");
        assert_eq!(m.answers[0].ttl, 300);
    }

    #[test]
    fn rejects_cyclic_pointer() {
        // A name whose pointer targets itself must not hang the decoder.
        let msg = [0x00u8, 0x00, 0xc0, 0x02];
        assert!(read_name(&msg, 2).is_err());
    }

    #[test]
    fn rejects_non_dns_payload() {
        assert!(parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn groups_by_parent_domain() {
        assert_eq!(parent_domain("a.b.c.evil.com"), "evil.com");
        assert_eq!(parent_domain("evil.com"), "evil.com");
        assert_eq!(parent_domain("localhost"), "localhost");
    }
}
