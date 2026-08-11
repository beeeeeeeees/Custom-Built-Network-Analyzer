//! Layer 3: IPv4, IPv6 (with extension-header walking), ICMP and ICMPv6.

use crate::bytes::Reader;
use crate::error::{DecodeError, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod proto_num {
    pub const HOPOPT: u8 = 0;
    pub const ICMP: u8 = 1;
    pub const IGMP: u8 = 2;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ROUTE: u8 = 43;
    pub const IPV6_FRAG: u8 = 44;
    pub const GRE: u8 = 47;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const ICMPV6: u8 = 58;
    pub const IPV6_NONXT: u8 = 59;
    pub const IPV6_OPTS: u8 = 60;
    pub const SCTP: u8 = 132;
}

/// Human label for an IP protocol number, for display only.
pub fn proto_name(p: u8) -> &'static str {
    use proto_num::*;
    match p {
        ICMP => "ICMP",
        IGMP => "IGMP",
        TCP => "TCP",
        UDP => "UDP",
        GRE => "GRE",
        ESP => "ESP",
        AH => "AH",
        ICMPV6 => "ICMPv6",
        SCTP => "SCTP",
        _ => "IP",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub total_len: u16,
    pub header_len: u8,
    pub checksum: u16,
    /// True when this datagram is any piece of a fragmented original.
    pub fragmented: bool,
}

impl Ipv4 {
    /// Only the first fragment carries a transport header.
    pub fn has_transport_header(&self) -> bool {
        self.fragment_offset == 0
    }
}

/// Parse an IPv4 header, returning the payload trimmed to the header's own
/// total-length field so Ethernet padding never leaks upward.
pub fn parse_ipv4(buf: &[u8]) -> Result<(Ipv4, &[u8])> {
    let mut r = Reader::new(buf, "ipv4");
    let vhl = r.u8()?;
    let version = vhl >> 4;
    if version != 4 {
        return Err(DecodeError::malformed("ipv4", "version nibble is not 4"));
    }
    let ihl = vhl & 0x0F;
    if ihl < 5 {
        return Err(DecodeError::malformed(
            "ipv4",
            "IHL below the 20-byte minimum",
        ));
    }
    let header_len = ihl as usize * 4;

    let tos = r.u8()?;
    let total_len = r.be_u16()?;
    let identification = r.be_u16()?;
    let flags_frag = r.be_u16()?;
    let ttl = r.u8()?;
    let protocol = r.u8()?;
    let checksum = r.be_u16()?;
    let src = Ipv4Addr::from(r.array::<4>()?);
    let dst = Ipv4Addr::from(r.array::<4>()?);

    // Skip options; `header_len` was validated to be >= 20.
    r.skip(header_len - 20)?;

    let more_fragments = flags_frag & 0x2000 != 0;
    let fragment_offset = (flags_frag & 0x1FFF) * 8;

    // total_len covers header + payload. A zero value shows up with TSO/LRO
    // offload captures, where the NIC has not yet filled it in.
    if total_len as usize > header_len {
        r.limit(total_len as usize - header_len);
    }

    let header = Ipv4 {
        src,
        dst,
        protocol,
        ttl,
        dscp: tos >> 2,
        ecn: tos & 0x03,
        identification,
        dont_fragment: flags_frag & 0x4000 != 0,
        more_fragments,
        fragment_offset,
        total_len,
        header_len: header_len as u8,
        checksum,
        fragmented: more_fragments || fragment_offset > 0,
    };
    Ok((header, r.rest()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6 {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// Protocol of the first non-extension header.
    pub next_header: u8,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_len: u16,
    /// Number of extension headers walked before the transport header.
    pub extension_headers: u8,
    pub fragmented: bool,
    pub fragment_offset: u16,
}

impl Ipv6 {
    pub fn has_transport_header(&self) -> bool {
        self.fragment_offset == 0
    }
}

/// Parse an IPv6 header and walk the extension-header chain to the transport
/// header. Encrypted payloads (ESP) and `NoNextHeader` terminate the walk.
pub fn parse_ipv6(buf: &[u8]) -> Result<(Ipv6, &[u8])> {
    use proto_num::*;

    let mut r = Reader::new(buf, "ipv6");
    let vtf = r.be_u32()?;
    if vtf >> 28 != 6 {
        return Err(DecodeError::malformed("ipv6", "version nibble is not 6"));
    }
    let payload_len = r.be_u16()?;
    let mut next_header = r.u8()?;
    let hop_limit = r.u8()?;
    let src = Ipv6Addr::from(r.array::<16>()?);
    let dst = Ipv6Addr::from(r.array::<16>()?);

    if payload_len > 0 {
        r.limit(payload_len as usize);
    }

    let mut extension_headers = 0u8;
    let mut fragmented = false;
    let mut fragment_offset = 0u16;

    // Bounded walk: a crafted chain of zero-length options must not loop.
    for _ in 0..16 {
        match next_header {
            HOPOPT | IPV6_ROUTE | IPV6_OPTS => {
                let nh = r.u8()?;
                let len = r.u8()? as usize; // in 8-octet units, not counting first 8
                r.skip(6 + len * 8)?;
                next_header = nh;
                extension_headers += 1;
            }
            IPV6_FRAG => {
                let nh = r.u8()?;
                r.skip(1)?;
                let off_flags = r.be_u16()?;
                r.skip(4)?; // identification
                fragmented = true;
                fragment_offset = (off_flags >> 3) * 8;
                next_header = nh;
                extension_headers += 1;
                if fragment_offset > 0 {
                    break; // no transport header in later fragments
                }
            }
            AH => {
                let nh = r.u8()?;
                // Total AH length is (len + 2) * 4; two bytes are already read.
                let len = r.u8()? as usize;
                r.skip(len * 4 + 6)?;
                next_header = nh;
                extension_headers += 1;
            }
            _ => break,
        }
    }

    let header = Ipv6 {
        src,
        dst,
        next_header,
        hop_limit,
        traffic_class: ((vtf >> 20) & 0xFF) as u8,
        flow_label: vtf & 0x000F_FFFF,
        payload_len,
        extension_headers,
        fragmented,
        fragment_offset,
    };
    Ok((header, r.rest()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Icmp {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    /// Echo identifier, when the type carries one.
    pub echo_id: Option<u16>,
    pub echo_seq: Option<u16>,
    pub v6: bool,
    pub payload_len: usize,
}

impl Icmp {
    pub fn description(&self) -> &'static str {
        if self.v6 {
            match self.icmp_type {
                1 => "destination unreachable",
                2 => "packet too big",
                3 => "time exceeded",
                4 => "parameter problem",
                128 => "echo request",
                129 => "echo reply",
                133 => "router solicitation",
                134 => "router advertisement",
                135 => "neighbor solicitation",
                136 => "neighbor advertisement",
                _ => "icmpv6",
            }
        } else {
            match self.icmp_type {
                0 => "echo reply",
                3 => "destination unreachable",
                5 => "redirect",
                8 => "echo request",
                11 => "time exceeded",
                13 => "timestamp request",
                14 => "timestamp reply",
                _ => "icmp",
            }
        }
    }

    /// Types that are normal for hosts to emit but are also the transport for
    /// tunnelling tools when paired with an oversized payload.
    pub fn is_echo(&self) -> bool {
        if self.v6 {
            matches!(self.icmp_type, 128 | 129)
        } else {
            matches!(self.icmp_type, 0 | 8)
        }
    }
}

pub fn parse_icmp(buf: &[u8], v6: bool) -> Result<Icmp> {
    let mut r = Reader::new(buf, if v6 { "icmpv6" } else { "icmp" });
    let icmp_type = r.u8()?;
    let code = r.u8()?;
    let checksum = r.be_u16()?;

    let echo = if v6 {
        matches!(icmp_type, 128 | 129)
    } else {
        matches!(icmp_type, 0 | 8)
    };
    let (echo_id, echo_seq) = if echo {
        (Some(r.be_u16()?), Some(r.be_u16()?))
    } else {
        (None, None)
    };

    Ok(Icmp {
        icmp_type,
        code,
        checksum,
        echo_id,
        echo_seq,
        v6,
        payload_len: r.remaining(),
    })
}

/// True for addresses that are not globally routable, used to classify a flow
/// as internal, egress, ingress, or external.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // unique local fc00::/7
                || (v6.octets()[0] & 0xFE) == 0xFC
                // link local fe80::/10
                || (v6.octets()[0] == 0xFE && (v6.octets()[1] & 0xC0) == 0x80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(total_len: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![
            0x45,
            0x00, // version/ihl, tos
            (total_len >> 8) as u8,
            total_len as u8,
            0xab,
            0xcd, // id
            0x40,
            0x00, // DF, offset 0
            0x40, // ttl 64
            0x06, // tcp
            0x00,
            0x00, // checksum
        ];
        b.extend_from_slice(&[10, 0, 0, 1]);
        b.extend_from_slice(&[10, 0, 0, 2]);
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn parses_ipv4_and_trims_padding() {
        // total_len says 24 (20 header + 4 payload) but the frame carries 8
        // bytes of Ethernet padding beyond that.
        let frame = ipv4_frame(24, &[1, 2, 3, 4, 0, 0, 0, 0]);
        let (ip, payload) = parse_ipv4(&frame).unwrap();
        assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, proto_num::TCP);
        assert!(ip.dont_fragment);
        assert!(!ip.fragmented);
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn flags_later_fragments() {
        let mut frame = ipv4_frame(28, &[9; 8]);
        frame[6] = 0x00;
        frame[7] = 0xB9; // offset 185*8 = 1480
        let (ip, _) = parse_ipv4(&frame).unwrap();
        assert!(ip.fragmented);
        assert_eq!(ip.fragment_offset, 1480);
        assert!(!ip.has_transport_header());
    }

    #[test]
    fn rejects_bad_version_and_ihl() {
        let mut frame = ipv4_frame(24, &[0; 4]);
        frame[0] = 0x64; // version 6 in an ipv4 slot
        assert!(parse_ipv4(&frame).is_err());
        frame[0] = 0x44; // ihl 4
        assert!(parse_ipv4(&frame).is_err());
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let mut b = vec![0x60, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0x00, 0x10]); // payload len 16
        b.push(proto_num::HOPOPT);
        b.push(64); // hop limit
        b.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        b.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // hop-by-hop: next=UDP, len=0 (8 bytes total)
        b.push(proto_num::UDP);
        b.push(0);
        b.extend_from_slice(&[0; 6]);
        b.extend_from_slice(&[0xaa; 8]); // udp-ish payload

        let (ip6, payload) = parse_ipv6(&b).unwrap();
        assert_eq!(ip6.next_header, proto_num::UDP);
        assert_eq!(ip6.extension_headers, 1);
        assert_eq!(ip6.hop_limit, 64);
        assert_eq!(payload, &[0xaa; 8]);
    }

    #[test]
    fn parses_icmp_echo() {
        let icmp = parse_icmp(&[8, 0, 0xff, 0xff, 0x12, 0x34, 0x00, 0x01, 1, 2, 3], false).unwrap();
        assert!(icmp.is_echo());
        assert_eq!(icmp.echo_id, Some(0x1234));
        assert_eq!(icmp.payload_len, 3);
        assert_eq!(icmp.description(), "echo request");
    }

    #[test]
    fn classifies_private_space() {
        assert!(is_private("192.168.1.5".parse().unwrap()));
        assert!(is_private("fe80::1".parse().unwrap()));
        assert!(!is_private("8.8.8.8".parse().unwrap()));
        assert!(!is_private("2606:4700::1".parse().unwrap()));
    }
}
