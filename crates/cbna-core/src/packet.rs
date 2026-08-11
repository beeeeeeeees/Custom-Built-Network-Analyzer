//! Top-level decode: raw bytes plus capture metadata to a layered view.
//!
//! Decoding never fails outright. Anything we cannot parse is recorded as a
//! warning on the packet and the layers below it are still reported, because a
//! truncated capture should still produce flow-level truth.

use crate::error::Warning;
use crate::link::{self, Arp, Ethernet, MacAddr};
use crate::net::{self, proto_num, Icmp, Ipv4, Ipv6};
use crate::proto::{self, DnsMessage, HttpMessage, TlsHello};
use crate::time::Timestamp;
use crate::transport::{self, Tcp, Udp};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// pcap link-layer type (LINKTYPE_* values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    Null,
    Ethernet,
    Raw,
    LinuxSll,
    LinuxSll2,
    Loop,
    Other(u32),
}

impl LinkType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            12 | 14 | 101 => LinkType::Raw,
            108 => LinkType::Loop,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            other => LinkType::Other(other),
        }
    }

    pub fn name(&self) -> String {
        match self {
            LinkType::Null => "NULL/BSD loopback".into(),
            LinkType::Ethernet => "Ethernet".into(),
            LinkType::Raw => "Raw IP".into(),
            LinkType::LinuxSll => "Linux cooked v1".into(),
            LinkType::LinuxSll2 => "Linux cooked v2".into(),
            LinkType::Loop => "OpenBSD loopback".into(),
            LinkType::Other(v) => format!("LINKTYPE_{v}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketMeta {
    /// 1-based position in the capture.
    pub index: u64,
    pub timestamp: Timestamp,
    /// Bytes actually stored (may be less than `wire_len` under a snaplen).
    pub captured_len: u32,
    /// Bytes on the wire.
    pub wire_len: u32,
}

impl PacketMeta {
    pub fn is_truncated(&self) -> bool {
        self.captured_len < self.wire_len
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkLayer {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Arp(Arp),
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransportLayer {
    Tcp(Tcp),
    Udp(Udp),
    Icmp(Icmp),
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AppLayer {
    Dns(Box<DnsMessage>),
    Http(Box<HttpMessage>),
    Tls(Box<TlsHello>),
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedPacket {
    pub meta: PacketMeta,
    pub link: Option<Ethernet>,
    pub network: NetworkLayer,
    pub transport: TransportLayer,
    pub app: AppLayer,
    /// Bytes of transport payload present in the capture.
    pub payload_len: usize,
    pub warnings: Vec<String>,
}

impl DecodedPacket {
    pub fn src_ip(&self) -> Option<IpAddr> {
        match &self.network {
            NetworkLayer::Ipv4(h) => Some(IpAddr::V4(h.src)),
            NetworkLayer::Ipv6(h) => Some(IpAddr::V6(h.src)),
            _ => None,
        }
    }

    pub fn dst_ip(&self) -> Option<IpAddr> {
        match &self.network {
            NetworkLayer::Ipv4(h) => Some(IpAddr::V4(h.dst)),
            NetworkLayer::Ipv6(h) => Some(IpAddr::V6(h.dst)),
            _ => None,
        }
    }

    pub fn ip_protocol(&self) -> Option<u8> {
        match &self.network {
            NetworkLayer::Ipv4(h) => Some(h.protocol),
            NetworkLayer::Ipv6(h) => Some(h.next_header),
            _ => None,
        }
    }

    pub fn ports(&self) -> Option<(u16, u16)> {
        match &self.transport {
            TransportLayer::Tcp(t) => Some((t.src_port, t.dst_port)),
            TransportLayer::Udp(u) => Some((u.src_port, u.dst_port)),
            _ => None,
        }
    }

    pub fn src_mac(&self) -> Option<MacAddr> {
        self.link.as_ref().map(|e| e.src)
    }

    /// Short one-line rendering, as used by `cbna analyze --packets`.
    pub fn summary(&self) -> String {
        let ts = self.meta.timestamp.to_time_of_day();
        let proto = self.protocol_label();
        let endpoints = match (self.src_ip(), self.dst_ip(), self.ports()) {
            (Some(s), Some(d), Some((sp, dp))) => format!("{s}:{sp} > {d}:{dp}"),
            (Some(s), Some(d), None) => format!("{s} > {d}"),
            _ => match &self.network {
                NetworkLayer::Arp(a) => format!("{} > {}", a.sender_ip, a.target_ip),
                _ => self
                    .link
                    .as_ref()
                    .map(|e| format!("{} > {}", e.src, e.dst))
                    .unwrap_or_else(|| "?".into()),
            },
        };

        let mut detail = String::new();
        if let TransportLayer::Tcp(t) = &self.transport {
            detail = format!(" [{}] seq={} win={}", t.flags, t.seq, t.window);
        }
        match &self.app {
            AppLayer::Dns(d) => {
                let q = d.primary_name().unwrap_or("?");
                detail = if d.is_response {
                    format!(" DNS response {q} {}", d.rcode_name())
                } else {
                    format!(" DNS query {q}")
                };
            }
            AppLayer::Http(h) => detail = format!(" {}", h.summary()),
            AppLayer::Tls(t) => {
                detail = format!(
                    " TLS {} {}",
                    t.version_name(),
                    t.sni.as_deref().unwrap_or("(no sni)")
                )
            }
            AppLayer::None => {}
        }

        format!(
            "{ts} {proto:<6} {endpoints} len={}{detail}",
            self.meta.wire_len
        )
    }

    pub fn protocol_label(&self) -> String {
        match &self.app {
            AppLayer::Dns(_) => return "DNS".into(),
            AppLayer::Http(_) => return "HTTP".into(),
            AppLayer::Tls(_) => return "TLS".into(),
            AppLayer::None => {}
        }
        match &self.transport {
            TransportLayer::Tcp(_) => "TCP".into(),
            TransportLayer::Udp(_) => "UDP".into(),
            TransportLayer::Icmp(i) => {
                if i.v6 {
                    "ICMPv6".into()
                } else {
                    "ICMP".into()
                }
            }
            TransportLayer::None => match &self.network {
                NetworkLayer::Arp(_) => "ARP".into(),
                NetworkLayer::Ipv4(h) => net::proto_name(h.protocol).into(),
                NetworkLayer::Ipv6(h) => net::proto_name(h.next_header).into(),
                NetworkLayer::None => self
                    .link
                    .as_ref()
                    .map(|e| link::ethertype_name(e.ethertype).to_string())
                    .unwrap_or_else(|| "?".into()),
            },
        }
    }
}

/// Decode one captured frame.
pub fn decode(meta: PacketMeta, bytes: &[u8], link_type: LinkType) -> DecodedPacket {
    let mut pkt = DecodedPacket {
        meta,
        link: None,
        network: NetworkLayer::None,
        transport: TransportLayer::None,
        app: AppLayer::None,
        payload_len: 0,
        warnings: Vec::new(),
    };

    let (ethertype, l3) = match link_type {
        LinkType::Ethernet => match link::parse_ethernet(bytes) {
            Ok((eth, rest)) => {
                let et = eth.ethertype;
                pkt.link = Some(eth);
                (et, rest)
            }
            Err(e) => {
                pkt.warnings.push(Warning::from(e).0);
                return pkt;
            }
        },
        // Headerless IP: infer the family from the version nibble.
        LinkType::Raw => match bytes.first().map(|b| b >> 4) {
            Some(4) => (link::ETHERTYPE_IPV4, bytes),
            Some(6) => (link::ETHERTYPE_IPV6, bytes),
            _ => {
                pkt.warnings
                    .push("raw link: unrecognised IP version".into());
                return pkt;
            }
        },
        // 4-byte host-order address family, then IP.
        LinkType::Null | LinkType::Loop => {
            if bytes.len() < 4 {
                pkt.warnings.push("loopback header: truncated".into());
                return pkt;
            }
            let af = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let et = match af {
                2 => link::ETHERTYPE_IPV4,
                24 | 28 | 30 => link::ETHERTYPE_IPV6,
                _ => {
                    pkt.warnings
                        .push(format!("loopback header: unknown address family {af}"));
                    return pkt;
                }
            };
            (et, &bytes[4..])
        }
        // Linux cooked capture: the EtherType sits at a fixed offset.
        LinkType::LinuxSll => {
            if bytes.len() < 16 {
                pkt.warnings.push("linux cooked header: truncated".into());
                return pkt;
            }
            (u16::from_be_bytes([bytes[14], bytes[15]]), &bytes[16..])
        }
        LinkType::LinuxSll2 => {
            if bytes.len() < 20 {
                pkt.warnings
                    .push("linux cooked v2 header: truncated".into());
                return pkt;
            }
            (u16::from_be_bytes([bytes[0], bytes[1]]), &bytes[20..])
        }
        LinkType::Other(v) => {
            pkt.warnings
                .push(format!("unsupported link type LINKTYPE_{v}"));
            return pkt;
        }
    };

    decode_network(&mut pkt, ethertype, l3);
    pkt
}

fn decode_network(pkt: &mut DecodedPacket, ethertype: u16, l3: &[u8]) {
    match ethertype {
        link::ETHERTYPE_IPV4 => match net::parse_ipv4(l3) {
            Ok((ip, payload)) => {
                let proto = ip.protocol;
                let can_decode_transport = ip.has_transport_header();
                pkt.network = NetworkLayer::Ipv4(ip);
                if can_decode_transport {
                    decode_transport(pkt, proto, payload);
                } else {
                    pkt.payload_len = payload.len();
                }
            }
            Err(e) => pkt.warnings.push(Warning::from(e).0),
        },
        link::ETHERTYPE_IPV6 => match net::parse_ipv6(l3) {
            Ok((ip, payload)) => {
                let proto = ip.next_header;
                let can_decode_transport = ip.has_transport_header();
                pkt.network = NetworkLayer::Ipv6(ip);
                if can_decode_transport {
                    decode_transport(pkt, proto, payload);
                } else {
                    pkt.payload_len = payload.len();
                }
            }
            Err(e) => pkt.warnings.push(Warning::from(e).0),
        },
        link::ETHERTYPE_ARP => match link::parse_arp(l3) {
            Ok(arp) => pkt.network = NetworkLayer::Arp(arp),
            Err(e) => pkt.warnings.push(Warning::from(e).0),
        },
        _ => {}
    }
}

fn decode_transport(pkt: &mut DecodedPacket, protocol: u8, l4: &[u8]) {
    match protocol {
        proto_num::TCP => match transport::parse_tcp(l4) {
            Ok((tcp, payload)) => {
                let ports = (tcp.src_port, tcp.dst_port);
                pkt.transport = TransportLayer::Tcp(tcp);
                pkt.payload_len = payload.len();
                decode_app(pkt, ports, payload, true);
            }
            Err(e) => pkt.warnings.push(Warning::from(e).0),
        },
        proto_num::UDP => match transport::parse_udp(l4) {
            Ok((udp, payload)) => {
                let ports = (udp.src_port, udp.dst_port);
                pkt.transport = TransportLayer::Udp(udp);
                pkt.payload_len = payload.len();
                decode_app(pkt, ports, payload, false);
            }
            Err(e) => pkt.warnings.push(Warning::from(e).0),
        },
        proto_num::ICMP | proto_num::ICMPV6 => {
            match net::parse_icmp(l4, protocol == proto_num::ICMPV6) {
                Ok(icmp) => {
                    pkt.payload_len = icmp.payload_len;
                    pkt.transport = TransportLayer::Icmp(icmp);
                }
                Err(e) => pkt.warnings.push(Warning::from(e).0),
            }
        }
        _ => pkt.payload_len = l4.len(),
    }
}

/// Try application decoders. Port hints come first, then content sniffing, so
/// a service on a non-standard port is still identified.
fn decode_app(pkt: &mut DecodedPacket, ports: (u16, u16), payload: &[u8], tcp: bool) {
    if payload.is_empty() {
        return;
    }
    let (sp, dp) = ports;
    let dns_port = matches!(sp, 53 | 5353 | 5355) || matches!(dp, 53 | 5353 | 5355);

    if dns_port {
        // Over TCP, DNS is framed with a 2-byte length prefix.
        let body = if tcp && payload.len() > 2 {
            &payload[2..]
        } else {
            payload
        };
        if let Some(msg) = proto::dns::parse(body) {
            pkt.app = AppLayer::Dns(Box::new(msg));
            return;
        }
    }

    if !tcp {
        return;
    }

    if let Some(hello) = proto::tls::parse(payload) {
        pkt.app = AppLayer::Tls(Box::new(hello));
        return;
    }
    if let Some(msg) = proto::http::parse(payload) {
        pkt.app = AppLayer::Http(Box::new(msg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> PacketMeta {
        PacketMeta {
            index: 1,
            timestamp: Timestamp::new(1_786_365_296, 0),
            captured_len: 0,
            wire_len: 0,
        }
    }

    /// Build an Ethernet/IPv4/UDP frame carrying `payload`.
    fn udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]);
        udp.extend_from_slice(payload);

        let total_len = (20 + udp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, proto_num::UDP, 0x00, 0x00]);
        ip.extend_from_slice(&[192, 168, 1, 50]);
        ip.extend_from_slice(&[1, 1, 1, 1]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        eth.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    fn dns_query() -> Vec<u8> {
        let mut b = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        b.push(6);
        b.extend_from_slice(b"update");
        b.push(9);
        b.extend_from_slice(b"microsoft");
        b.push(3);
        b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        b
    }

    #[test]
    fn decodes_full_stack_to_dns() {
        let frame = udp_frame(51000, 53, &dns_query());
        let pkt = decode(meta(), &frame, LinkType::Ethernet);
        assert!(pkt.warnings.is_empty(), "{:?}", pkt.warnings);
        assert_eq!(pkt.src_ip().unwrap().to_string(), "192.168.1.50");
        assert_eq!(pkt.ports(), Some((51000, 53)));
        assert_eq!(pkt.protocol_label(), "DNS");
        match &pkt.app {
            AppLayer::Dns(d) => assert_eq!(d.primary_name(), Some("update.microsoft.com")),
            other => panic!("expected DNS, got {other:?}"),
        }
        assert!(pkt.summary().contains("DNS query update.microsoft.com"));
    }

    #[test]
    fn decodes_raw_ip_link_type() {
        let frame = udp_frame(1234, 53, &dns_query());
        let ip_only = &frame[14..];
        let pkt = decode(meta(), ip_only, LinkType::Raw);
        assert!(pkt.link.is_none());
        assert_eq!(pkt.protocol_label(), "DNS");
    }

    #[test]
    fn unknown_link_type_warns_without_panicking() {
        let pkt = decode(meta(), &[0u8; 40], LinkType::Other(999));
        assert_eq!(pkt.network, NetworkLayer::None);
        assert_eq!(pkt.warnings.len(), 1);
        assert!(pkt.warnings[0].contains("LINKTYPE_999"));
    }

    #[test]
    fn truncated_frame_records_warning_and_keeps_lower_layers() {
        // Ethernet + IPv4 header claiming TCP, but the TCP header is cut off.
        let mut frame = udp_frame(1, 2, &[]);
        frame[23] = proto_num::TCP;
        frame.truncate(frame.len() - 4);
        let pkt = decode(meta(), &frame, LinkType::Ethernet);
        assert!(matches!(pkt.network, NetworkLayer::Ipv4(_)));
        assert_eq!(pkt.transport, TransportLayer::None);
        assert!(!pkt.warnings.is_empty());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Decoding is exposed to hostile input, so exercise a spread of shapes.
        for len in 0..80usize {
            let frame: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            for lt in [
                LinkType::Ethernet,
                LinkType::Raw,
                LinkType::Null,
                LinkType::LinuxSll,
            ] {
                let _ = decode(meta(), &frame, lt);
            }
        }
    }
}
