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
    /// Offset of that payload within the frame this packet was decoded from.
    ///
    /// The payload bytes themselves are deliberately not stored — copying them
    /// for every packet would double the memory a capture costs, and almost
    /// nothing needs them. A caller that still holds the frame can recover them
    /// with `&frame[payload_offset..][..payload_len]`, which is how the stream
    /// reassembler gets its input.
    pub payload_offset: usize,
    /// For a fragmented IP datagram only, the `(offset, len)` of this fragment's
    /// whole layer-3 payload within the frame — transport header plus data on
    /// the first fragment, raw data on later ones. `None` for everything else.
    ///
    /// The IP reassembler needs the entire L3 payload placed at the fragment
    /// offset, which is not what `payload_offset`/`payload_len` describe: those
    /// point at the *transport* payload and are only set for the first fragment.
    pub ip_payload: Option<(usize, usize)>,
    pub warnings: Vec<String>,
}

impl DecodedPacket {
    /// Transport payload, recovered from the frame this packet was decoded
    /// from. Empty if `frame` is not that frame, so a mismatched caller gets
    /// nothing rather than someone else's bytes.
    pub fn payload<'a>(&self, frame: &'a [u8]) -> &'a [u8] {
        let end = self.payload_offset.saturating_add(self.payload_len);
        frame.get(self.payload_offset..end).unwrap_or(&[])
    }

    /// This fragment's whole layer-3 payload, recovered from its frame. Empty
    /// unless the packet is a fragment (see [`DecodedPacket::ip_payload`]).
    pub fn fragment_bytes<'a>(&self, frame: &'a [u8]) -> &'a [u8] {
        match self.ip_payload {
            Some((off, len)) => frame.get(off..off.saturating_add(len)).unwrap_or(&[]),
            None => &[],
        }
    }

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
        payload_offset: 0,
        ip_payload: None,
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

    decode_network(&mut pkt, ethertype, l3, bytes);
    pkt
}

fn decode_network(pkt: &mut DecodedPacket, ethertype: u16, l3: &[u8], frame: &[u8]) {
    match ethertype {
        link::ETHERTYPE_IPV4 => match net::parse_ipv4(l3) {
            Ok((ip, payload)) => {
                let proto = ip.protocol;
                let can_decode_transport = ip.has_transport_header();
                let fragmented = ip.fragmented;
                // Hand the reassembler this fragment's whole L3 payload; the
                // transport-payload fields below describe only the first
                // fragment's transport data, not the bytes to be reassembled.
                if fragmented {
                    pkt.ip_payload = Some((offset_in(frame, payload), payload.len()));
                }
                pkt.network = NetworkLayer::Ipv4(ip);
                if can_decode_transport {
                    // The first fragment carries a transport header but only a
                    // truncated transport payload, so decode the transport (for
                    // ports and the flow) yet leave the application layer to the
                    // reassembler, which sees the whole datagram. Decoding it
                    // here too would index the message twice.
                    decode_transport(pkt, proto, payload, frame, !fragmented);
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
                let fragmented = ip.fragmented;
                if fragmented {
                    pkt.ip_payload = Some((offset_in(frame, payload), payload.len()));
                }
                pkt.network = NetworkLayer::Ipv6(ip);
                if can_decode_transport {
                    decode_transport(pkt, proto, payload, frame, !fragmented);
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

/// Byte offset of `sub` within `whole`. Both always come from the same
/// allocation here: every `sub` is a subslice the parsers carved out of the
/// frame, so the subtraction is meaningful.
fn offset_in(whole: &[u8], sub: &[u8]) -> usize {
    (sub.as_ptr() as usize).saturating_sub(whole.as_ptr() as usize)
}

/// Decode the transport header and, unless `decode_app_layer` is false, the
/// application message on top of it. Fragments pass `false`: their transport
/// payload is truncated, so only the reassembled datagram is worth decoding at
/// L7.
fn decode_transport(
    pkt: &mut DecodedPacket,
    protocol: u8,
    l4: &[u8],
    frame: &[u8],
    decode_app_layer: bool,
) {
    match protocol {
        proto_num::TCP => match transport::parse_tcp(l4) {
            Ok((tcp, payload)) => {
                let ports = (tcp.src_port, tcp.dst_port);
                pkt.transport = TransportLayer::Tcp(tcp);
                pkt.payload_len = payload.len();
                pkt.payload_offset = offset_in(frame, payload);
                if decode_app_layer {
                    decode_app(pkt, ports, payload, true);
                }
            }
            Err(e) => pkt.warnings.push(Warning::from(e).0),
        },
        proto_num::UDP => match transport::parse_udp(l4) {
            Ok((udp, payload)) => {
                let ports = (udp.src_port, udp.dst_port);
                pkt.transport = TransportLayer::Udp(udp);
                pkt.payload_len = payload.len();
                pkt.payload_offset = offset_in(frame, payload);
                if decode_app_layer {
                    decode_app(pkt, ports, payload, false);
                }
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

fn decode_app(pkt: &mut DecodedPacket, ports: (u16, u16), payload: &[u8], tcp: bool) {
    pkt.app = app_from_payload(ports, payload, tcp);
}

/// Try application decoders. Port hints come first, then content sniffing, so
/// a service on a non-standard port is still identified.
///
/// Split out from [`decode`] because the stream reassembler runs the same
/// decoders over a payload rebuilt from several segments. Both callers must
/// identify a protocol the same way, or a message would be classified
/// differently depending on how the sender happened to split it.
pub fn app_from_payload(ports: (u16, u16), payload: &[u8], tcp: bool) -> AppLayer {
    if payload.is_empty() {
        return AppLayer::None;
    }
    let (sp, dp) = ports;
    let dns_port = matches!(sp, 53 | 5353 | 5355) || matches!(dp, 53 | 5353 | 5355);

    if dns_port {
        // Over TCP, DNS is framed with a 2-byte length prefix — but the prefix
        // does not have to share a segment with the message it describes.
        // Windows resolvers commonly push the two bytes on their own and send
        // the message in the next segment, so stripping unconditionally would
        // eat the transaction ID and corrupt every query. Only strip a prefix
        // that actually accounts for the rest of the payload, and fall back to
        // reading the payload as a bare message.
        let prefixed = if tcp && payload.len() > 2 {
            let declared = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            (declared == payload.len() - 2).then(|| &payload[2..])
        } else {
            None
        };
        let decoded = prefixed
            .and_then(proto::dns::parse)
            .or_else(|| proto::dns::parse(payload));
        if let Some(msg) = decoded {
            return AppLayer::Dns(Box::new(msg));
        }
    }

    if !tcp {
        return AppLayer::None;
    }

    if let Some(hello) = proto::tls::parse(payload) {
        return AppLayer::Tls(Box::new(hello));
    }
    if let Some(msg) = proto::http::parse(payload) {
        return AppLayer::Http(Box::new(msg));
    }
    AppLayer::None
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

    /// Build an Ethernet/IPv4/TCP frame carrying `payload`.
    fn tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        tcp.extend_from_slice(&[0x50, 0x18]); // offset 5, PSH|ACK
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend_from_slice(payload);

        let total_len = (20 + tcp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, proto_num::TCP, 0x00, 0x00]);
        ip.extend_from_slice(&[192, 168, 1, 9]);
        ip.extend_from_slice(&[192, 168, 1, 1]);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    #[test]
    fn decodes_dns_over_tcp_with_the_length_prefix_attached() {
        let msg = dns_query();
        let mut payload = (msg.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(&msg);

        let pkt = decode(meta(), &tcp_frame(38154, 53, &payload), LinkType::Ethernet);
        match &pkt.app {
            AppLayer::Dns(d) => assert_eq!(d.primary_name(), Some("update.microsoft.com")),
            other => panic!("expected DNS, got {other:?}"),
        }
    }

    #[test]
    fn decodes_dns_over_tcp_when_the_prefix_arrived_in_its_own_segment() {
        // Windows resolvers split the 2-byte length prefix into a separate
        // segment; the message then starts at byte 0 of the next one. Stripping
        // two bytes here would eat the transaction ID and lose the query name.
        let pkt = decode(
            meta(),
            &tcp_frame(38154, 53, &dns_query()),
            LinkType::Ethernet,
        );
        match &pkt.app {
            AppLayer::Dns(d) => {
                assert_eq!(d.primary_name(), Some("update.microsoft.com"));
                assert_eq!(d.transaction_id, 0xabcd);
            }
            other => panic!("expected DNS, got {other:?}"),
        }
    }

    #[test]
    fn lone_length_prefix_segment_is_not_mistaken_for_dns() {
        let pkt = decode(
            meta(),
            &tcp_frame(38154, 53, &[0x00, 0x2a]),
            LinkType::Ethernet,
        );
        assert_eq!(pkt.app, AppLayer::None);
        assert_eq!(pkt.protocol_label(), "TCP");
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
    fn fragment_exposes_l3_payload_others_do_not() {
        // A non-fragmented UDP frame carries no fragment view.
        let whole = udp_frame(51000, 53, &dns_query());
        let pkt = decode(meta(), &whole, LinkType::Ethernet);
        assert_eq!(pkt.ip_payload, None);
        assert!(pkt.fragment_bytes(&whole).is_empty());

        // Flip the IP flags word to MF; the L3 payload (UDP header + data) must
        // now be recoverable in full for the reassembler.
        let mut frag = whole.clone();
        frag[14 + 6] = 0x20; // MF bit in the flags/frag-offset word
        frag[14 + 7] = 0x00;
        let pkt = decode(meta(), &frag, LinkType::Ethernet);
        let (off, len) = pkt.ip_payload.expect("fragment should expose L3 payload");
        assert_eq!(off, 14 + 20); // Ethernet + IPv4 header
        assert_eq!(len, dns_query().len() + 8); // UDP header + DNS
        assert_eq!(pkt.fragment_bytes(&frag), &frag[off..off + len]);
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
