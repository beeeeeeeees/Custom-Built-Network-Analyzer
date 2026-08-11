//! Bidirectional flow tracking.
//!
//! Flows are keyed on a canonicalised 5-tuple so both directions land in one
//! record. The canonical form puts the lower `(ip, port)` pair first, which is
//! stable regardless of which direction we happened to see first.

use crate::net::{is_private, proto_name, proto_num};
use crate::packet::{AppLayer, DecodedPacket, TransportLayer};
use crate::time::Timestamp;
use crate::transport::{service_name, TcpFlags};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;

/// Per-direction inter-arrival samples are capped so a long capture cannot grow
/// without bound; beacon scoring needs shape, not every packet.
const MAX_TIMESTAMP_SAMPLES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub a_port: u16,
    pub b_ip: IpAddr,
    pub b_port: u16,
    pub protocol: u8,
}

/// Which endpoint of the canonical key a packet travelled from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    AToB,
    BToA,
}

impl FlowKey {
    /// Build the canonical key plus the direction this packet represents.
    pub fn canonical(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: u8,
    ) -> (FlowKey, Direction) {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            (
                FlowKey {
                    a_ip: src_ip,
                    a_port: src_port,
                    b_ip: dst_ip,
                    b_port: dst_port,
                    protocol,
                },
                Direction::AToB,
            )
        } else {
            (
                FlowKey {
                    a_ip: dst_ip,
                    a_port: dst_port,
                    b_ip: src_ip,
                    b_port: src_port,
                    protocol,
                },
                Direction::BToA,
            )
        }
    }

    pub fn from_packet(pkt: &DecodedPacket) -> Option<(FlowKey, Direction)> {
        let src = pkt.src_ip()?;
        let dst = pkt.dst_ip()?;
        let protocol = pkt.ip_protocol()?;
        let (sp, dp) = pkt.ports().unwrap_or((0, 0));
        Some(FlowKey::canonical(src, sp, dst, dp, protocol))
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.a_port == 0 && self.b_port == 0 {
            write!(
                f,
                "{} <-> {} {}",
                self.a_ip,
                self.b_ip,
                proto_name(self.protocol)
            )
        } else {
            write!(
                f,
                "{}:{} <-> {}:{} {}",
                self.a_ip,
                self.a_port,
                self.b_ip,
                self.b_port,
                proto_name(self.protocol)
            )
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectionStats {
    pub packets: u64,
    pub bytes: u64,
    pub payload_bytes: u64,
    pub tcp_flags_seen: u8,
    /// Packet timestamps, capped at [`MAX_TIMESTAMP_SAMPLES`].
    #[serde(skip)]
    pub timestamps: Vec<f64>,
    /// True once sampling stopped, so analysis can note reduced confidence.
    pub samples_truncated: bool,
}

impl DirectionStats {
    fn observe(&mut self, pkt: &DecodedPacket) {
        self.packets += 1;
        self.bytes += pkt.meta.wire_len as u64;
        self.payload_bytes += pkt.payload_len as u64;
        if let TransportLayer::Tcp(t) = &pkt.transport {
            self.tcp_flags_seen |= t.flags.0;
        }
        if self.timestamps.len() < MAX_TIMESTAMP_SAMPLES {
            self.timestamps.push(pkt.meta.timestamp.as_secs_f64());
        } else {
            self.samples_truncated = true;
        }
    }
}

/// Where a flow sits relative to the local network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowScope {
    Internal,
    Outbound,
    Inbound,
    External,
}

impl fmt::Display for FlowScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FlowScope::Internal => "internal",
            FlowScope::Outbound => "outbound",
            FlowScope::Inbound => "inbound",
            FlowScope::External => "external",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub key: FlowKey,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub a_to_b: DirectionStats,
    pub b_to_a: DirectionStats,
    /// Application protocols observed on this flow.
    pub protocols: BTreeSet<String>,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub http_hosts: BTreeSet<String>,
    pub user_agents: BTreeSet<String>,
    pub dns_names: BTreeSet<String>,
    pub cleartext_credentials: bool,
    /// True if we ever saw a SYN without ACK — i.e. we caught the handshake.
    pub saw_handshake: bool,
    /// Which canonical endpoint opened the conversation. Seeded from the first
    /// packet and corrected if a SYN later proves who the real client was.
    ///
    /// The canonical key sorts endpoints by address so both directions share a
    /// record, which says nothing about who initiated — deriving the client
    /// from key order would call an outbound connection to 93.x inbound purely
    /// because 93 sorts below 192.
    pub initiator: Direction,
}

impl Flow {
    fn new(key: FlowKey, ts: Timestamp, initiator: Direction) -> Self {
        Self {
            key,
            initiator,
            first_seen: ts,
            last_seen: ts,
            a_to_b: DirectionStats::default(),
            b_to_a: DirectionStats::default(),
            protocols: BTreeSet::new(),
            sni: None,
            ja3: None,
            http_hosts: BTreeSet::new(),
            user_agents: BTreeSet::new(),
            dns_names: BTreeSet::new(),
            cleartext_credentials: false,
            saw_handshake: false,
        }
    }

    pub fn packets(&self) -> u64 {
        self.a_to_b.packets + self.b_to_a.packets
    }

    pub fn bytes(&self) -> u64 {
        self.a_to_b.bytes + self.b_to_a.bytes
    }

    pub fn duration_secs(&self) -> f64 {
        self.last_seen.delta_secs(self.first_seen)
    }

    /// Direction the client's packets travel in.
    ///
    /// A bare SYN settles it. Without one — live captures very often start
    /// mid-conversation, and then the first packet seen is just as likely to be
    /// the server's — fall back to port shape: the well-known or lower port is
    /// the service, the ephemeral high port is the client.
    pub fn client_direction(&self) -> Direction {
        if self.saw_handshake || self.key.a_port == self.key.b_port {
            return self.initiator;
        }
        let tcp = self.key.protocol == proto_num::TCP;
        match (
            service_name(self.key.a_port, tcp).is_some(),
            service_name(self.key.b_port, tcp).is_some(),
        ) {
            (true, false) => Direction::BToA,
            (false, true) => Direction::AToB,
            _ => {
                if self.key.a_port > self.key.b_port {
                    Direction::AToB
                } else {
                    Direction::BToA
                }
            }
        }
    }

    /// The endpoint that opened the conversation.
    pub fn client(&self) -> (IpAddr, u16) {
        match self.client_direction() {
            Direction::AToB => (self.key.a_ip, self.key.a_port),
            Direction::BToA => (self.key.b_ip, self.key.b_port),
        }
    }

    /// The endpoint that was connected to.
    pub fn server(&self) -> (IpAddr, u16) {
        match self.client_direction() {
            Direction::AToB => (self.key.b_ip, self.key.b_port),
            Direction::BToA => (self.key.a_ip, self.key.a_port),
        }
    }

    /// Traffic the client sent.
    pub fn client_stats(&self) -> &DirectionStats {
        match self.client_direction() {
            Direction::AToB => &self.a_to_b,
            Direction::BToA => &self.b_to_a,
        }
    }

    /// Traffic the server sent back.
    pub fn server_stats(&self) -> &DirectionStats {
        match self.client_direction() {
            Direction::AToB => &self.b_to_a,
            Direction::BToA => &self.a_to_b,
        }
    }

    pub fn scope(&self) -> FlowScope {
        match (is_private(self.client().0), is_private(self.server().0)) {
            (true, true) => FlowScope::Internal,
            (true, false) => FlowScope::Outbound,
            (false, true) => FlowScope::Inbound,
            (false, false) => FlowScope::External,
        }
    }

    /// The service being talked to, preferring the endpoint we believe is the
    /// server and falling back to whichever side holds a well-known port.
    pub fn service(&self) -> Option<(IpAddr, u16, &'static str)> {
        let tcp = self.key.protocol == proto_num::TCP;
        let (server_ip, server_port) = self.server();
        if let Some(name) = service_name(server_port, tcp) {
            return Some((server_ip, server_port, name));
        }
        let (client_ip, client_port) = self.client();
        service_name(client_port, tcp).map(|n| (client_ip, client_port, n))
    }

    /// Ratio of payload the client pushed to payload it pulled back. High
    /// values on an outbound flow are the shape of data staging.
    pub fn upload_ratio(&self) -> f64 {
        let up = self.client_stats().payload_bytes;
        let down = self.server_stats().payload_bytes;
        if down == 0 {
            if up == 0 {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            up as f64 / down as f64
        }
    }

    /// TCP connections that were opened but never answered, i.e. scan residue.
    pub fn is_unanswered_syn(&self) -> bool {
        self.key.protocol == proto_num::TCP
            && self.saw_handshake
            && self.server_stats().packets == 0
            && self.client_stats().packets <= 4
    }

    pub fn was_reset(&self) -> bool {
        TcpFlags(self.a_to_b.tcp_flags_seen).rst() || TcpFlags(self.b_to_a.tcp_flags_seen).rst()
    }

    fn stats_mut(&mut self, dir: Direction) -> &mut DirectionStats {
        match dir {
            Direction::AToB => &mut self.a_to_b,
            Direction::BToA => &mut self.b_to_a,
        }
    }

    fn record_app(&mut self, pkt: &DecodedPacket) {
        match &pkt.app {
            AppLayer::Dns(d) => {
                self.protocols.insert("dns".into());
                for q in &d.questions {
                    if self.dns_names.len() < 256 {
                        self.dns_names.insert(q.name.clone());
                    }
                }
            }
            AppLayer::Http(h) => {
                self.protocols.insert("http".into());
                if let Some(host) = &h.host {
                    if self.http_hosts.len() < 64 {
                        self.http_hosts.insert(host.clone());
                    }
                }
                if let Some(ua) = &h.user_agent {
                    if self.user_agents.len() < 16 {
                        self.user_agents.insert(ua.clone());
                    }
                }
                if h.has_authorization {
                    self.cleartext_credentials = true;
                }
            }
            AppLayer::Tls(t) => {
                self.protocols.insert("tls".into());
                if self.sni.is_none() {
                    self.sni.clone_from(&t.sni);
                }
                if self.ja3.is_none() && t.kind == crate::proto::TlsHelloKind::Client {
                    self.ja3 = Some(t.ja3_md5.clone());
                }
            }
            AppLayer::None => {}
        }
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a packet into the table, creating the flow if it is new.
    pub fn observe(&mut self, pkt: &DecodedPacket) -> Option<FlowKey> {
        let (key, dir) = FlowKey::from_packet(pkt)?;
        let flow = self
            .flows
            .entry(key)
            .or_insert_with(|| Flow::new(key, pkt.meta.timestamp, dir));

        if pkt.meta.timestamp < flow.first_seen {
            flow.first_seen = pkt.meta.timestamp;
        }
        if pkt.meta.timestamp > flow.last_seen {
            flow.last_seen = pkt.meta.timestamp;
        }
        if let TransportLayer::Tcp(t) = &pkt.transport {
            if t.flags.is_syn_only() {
                // A bare SYN is definitive about who the client is, even if we
                // joined the capture mid-conversation and guessed wrong.
                if !flow.saw_handshake {
                    flow.initiator = dir;
                }
                flow.saw_handshake = true;
            }
        }
        flow.stats_mut(dir).observe(pkt);
        flow.record_app(pkt);
        Some(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    /// Flows sorted by total bytes, descending.
    pub fn by_bytes(&self) -> Vec<&Flow> {
        let mut v: Vec<&Flow> = self.flows.values().collect();
        v.sort_by(|a, b| b.bytes().cmp(&a.bytes()).then_with(|| a.key.cmp(&b.key)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{decode, LinkType, PacketMeta};

    fn tcp_frame(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 1]); // seq
        tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
        tcp.extend_from_slice(&[0x50, flags]); // offset 5
        tcp.extend_from_slice(&[0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        tcp.extend_from_slice(payload);

        let total = (20 + tcp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, proto_num::TCP, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    fn pkt(index: u64, ts: f64, bytes: &[u8]) -> DecodedPacket {
        decode(
            PacketMeta {
                index,
                timestamp: Timestamp::new(ts as i64, ((ts.fract()) * 1e9) as u32),
                captured_len: bytes.len() as u32,
                wire_len: bytes.len() as u32,
            },
            bytes,
            LinkType::Ethernet,
        )
    }

    #[test]
    fn both_directions_land_in_one_flow() {
        let mut table = FlowTable::new();
        let out = tcp_frame(
            [192, 168, 1, 10],
            50000,
            [93, 184, 216, 34],
            443,
            TcpFlags::SYN,
            &[],
        );
        let back = tcp_frame(
            [93, 184, 216, 34],
            443,
            [192, 168, 1, 10],
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            &[],
        );
        table.observe(&pkt(1, 100.0, &out));
        table.observe(&pkt(2, 100.1, &back));

        assert_eq!(table.len(), 1);
        let flow = table.iter().next().unwrap();
        assert_eq!(flow.packets(), 2);
        assert_eq!(flow.a_to_b.packets, 1);
        assert_eq!(flow.b_to_a.packets, 1);
        assert!(flow.saw_handshake);
        assert_eq!(flow.scope(), FlowScope::Outbound);
        assert_eq!(flow.service().map(|s| s.2), Some("https"));
        assert_eq!(flow.client().0.to_string(), "192.168.1.10");
        assert_eq!(flow.server().0.to_string(), "93.184.216.34");
    }

    #[test]
    fn a_syn_overrides_the_port_heuristic() {
        // A service listening on a high port with a client bound low: the port
        // heuristic gets this backwards, and only the SYN can settle it.
        let mut table = FlowTable::new();
        let from_server = tcp_frame(
            [10, 0, 0, 200],
            60000,
            [10, 0, 0, 5],
            1000,
            TcpFlags::PSH | TcpFlags::ACK,
            &[0; 20],
        );
        let syn = tcp_frame(
            [10, 0, 0, 5],
            1000,
            [10, 0, 0, 200],
            60000,
            TcpFlags::SYN,
            &[],
        );

        table.observe(&pkt(1, 1.0, &from_server));
        let flow = table.iter().next().unwrap();
        assert_eq!(flow.client().1, 60000, "heuristic picks the higher port");

        table.observe(&pkt(2, 1.1, &syn));
        let flow = table.iter().next().unwrap();
        assert_eq!(flow.client().1, 1000);
        assert_eq!(flow.server().1, 60000);
    }

    #[test]
    fn mid_session_flow_infers_the_client_from_port_shape() {
        // No SYN in the capture — only the server's data. Port 443 versus an
        // ephemeral 51480 is enough to say who called whom.
        let mut table = FlowTable::new();
        let from_server = tcp_frame(
            [129, 153, 148, 165],
            443,
            [192, 168, 1, 9],
            51480,
            TcpFlags::PSH | TcpFlags::ACK,
            &[0; 100],
        );
        table.observe(&pkt(1, 1.0, &from_server));

        let flow = table.iter().next().unwrap();
        assert!(!flow.saw_handshake);
        assert_eq!(flow.client().0.to_string(), "192.168.1.9");
        assert_eq!(flow.server().1, 443);
        assert_eq!(flow.scope(), FlowScope::Outbound);
        assert_eq!(flow.server_stats().payload_bytes, 100);
        assert_eq!(flow.client_stats().payload_bytes, 0);
    }

    #[test]
    fn ephemeral_port_wins_when_neither_side_is_well_known() {
        let mut table = FlowTable::new();
        let f = tcp_frame(
            [10, 0, 0, 2],
            9001,
            [10, 0, 0, 1],
            55000,
            TcpFlags::ACK,
            &[0; 10],
        );
        table.observe(&pkt(1, 1.0, &f));
        let flow = table.iter().next().unwrap();
        assert_eq!(flow.client().1, 55000);
        assert_eq!(flow.server().1, 9001);
    }

    #[test]
    fn upload_ratio_follows_the_client_not_the_key_order() {
        let mut table = FlowTable::new();
        // 192.168.x sorts above 93.x, so the canonical key puts the public
        // host first. The ratio must still measure what the client sent.
        let up = tcp_frame(
            [192, 168, 1, 10],
            50000,
            [93, 184, 216, 34],
            443,
            TcpFlags::SYN,
            &[],
        );
        let up_data = tcp_frame(
            [192, 168, 1, 10],
            50000,
            [93, 184, 216, 34],
            443,
            TcpFlags::PSH | TcpFlags::ACK,
            &[0; 400],
        );
        let down = tcp_frame(
            [93, 184, 216, 34],
            443,
            [192, 168, 1, 10],
            50000,
            TcpFlags::ACK,
            &[0; 40],
        );
        table.observe(&pkt(1, 1.0, &up));
        table.observe(&pkt(2, 1.1, &up_data));
        table.observe(&pkt(3, 1.2, &down));

        let flow = table.iter().next().unwrap();
        assert_eq!(flow.client_stats().payload_bytes, 400);
        assert_eq!(flow.server_stats().payload_bytes, 40);
        assert!((flow.upload_ratio() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn canonical_key_is_direction_independent() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let (k1, d1) = FlowKey::canonical(a, 1234, b, 80, 6);
        let (k2, d2) = FlowKey::canonical(b, 80, a, 1234, 6);
        assert_eq!(k1, k2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn detects_unanswered_syn() {
        let mut table = FlowTable::new();
        let syn = tcp_frame([10, 0, 0, 5], 40000, [10, 0, 0, 9], 445, TcpFlags::SYN, &[]);
        table.observe(&pkt(1, 1.0, &syn));
        let flow = table.iter().next().unwrap();
        assert!(flow.is_unanswered_syn());
        assert!(!flow.was_reset());
    }

    #[test]
    fn tracks_duration_and_ordering() {
        let mut table = FlowTable::new();
        let f = tcp_frame(
            [10, 0, 0, 1],
            1000,
            [10, 0, 0, 2],
            22,
            TcpFlags::ACK,
            &[1, 2, 3],
        );
        table.observe(&pkt(1, 50.0, &f));
        table.observe(&pkt(2, 62.5, &f));
        let flow = table.iter().next().unwrap();
        assert!((flow.duration_secs() - 12.5).abs() < 1e-6);
        assert_eq!(flow.a_to_b.payload_bytes, 6);
    }

    #[test]
    fn sorts_by_volume() {
        let mut table = FlowTable::new();
        let small = tcp_frame([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, TcpFlags::ACK, &[0; 10]);
        let big = tcp_frame([10, 0, 0, 3], 3, [10, 0, 0, 4], 4, TcpFlags::ACK, &[0; 500]);
        table.observe(&pkt(1, 1.0, &small));
        table.observe(&pkt(2, 1.0, &big));
        let sorted = table.by_bytes();
        assert!(sorted[0].bytes() > sorted[1].bytes());
    }
}
