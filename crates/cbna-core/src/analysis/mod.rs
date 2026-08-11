//! The analysis pipeline: fold packets in, get a [`Report`] out.

mod beacon;
mod findings;
mod report;

pub use beacon::{score_intervals, BeaconScore};
pub use findings::{Finding, Severity};
pub use report::{
    DnsOverview, FlowSummary, HttpOverview, Report, ServiceStat, Summary, TalkerStat, TlsOverview,
};

use crate::flow::FlowTable;
use crate::link::{ArpOp, MacAddr};
use crate::net::proto_num;
use crate::packet::{AppLayer, DecodedPacket, NetworkLayer, TransportLayer};
use crate::proto::dns::parent_domain;
use crate::reassembly::Reassembler;
use crate::time::Timestamp;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

/// Tunables for the detection heuristics.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Minimum packets in one direction before beacon scoring is attempted.
    pub beacon_min_packets: usize,
    /// Interval regularity threshold; lower is stricter.
    pub beacon_max_jitter: f64,
    /// Ignore candidate intervals outside this range (seconds).
    pub beacon_interval_range: (f64, f64),
    /// Entropy above which a DNS label is called suspicious (bits/char).
    pub dns_entropy_threshold: f64,
    /// Unique subdomains under one parent before tunnelling is suspected.
    pub dns_subdomain_threshold: usize,
    /// Distinct ports one source may touch on one destination before it is
    /// treated as a port scan.
    pub scan_port_threshold: usize,
    /// Payload bytes uploaded on one outbound flow before it is called out.
    pub exfil_bytes_threshold: u64,
    /// Upload:download payload ratio that makes a flow upload-heavy.
    pub exfil_ratio_threshold: f64,
    /// Rows in each table of the report.
    pub top_n: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            beacon_min_packets: 8,
            beacon_max_jitter: 0.20,
            beacon_interval_range: (0.5, 86_400.0),
            dns_entropy_threshold: 3.8,
            dns_subdomain_threshold: 40,
            scan_port_threshold: 15,
            exfil_bytes_threshold: 5 * 1024 * 1024,
            exfil_ratio_threshold: 4.0,
            top_n: 20,
        }
    }
}

/// Aggregate counters over everything observed.
#[derive(Debug, Default, Clone)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
    pub captured_bytes: u64,
    pub truncated_packets: u64,
    pub decode_warnings: u64,
    pub arp: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other_l3: u64,
    pub fragments: u64,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

/// Per-name DNS activity.
#[derive(Debug, Default, Clone)]
pub struct DnsNameStat {
    pub queries: u64,
    pub responses: u64,
    pub nxdomain: u64,
    pub resolved: BTreeSet<String>,
    pub qtypes: BTreeSet<u16>,
}

#[derive(Debug, Default)]
pub struct DnsIndex {
    pub names: HashMap<String, DnsNameStat>,
    /// Parent domain to the set of distinct subdomains seen under it.
    pub subdomains: HashMap<String, BTreeSet<String>>,
    pub servers: BTreeMap<IpAddr, u64>,
}

#[derive(Debug, Default)]
pub struct TlsIndex {
    /// SNI to connection count.
    pub sni: BTreeMap<String, u64>,
    /// JA3 hash to (count, sample SNI).
    pub ja3: BTreeMap<String, (u64, Option<String>)>,
    pub obsolete_versions: u64,
    pub no_sni: u64,
}

#[derive(Debug, Default)]
pub struct HttpIndex {
    pub hosts: BTreeMap<String, u64>,
    pub user_agents: BTreeMap<String, u64>,
    pub requests: u64,
    pub responses: u64,
    pub cleartext_auth: u64,
    /// (host, uri) pairs where credentials rode in the clear.
    pub credential_requests: Vec<String>,
}

/// IP-to-MAC bindings observed in ARP, used to spot address conflicts.
#[derive(Debug, Default)]
pub struct ArpIndex {
    pub bindings: HashMap<Ipv4Addr, BTreeSet<MacAddr>>,
    pub gratuitous: u64,
    pub requests: u64,
    pub replies: u64,
}

/// Per-host rollups for the talker table and scan detection.
#[derive(Debug, Default, Clone)]
pub struct HostStat {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peers: BTreeSet<IpAddr>,
    /// Destination ports this host initiated toward, per destination host.
    pub scanned_ports: HashMap<IpAddr, BTreeSet<u16>>,
}

/// Owns all state built up while packets stream through.
#[derive(Debug)]
pub struct Analyzer {
    pub config: AnalysisConfig,
    pub counters: Counters,
    pub flows: FlowTable,
    pub dns: DnsIndex,
    pub tls: TlsIndex,
    pub http: HttpIndex,
    pub arp: ArpIndex,
    pub hosts: HashMap<IpAddr, HostStat>,
    /// Traffic volume bucketed into one-second bins for the timeline chart.
    pub timeline: BTreeMap<i64, (u64, u64)>,
    /// Rebuilds the head of each TCP direction so application messages split
    /// across segments are still decoded.
    pub reassembly: Reassembler,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new(AnalysisConfig::default())
    }
}

impl Analyzer {
    pub fn new(config: AnalysisConfig) -> Self {
        Self {
            config,
            counters: Counters::default(),
            flows: FlowTable::new(),
            dns: DnsIndex::default(),
            tls: TlsIndex::default(),
            http: HttpIndex::default(),
            arp: ArpIndex::default(),
            hosts: HashMap::new(),
            timeline: BTreeMap::new(),
            reassembly: Reassembler::new(),
        }
    }

    /// Fold one decoded packet into every index.
    ///
    /// `frame` is the buffer `pkt` was decoded from. It is needed because
    /// `DecodedPacket` stores an offset to its payload rather than a copy of
    /// it, and the stream reassembler works on those bytes. Pass an empty
    /// slice and everything except reassembly still works.
    pub fn observe(&mut self, pkt: &DecodedPacket, frame: &[u8]) {
        self.count(pkt);
        self.flows.observe(pkt);
        self.index_hosts(pkt);
        self.index_arp(pkt);
        self.index_app(&pkt.app, pkt);

        // Anything the reassembler hands back was missed by single-segment
        // decoding, so it has not been counted yet and must go through the
        // same indexing a normal packet would.
        if let Some(app) = self.reassembly.push(pkt, frame) {
            self.index_app(&app, pkt);
            if let Some((key, _)) = crate::flow::FlowKey::from_packet(pkt) {
                self.flows.record_app(&key, &app);
            }
        }
    }

    fn count(&mut self, pkt: &DecodedPacket) {
        let c = &mut self.counters;
        c.packets += 1;
        c.bytes += pkt.meta.wire_len as u64;
        c.captured_bytes += pkt.meta.captured_len as u64;
        if pkt.meta.is_truncated() {
            c.truncated_packets += 1;
        }
        c.decode_warnings += pkt.warnings.len() as u64;

        let ts = pkt.meta.timestamp;
        if !ts.is_zero() {
            c.first_seen = Some(c.first_seen.map_or(ts, |f| f.min(ts)));
            c.last_seen = Some(c.last_seen.map_or(ts, |l| l.max(ts)));
            let bin = self.timeline.entry(ts.secs).or_default();
            bin.0 += 1;
            bin.1 += pkt.meta.wire_len as u64;
        }

        let c = &mut self.counters;
        match &pkt.network {
            NetworkLayer::Ipv4(h) => {
                c.ipv4 += 1;
                if h.fragmented {
                    c.fragments += 1;
                }
            }
            NetworkLayer::Ipv6(h) => {
                c.ipv6 += 1;
                if h.fragmented {
                    c.fragments += 1;
                }
            }
            NetworkLayer::Arp(_) => c.arp += 1,
            NetworkLayer::None => c.other_l3 += 1,
        }
        match &pkt.transport {
            TransportLayer::Tcp(_) => c.tcp += 1,
            TransportLayer::Udp(_) => c.udp += 1,
            TransportLayer::Icmp(_) => c.icmp += 1,
            TransportLayer::None => {}
        }
    }

    fn index_hosts(&mut self, pkt: &DecodedPacket) {
        let (Some(src), Some(dst)) = (pkt.src_ip(), pkt.dst_ip()) else {
            return;
        };
        let bytes = pkt.meta.wire_len as u64;

        let s = self.hosts.entry(src).or_default();
        s.packets_sent += 1;
        s.bytes_sent += bytes;
        s.peers.insert(dst);

        // Only count connection *attempts* toward the scan signal, so a busy
        // client with many established sessions is not mistaken for a scanner.
        if let TransportLayer::Tcp(t) = &pkt.transport {
            if t.flags.is_syn_only() {
                s.scanned_ports.entry(dst).or_default().insert(t.dst_port);
            }
        }

        let d = self.hosts.entry(dst).or_default();
        d.packets_received += 1;
        d.bytes_received += bytes;
        d.peers.insert(src);
    }

    fn index_arp(&mut self, pkt: &DecodedPacket) {
        let NetworkLayer::Arp(arp) = &pkt.network else {
            return;
        };
        match arp.op {
            ArpOp::Request => self.arp.requests += 1,
            ArpOp::Reply => self.arp.replies += 1,
            ArpOp::Other(_) => {}
        }
        if arp.is_gratuitous() {
            self.arp.gratuitous += 1;
        }
        // Only replies and gratuitous announcements assert a binding; requests
        // carry a target MAC of zero.
        if arp.op == ArpOp::Reply && !arp.sender_ip.is_unspecified() {
            self.arp
                .bindings
                .entry(arp.sender_ip)
                .or_default()
                .insert(arp.sender_mac);
        }
    }

    fn index_app(&mut self, app: &AppLayer, pkt: &DecodedPacket) {
        match app {
            AppLayer::Dns(d) => {
                if let Some(server) = if d.is_response {
                    pkt.src_ip()
                } else {
                    pkt.dst_ip()
                } {
                    *self.dns.servers.entry(server).or_default() += 1;
                }
                for q in &d.questions {
                    let name = q.name.to_ascii_lowercase();
                    let stat = self.dns.names.entry(name.clone()).or_default();
                    if d.is_response {
                        stat.responses += 1;
                        if d.rcode == 3 {
                            stat.nxdomain += 1;
                        }
                    } else {
                        stat.queries += 1;
                    }
                    stat.qtypes.insert(q.qtype);

                    let parent = parent_domain(&name);
                    if parent != name {
                        let set = self.dns.subdomains.entry(parent).or_default();
                        // Cap growth under a tunnelling flood; the count is
                        // already past any threshold by then.
                        if set.len() < 10_000 {
                            set.insert(name.clone());
                        }
                    }
                }
                for a in &d.answers {
                    if let Some(stat) = self.dns.names.get_mut(&a.name.to_ascii_lowercase()) {
                        if stat.resolved.len() < 32 {
                            stat.resolved.insert(a.data.clone());
                        }
                    }
                }
            }
            AppLayer::Tls(t) => {
                if let Some(sni) = &t.sni {
                    *self.tls.sni.entry(sni.to_ascii_lowercase()).or_default() += 1;
                } else if t.kind == crate::proto::TlsHelloKind::Client {
                    self.tls.no_sni += 1;
                }
                if t.kind == crate::proto::TlsHelloKind::Client {
                    let e = self
                        .tls
                        .ja3
                        .entry(t.ja3_md5.clone())
                        .or_insert((0, t.sni.clone()));
                    e.0 += 1;
                }
                if t.is_obsolete_version() {
                    self.tls.obsolete_versions += 1;
                }
            }
            AppLayer::Http(h) => {
                use crate::proto::HttpKind;
                match h.kind {
                    HttpKind::Request => self.http.requests += 1,
                    HttpKind::Response => self.http.responses += 1,
                }
                if let Some(host) = &h.host {
                    *self
                        .http
                        .hosts
                        .entry(host.to_ascii_lowercase())
                        .or_default() += 1;
                }
                if let Some(ua) = &h.user_agent {
                    *self.http.user_agents.entry(ua.clone()).or_default() += 1;
                }
                if h.has_authorization {
                    self.http.cleartext_auth += 1;
                    if self.http.credential_requests.len() < 50 {
                        self.http.credential_requests.push(h.summary());
                    }
                }
            }
            AppLayer::None => {}
        }
    }

    /// Total capture duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        match (self.counters.first_seen, self.counters.last_seen) {
            (Some(f), Some(l)) => l.delta_secs(f),
            _ => 0.0,
        }
    }

    /// Hosts sorted by total bytes, descending.
    pub fn top_talkers(&self, n: usize) -> Vec<TalkerStat> {
        let mut v: Vec<TalkerStat> = self
            .hosts
            .iter()
            .map(|(ip, s)| TalkerStat {
                address: ip.to_string(),
                packets_sent: s.packets_sent,
                packets_received: s.packets_received,
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                total_bytes: s.bytes_sent + s.bytes_received,
                peers: s.peers.len(),
                private: crate::net::is_private(*ip),
            })
            .collect();
        v.sort_by(|a, b| {
            b.total_bytes
                .cmp(&a.total_bytes)
                .then_with(|| a.address.cmp(&b.address))
        });
        v.truncate(n);
        v
    }

    /// Traffic broken down by recognised service.
    ///
    /// Keyed on (protocol, port) rather than service name: DNS over UDP and
    /// DNS over TCP are different things operationally, and rolling 139 and
    /// 445 into one "smb" row would report a port that half the traffic never
    /// touched.
    pub fn services(&self, n: usize) -> Vec<ServiceStat> {
        let mut map: BTreeMap<(u8, u16), ServiceStat> = BTreeMap::new();
        for flow in self.flows.iter() {
            let Some((_, port, name)) = flow.service() else {
                continue;
            };
            let e = map
                .entry((flow.key.protocol, port))
                .or_insert_with(|| ServiceStat {
                    service: name.to_string(),
                    port,
                    protocol: crate::net::proto_name(flow.key.protocol).to_string(),
                    flows: 0,
                    packets: 0,
                    bytes: 0,
                });
            e.flows += 1;
            e.packets += flow.packets();
            e.bytes += flow.bytes();
        }
        let mut v: Vec<ServiceStat> = map.into_values().collect();
        v.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.service.cmp(&b.service))
                .then_with(|| a.port.cmp(&b.port))
        });
        v.truncate(n);
        v
    }

    /// Beacon candidates across all flows, strongest first.
    pub fn beacons(&self) -> Vec<BeaconScore> {
        let cfg = &self.config;
        let mut out = Vec::new();
        for flow in self.flows.iter() {
            // Score the initiator side only: the server's replies inherit the
            // client's cadence, so scoring both would double-report every
            // candidate at the same interval.
            let stats = flow.client_stats();
            if stats.packets < cfg.beacon_min_packets as u64 {
                continue;
            }
            let Some(score) = score_intervals(&stats.timestamps) else {
                continue;
            };
            if score.jitter > cfg.beacon_max_jitter
                || score.interval < cfg.beacon_interval_range.0
                || score.interval > cfg.beacon_interval_range.1
            {
                continue;
            }
            let (server_ip, server_port) = flow.server();
            out.push(BeaconScore {
                flow: flow.key.to_string(),
                destination: format!("{server_ip}:{server_port}"),
                sni: flow.sni.clone(),
                samples_truncated: stats.samples_truncated,
                ..score
            });
        }
        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.flow.cmp(&b.flow))
        });
        out
    }

    /// Everything the heuristics flagged, most severe first.
    pub fn findings(&self) -> Vec<Finding> {
        findings::collect(self)
    }

    /// Build the full serialisable report.
    pub fn report(&self, source: impl Into<String>) -> Report {
        report::build(self, source.into())
    }

    /// True when nothing at all was observed.
    pub fn is_empty(&self) -> bool {
        self.counters.packets == 0
    }
}

/// Convenience: count of TCP flows that never got a response.
pub(crate) fn unanswered_syn_count(analyzer: &Analyzer) -> usize {
    analyzer
        .flows
        .iter()
        .filter(|f| f.key.protocol == proto_num::TCP && f.is_unanswered_syn())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{decode, LinkType, PacketMeta};

    pub(crate) fn frame_udp_dns(qname: &str, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut dns = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in qname.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let mut udp = vec![0xc3, 0x50, 0x00, 0x35];
        udp.extend_from_slice(&((dns.len() + 8) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&dns);

        let total = (20 + udp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, proto_num::UDP, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    pub(crate) fn at(index: u64, ts: f64, bytes: &[u8]) -> DecodedPacket {
        decode(
            PacketMeta {
                index,
                timestamp: Timestamp::new(ts.trunc() as i64, (ts.fract() * 1e9) as u32),
                captured_len: bytes.len() as u32,
                wire_len: bytes.len() as u32,
            },
            bytes,
            LinkType::Ethernet,
        )
    }

    #[test]
    fn counts_and_indexes_dns() {
        let mut a = Analyzer::default();
        let f = frame_udp_dns("telemetry.example.com", [10, 0, 0, 5], [10, 0, 0, 1]);
        a.observe(&at(1, 100.0, &f), &f);
        a.observe(&at(2, 101.0, &f), &f);

        assert_eq!(a.counters.packets, 2);
        assert_eq!(a.counters.udp, 2);
        assert_eq!(a.counters.ipv4, 2);
        assert_eq!(a.flows.len(), 1);
        assert_eq!(a.dns.names["telemetry.example.com"].queries, 2);
        assert_eq!(a.dns.subdomains["example.com"].len(), 1);
        assert!((a.duration_secs() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn talkers_rank_by_volume() {
        let mut a = Analyzer::default();
        let quiet = frame_udp_dns("a.example.com", [10, 0, 0, 5], [10, 0, 0, 1]);
        let loud = frame_udp_dns(
            "a-much-longer-name-that-makes-the-frame-bigger.example.com",
            [10, 0, 0, 6],
            [10, 0, 0, 1],
        );
        a.observe(&at(1, 1.0, &quiet), &quiet);
        for i in 0..5 {
            a.observe(&at(i + 2, 1.0, &loud), &loud);
        }
        let talkers = a.top_talkers(5);
        assert_eq!(talkers[0].address, "10.0.0.1"); // the server sees both sides
        assert!(talkers.iter().any(|t| t.address == "10.0.0.6"));
        assert!(talkers.iter().all(|t| t.private));
    }

    #[test]
    fn services_separate_udp_and_tcp_on_the_same_port() {
        let mut a = Analyzer::default();
        // Two DNS-over-UDP flows and one TCP SYN to port 53 (scan residue).
        let a_query = frame_udp_dns("a.example.com", [10, 0, 0, 5], [10, 0, 0, 1]);
        let b_query = frame_udp_dns("b.example.com", [10, 0, 0, 6], [10, 0, 0, 1]);
        let syn = tcp_syn([10, 0, 0, 9], 40000, [10, 0, 0, 1], 53);
        a.observe(&at(1, 1.0, &a_query), &a_query);
        a.observe(&at(2, 2.0, &b_query), &b_query);
        a.observe(&at(3, 3.0, &syn), &syn);

        let services = a.services(10);
        let dns_rows: Vec<_> = services.iter().filter(|s| s.service == "dns").collect();
        assert_eq!(dns_rows.len(), 2, "udp and tcp dns must not be merged");
        assert!(dns_rows.iter().any(|s| s.protocol == "UDP" && s.flows == 2));
        assert!(dns_rows.iter().any(|s| s.protocol == "TCP" && s.flows == 1));
    }

    pub(crate) fn tcp_syn(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        t.extend_from_slice(&[0x50, 0x02]);
        t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);

        let total = (20 + t.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, proto_num::TCP, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&t);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// A PSH|ACK segment carrying `payload`, for exercising L7 decoding.
    pub(crate) fn tcp_data(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
        t.extend_from_slice(&[0x50, 0x18]);
        t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        t.extend_from_slice(payload);

        let total = (20 + t.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, proto_num::TCP, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&t);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// A PSH|ACK segment with a caller-chosen sequence number, for driving the
    /// stream reassembler.
    pub(crate) fn tcp_seg(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 0]);
        t.extend_from_slice(&[0x50, 0x18]);
        t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        t.extend_from_slice(payload);

        let total = (20 + t.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, proto_num::TCP, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&t);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// A ServerHello selecting `version`, with no extensions — so the legacy
    /// version field is the negotiated one.
    pub(crate) fn tls_server_hello(version: u16) -> Vec<u8> {
        let mut hs = version.to_be_bytes().to_vec();
        hs.extend_from_slice(&[0x7a; 32]);
        hs.push(0x00);
        hs.extend_from_slice(&[0x00, 0x2f]);
        hs.push(0x00);

        let mut handshake = vec![0x02];
        handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hs);

        let mut record = vec![0x16];
        record.extend_from_slice(&version.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn empty_analyzer_is_reportable() {
        let a = Analyzer::default();
        assert!(a.is_empty());
        let r = a.report("none");
        assert_eq!(r.summary.packets, 0);
        assert!(r.findings.is_empty());
    }
}
