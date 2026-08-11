//! The serialisable report shared by the CLI, the JSON output and the web UI.

use super::{Analyzer, BeaconScore, Finding};
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub packets: u64,
    pub bytes: u64,
    pub captured_bytes: u64,
    pub flows: usize,
    pub hosts: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub duration_secs: f64,
    pub packets_per_sec: f64,
    pub bits_per_sec: f64,
    pub truncated_packets: u64,
    pub decode_warnings: u64,
    pub counts: ProtocolCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCounts {
    pub ipv4: u64,
    pub ipv6: u64,
    pub arp: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub other: u64,
    pub fragments: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkerStat {
    pub address: String,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
    pub peers: usize,
    pub private: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStat {
    pub service: String,
    pub port: u16,
    pub protocol: String,
    pub flows: u64,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub flow: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub service: Option<String>,
    pub scope: String,
    pub packets: u64,
    pub bytes: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_secs: f64,
    pub first_seen: String,
    pub last_seen: String,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub protocols: Vec<String>,
    pub reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOverview {
    pub unique_names: usize,
    pub queries: u64,
    pub nxdomain: u64,
    pub servers: Vec<(String, u64)>,
    pub top_names: Vec<(String, u64)>,
    pub top_parents: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsOverview {
    pub handshakes: u64,
    pub unique_sni: usize,
    pub no_sni: u64,
    pub obsolete_versions: u64,
    pub top_sni: Vec<(String, u64)>,
    /// (ja3 hash, count, example SNI)
    pub top_ja3: Vec<(String, u64, Option<String>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOverview {
    pub requests: u64,
    pub responses: u64,
    pub cleartext_auth: u64,
    pub top_hosts: Vec<(String, u64)>,
    pub top_user_agents: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub generated_at: String,
    pub source: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub talkers: Vec<TalkerStat>,
    pub services: Vec<ServiceStat>,
    pub top_flows: Vec<FlowSummary>,
    pub beacons: Vec<BeaconScore>,
    pub dns: DnsOverview,
    pub tls: TlsOverview,
    pub http: HttpOverview,
    /// (unix second, packets, bytes) for the activity timeline.
    pub timeline: Vec<(i64, u64, u64)>,
}

pub(super) fn build(a: &Analyzer, source: String) -> Report {
    let n = a.config.top_n;
    let duration = a.duration_secs();
    let c = &a.counters;

    let summary = Summary {
        packets: c.packets,
        bytes: c.bytes,
        captured_bytes: c.captured_bytes,
        flows: a.flows.len(),
        hosts: a.hosts.len(),
        first_seen: c.first_seen.map(|t| t.to_rfc3339()),
        last_seen: c.last_seen.map(|t| t.to_rfc3339()),
        duration_secs: duration,
        packets_per_sec: rate(c.packets as f64, duration),
        bits_per_sec: rate(c.bytes as f64 * 8.0, duration),
        truncated_packets: c.truncated_packets,
        decode_warnings: c.decode_warnings,
        counts: ProtocolCounts {
            ipv4: c.ipv4,
            ipv6: c.ipv6,
            arp: c.arp,
            tcp: c.tcp,
            udp: c.udp,
            icmp: c.icmp,
            other: c.other_l3,
            fragments: c.fragments,
        },
    };

    let top_flows = a
        .flows
        .by_bytes()
        .into_iter()
        .take(n)
        .map(flow_summary)
        .collect();

    let mut top_names: Vec<(String, u64)> = a
        .dns
        .names
        .iter()
        .map(|(k, v)| (k.clone(), v.queries + v.responses))
        .collect();
    top_names.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    top_names.truncate(n);

    let mut top_parents: Vec<(String, usize)> = a
        .dns
        .subdomains
        .iter()
        .map(|(k, v)| (k.clone(), v.len()))
        .collect();
    top_parents.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    top_parents.truncate(n);

    let mut servers: Vec<(String, u64)> = a
        .dns
        .servers
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();
    servers.sort_by_key(|s| Reverse(s.1));
    servers.truncate(n);

    let dns = DnsOverview {
        unique_names: a.dns.names.len(),
        queries: a.dns.names.values().map(|s| s.queries).sum(),
        nxdomain: a.dns.names.values().map(|s| s.nxdomain).sum(),
        servers,
        top_names,
        top_parents,
    };

    let mut top_sni: Vec<(String, u64)> = a.tls.sni.iter().map(|(k, v)| (k.clone(), *v)).collect();
    top_sni.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    top_sni.truncate(n);

    let mut top_ja3: Vec<(String, u64, Option<String>)> = a
        .tls
        .ja3
        .iter()
        .map(|(k, (count, sni))| (k.clone(), *count, sni.clone()))
        .collect();
    top_ja3.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    top_ja3.truncate(n);

    let tls = TlsOverview {
        handshakes: a.tls.sni.values().sum::<u64>() + a.tls.no_sni,
        unique_sni: a.tls.sni.len(),
        no_sni: a.tls.no_sni,
        obsolete_versions: a.tls.obsolete_versions,
        top_sni,
        top_ja3,
    };

    let http = HttpOverview {
        requests: a.http.requests,
        responses: a.http.responses,
        cleartext_auth: a.http.cleartext_auth,
        top_hosts: top_map(&a.http.hosts, n),
        top_user_agents: top_map(&a.http.user_agents, n),
    };

    Report {
        tool: format!("cbna {}", env!("CARGO_PKG_VERSION")),
        generated_at: Timestamp::new(now_unix(), 0).to_rfc3339(),
        source,
        summary,
        findings: a.findings(),
        talkers: a.top_talkers(n),
        services: a.services(n),
        top_flows,
        beacons: a.beacons().into_iter().take(n).collect(),
        dns,
        tls,
        http,
        timeline: a
            .timeline
            .iter()
            .map(|(sec, (packets, bytes))| (*sec, *packets, *bytes))
            .collect(),
    }
}

fn flow_summary(f: &crate::flow::Flow) -> FlowSummary {
    FlowSummary {
        flow: f.key.to_string(),
        source: format!("{}:{}", f.client().0, f.client().1),
        destination: format!("{}:{}", f.server().0, f.server().1),
        protocol: crate::net::proto_name(f.key.protocol).to_string(),
        service: f.service().map(|(_, _, name)| name.to_string()),
        scope: f.scope().to_string(),
        packets: f.packets(),
        bytes: f.bytes(),
        bytes_up: f.client_stats().bytes,
        bytes_down: f.server_stats().bytes,
        duration_secs: f.duration_secs(),
        first_seen: f.first_seen.to_rfc3339(),
        last_seen: f.last_seen.to_rfc3339(),
        sni: f.sni.clone(),
        ja3: f.ja3.clone(),
        protocols: f.protocols.iter().cloned().collect(),
        reset: f.was_reset(),
    }
}

fn top_map(map: &std::collections::BTreeMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    v.truncate(n);
    v
}

fn rate(total: f64, duration: f64) -> f64 {
    if duration > 0.0 {
        total / duration
    } else {
        0.0
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{at, frame_udp_dns};
    use super::*;
    use crate::analysis::Analyzer;

    #[test]
    fn report_round_trips_through_json() {
        let mut a = Analyzer::default();
        let f = frame_udp_dns("www.example.com", [10, 0, 0, 5], [10, 0, 0, 1]);
        a.observe(&at(1, 100.0, &f), &f);
        a.observe(&at(2, 103.0, &f), &f);

        let report = a.report("unit-test.pcap");
        assert_eq!(report.summary.packets, 2);
        assert_eq!(report.summary.flows, 1);
        assert_eq!(report.dns.unique_names, 1);
        assert_eq!(report.timeline.len(), 2);
        assert!(report.summary.packets_per_sec > 0.0);

        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("www.example.com"));
        assert!(json.contains("\"source\":\"unit-test.pcap\""));
    }

    #[test]
    fn rate_is_zero_for_instantaneous_captures() {
        assert_eq!(rate(100.0, 0.0), 0.0);
        assert_eq!(rate(100.0, 2.0), 50.0);
    }
}
