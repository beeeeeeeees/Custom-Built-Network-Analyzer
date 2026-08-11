//! Heuristics that turn indexed traffic into reviewable findings.
//!
//! Every finding is evidence-bearing: it names the flow or host it came from so
//! an analyst can go back to the capture and confirm. None of these are
//! verdicts — they are leads, ordered so the strongest ones surface first.

use super::{unanswered_syn_count, Analyzer};
use crate::net::is_private;
use crate::proto::shannon_entropy;
use crate::proto::tls::version_name as tls_version_name;
use crate::time::{human_bytes, human_duration, human_percent};
use crate::transport::is_cleartext_service;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fmt;

/// Serialized lowercase so the JSON matches the `Display` impl and the terminal
/// report. Consumers key off these strings — the dashboard styles severity
/// badges by class name — so the two renderings must not diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable slug, so downstream tooling can match on it.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Concrete observations backing the finding.
    pub evidence: Vec<String>,
}

impl Finding {
    fn new(
        id: &str,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.to_string(),
            severity,
            title: title.into(),
            detail: detail.into(),
            evidence: Vec::new(),
        }
    }

    fn with(mut self, evidence: impl IntoIterator<Item = String>) -> Self {
        self.evidence = evidence.into_iter().take(12).collect();
        self
    }
}

pub(super) fn collect(a: &Analyzer) -> Vec<Finding> {
    let mut out = Vec::new();
    beaconing(a, &mut out);
    dns_tunnelling(a, &mut out);
    dga_like_names(a, &mut out);
    port_scanning(a, &mut out);
    data_egress(a, &mut out);
    cleartext_credentials(a, &mut out);
    cleartext_services(a, &mut out);
    obsolete_tls(a, &mut out);
    overlapping_segments(a, &mut out);
    arp_conflicts(a, &mut out);
    capture_quality(a, &mut out);

    out.sort_by(|x, y| y.severity.cmp(&x.severity).then_with(|| x.id.cmp(&y.id)));
    out
}

fn beaconing(a: &Analyzer, out: &mut Vec<Finding>) {
    let beacons = a.beacons();
    if beacons.is_empty() {
        return;
    }
    let strong = beacons.iter().filter(|b| b.confidence >= 0.8).count();
    let severity = if strong > 0 {
        Severity::High
    } else {
        Severity::Medium
    };

    let evidence = beacons.iter().take(12).map(|b| {
        format!(
            "{} every {} (jitter {}, {} samples, confidence {:.2}){}",
            b.flow,
            human_duration(b.interval),
            human_percent(b.jitter),
            b.samples,
            b.confidence,
            b.sni
                .as_ref()
                .map(|s| format!(" sni={s}"))
                .unwrap_or_default()
        )
    });

    out.push(
        Finding::new(
            "periodic-beaconing",
            severity,
            format!("{} flow(s) with machine-regular timing", beacons.len()),
            "Inter-arrival times are far more regular than human-driven traffic. \
             Scheduled jobs and telemetry agents look like this too — confirm the \
             process behind the connection before escalating.",
        )
        .with(evidence),
    );
}

fn dns_tunnelling(a: &Analyzer, out: &mut Vec<Finding>) {
    let threshold = a.config.dns_subdomain_threshold;
    let mut hits: Vec<(&String, usize)> = a
        .dns
        .subdomains
        .iter()
        .filter(|(_, subs)| subs.len() >= threshold)
        .map(|(parent, subs)| (parent, subs.len()))
        .collect();
    if hits.is_empty() {
        return;
    }
    hits.sort_by_key(|h| Reverse(h.1));

    let evidence = hits.iter().take(12).map(|(parent, count)| {
        let sample = a
            .dns
            .subdomains
            .get(*parent)
            .and_then(|s| s.iter().next())
            .cloned()
            .unwrap_or_default();
        format!("{parent}: {count} distinct subdomains, e.g. {sample}")
    });

    out.push(
        Finding::new(
            "dns-subdomain-volume",
            Severity::High,
            format!(
                "{} domain(s) queried with unusually many subdomains",
                hits.len()
            ),
            "A high count of distinct subdomains under one parent is the standard \
             signature of DNS tunnelling or data staging over DNS. CDNs and some \
             AV vendors also generate these, so check the parent domain's reputation.",
        )
        .with(evidence),
    );
}

fn dga_like_names(a: &Analyzer, out: &mut Vec<Finding>) {
    let mut hits: Vec<(String, f64, u64)> = Vec::new();
    for (name, stat) in &a.dns.names {
        let label = name.split('.').next().unwrap_or(name);
        // Short labels have unstable entropy; require some length first.
        if label.len() < 12 {
            continue;
        }
        let entropy = shannon_entropy(label);
        if entropy >= a.config.dns_entropy_threshold {
            hits.push((name.clone(), entropy, stat.queries + stat.responses));
        }
    }
    if hits.is_empty() {
        return;
    }
    hits.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap_or(std::cmp::Ordering::Equal));

    let nxdomain_heavy = hits
        .iter()
        .filter(|(n, _, _)| a.dns.names.get(n).is_some_and(|s| s.nxdomain > 0))
        .count();
    let severity = if nxdomain_heavy > 2 {
        Severity::High
    } else {
        Severity::Medium
    };

    let evidence = hits.iter().take(12).map(|(name, entropy, count)| {
        let nx = a.dns.names.get(name).map(|s| s.nxdomain).unwrap_or(0);
        format!(
            "{name} (entropy {entropy:.2} bits/char, {count} lookups{})",
            if nx > 0 {
                format!(", {nx} NXDOMAIN")
            } else {
                String::new()
            }
        )
    });

    out.push(
        Finding::new(
            "high-entropy-dns",
            severity,
            format!("{} high-entropy DNS name(s)", hits.len()),
            "Randomised-looking labels are produced by domain generation algorithms \
             and by encoded tunnel payloads. Cloud and CDN infrastructure also uses \
             hashed hostnames, so correlate with the parent domain before acting.",
        )
        .with(evidence),
    );
}

fn port_scanning(a: &Analyzer, out: &mut Vec<Finding>) {
    let threshold = a.config.scan_port_threshold;
    let mut hits: Vec<(String, usize, usize)> = Vec::new();
    for (ip, stat) in &a.hosts {
        let widest = stat
            .scanned_ports
            .values()
            .map(|ports| ports.len())
            .max()
            .unwrap_or(0);
        let total_targets = stat
            .scanned_ports
            .iter()
            .filter(|(_, ports)| ports.len() > 1)
            .count();
        if widest >= threshold {
            hits.push((ip.to_string(), widest, total_targets));
        }
    }
    if hits.is_empty() {
        return;
    }
    hits.sort_by_key(|h| Reverse(h.1));

    let unanswered = unanswered_syn_count(a);
    let evidence = hits.iter().take(12).map(|(ip, widest, targets)| {
        format!("{ip}: up to {widest} ports probed on a single host, {targets} host(s) targeted")
    });

    out.push(
        Finding::new(
            "port-scan",
            Severity::High,
            format!("{} host(s) exhibiting port-scan behaviour", hits.len()),
            format!(
                "SYNs were sent to many ports on the same destination. \
                 {unanswered} TCP flow(s) in this capture never received a reply, \
                 which is consistent with scanning closed or filtered ports. \
                 Vulnerability scanners and monitoring agents produce the same pattern."
            ),
        )
        .with(evidence),
    );
}

fn data_egress(a: &Analyzer, out: &mut Vec<Finding>) {
    use crate::flow::FlowScope;
    let cfg = &a.config;
    let mut hits: Vec<String> = Vec::new();
    let mut worst = 0u64;

    for flow in a.flows.iter() {
        if flow.scope() != FlowScope::Outbound {
            continue;
        }
        let up = flow.client_stats().payload_bytes;
        if up < cfg.exfil_bytes_threshold {
            continue;
        }
        let ratio = flow.upload_ratio();
        if ratio < cfg.exfil_ratio_threshold {
            continue;
        }
        worst = worst.max(up);
        hits.push(format!(
            "{} sent {} up vs {} down (ratio {:.1}x) over {}{}",
            flow.key,
            human_bytes(up),
            human_bytes(flow.server_stats().payload_bytes),
            ratio,
            human_duration(flow.duration_secs()),
            flow.sni
                .as_ref()
                .map(|s| format!(" sni={s}"))
                .unwrap_or_default()
        ));
    }
    if hits.is_empty() {
        return;
    }

    out.push(
        Finding::new(
            "outbound-upload-heavy",
            Severity::Medium,
            format!("{} outbound flow(s) dominated by upload", hits.len()),
            format!(
                "Internal hosts pushed substantially more data out than they pulled back \
                 (largest single flow: {}). Backups, cloud sync and CI artefact uploads \
                 look identical — confirm the destination is expected.",
                human_bytes(worst)
            ),
        )
        .with(hits),
    );
}

fn cleartext_credentials(a: &Analyzer, out: &mut Vec<Finding>) {
    if a.http.cleartext_auth == 0 {
        return;
    }
    out.push(
        Finding::new(
            "cleartext-http-credentials",
            Severity::High,
            format!(
                "HTTP Authorization sent in the clear on {} request(s)",
                a.http.cleartext_auth
            ),
            "Credentials travelled over unencrypted HTTP and are recoverable by anyone \
             on the path. The header values are not stored by this tool; re-run with the \
             capture in a packet viewer if you need to confirm the account.",
        )
        .with(a.http.credential_requests.iter().cloned()),
    );
}

fn cleartext_services(a: &Analyzer, out: &mut Vec<Finding>) {
    let mut hits: Vec<String> = Vec::new();
    for flow in a.flows.iter() {
        let Some((ip, port, _)) = flow.service() else {
            continue;
        };
        let Some(name) =
            is_cleartext_service(port, flow.key.protocol == crate::net::proto_num::TCP)
        else {
            continue;
        };
        // Only meaningful once data actually moved.
        if flow.a_to_b.payload_bytes + flow.b_to_a.payload_bytes == 0 {
            continue;
        }
        hits.push(format!(
            "{name} on {ip}:{port} — {} across {} packet(s)",
            human_bytes(flow.bytes()),
            flow.packets()
        ));
    }
    if hits.is_empty() {
        return;
    }
    hits.sort();
    hits.dedup();

    out.push(
        Finding::new(
            "cleartext-service",
            Severity::Low,
            format!("{} unencrypted service flow(s)", hits.len()),
            "These protocols carry their payload, and often their authentication, \
             without transport encryption.",
        )
        .with(hits),
    );
}

fn obsolete_tls(a: &Analyzer, out: &mut Vec<Finding>) {
    if a.tls.obsolete_versions == 0 {
        return;
    }
    // Only the flows that actually negotiated an obsolete version, and named
    // whether or not they carried an SNI — an appliance with no SNI is exactly
    // the kind of thing this finding exists to surface, and listing every TLS
    // flow would send an analyst chasing modern connections.
    let evidence = a
        .flows
        .iter()
        .filter(|f| f.tls_version.is_some_and(|v| matches!(v, 0x0300..=0x0302)))
        .map(|f| {
            let version = tls_version_name(f.tls_version.unwrap_or_default());
            match &f.sni {
                Some(s) => format!("{} {version} sni={s}", f.key),
                None => format!("{} {version}", f.key),
            }
        })
        .take(12)
        .collect::<Vec<_>>();

    out.push(
        Finding::new(
            "obsolete-tls",
            Severity::Medium,
            format!(
                "{} TLS handshake(s) negotiated a deprecated version",
                a.tls.obsolete_versions
            ),
            "SSL 3.0 / TLS 1.0 / TLS 1.1 are deprecated and have known downgrade and \
             padding-oracle weaknesses. Trace these back to the client or appliance \
             that cannot negotiate anything newer.",
        )
        .with(evidence),
    );
}

/// Two segments claiming the same sequence range with different bytes.
///
/// This is the shape of the classic inspection-evasion trick: send one payload
/// that a monitor accepts and a second, overlapping one that the destination
/// host prefers, so the two disagree about what was transmitted. It also
/// happens for dull reasons — a broken middlebox, or a capture that merged two
/// taps — which is why this is a lead rather than a verdict.
fn overlapping_segments(a: &Analyzer, out: &mut Vec<Finding>) {
    let n = a.reassembly.stats().conflicting_overlaps;
    if n == 0 {
        return;
    }
    out.push(
        Finding::new(
            "tcp-overlap-conflict",
            Severity::Medium,
            format!("{n} TCP segment(s) overlapped earlier data with different bytes"),
            "Retransmissions normally repeat what they replace. A disagreement means \
             the same sequence range carried two different payloads, which is how an \
             attacker makes a monitor and the destination host read different requests. \
             Duplicated capture points and rewriting middleboxes produce it too — check \
             whether the capture merges more than one tap before escalating.",
        )
        .with(vec![format!(
            "{n} conflicting overlap(s) across {} tracked stream(s); first writer was kept",
            a.reassembly.tracked()
        )]),
    );
}

fn arp_conflicts(a: &Analyzer, out: &mut Vec<Finding>) {
    let conflicts: Vec<String> = a
        .arp
        .bindings
        .iter()
        .filter(|(_, macs)| macs.len() > 1)
        .map(|(ip, macs)| {
            format!(
                "{ip} claimed by {}",
                macs.iter()
                    .map(|m| m.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect();
    if conflicts.is_empty() {
        return;
    }

    out.push(
        Finding::new(
            "arp-address-conflict",
            Severity::High,
            format!("{} IP(s) claimed by more than one MAC", conflicts.len()),
            "Multiple hardware addresses answered for the same IP. This is the signature \
             of ARP cache poisoning, but it is also produced by HA failover pairs, \
             clustered virtual IPs and misconfigured static addressing.",
        )
        .with(conflicts),
    );
}

fn capture_quality(a: &Analyzer, out: &mut Vec<Finding>) {
    let c = &a.counters;
    let mut notes = Vec::new();

    if c.truncated_packets > 0 {
        let pct = c.truncated_packets as f64 / c.packets.max(1) as f64 * 100.0;
        notes.push(format!(
            "{} of {} packets ({pct:.1}%) were cut short by the capture snaplen — \
             application-layer decoding is incomplete for those",
            c.truncated_packets, c.packets
        ));
    }
    if c.decode_warnings > 0 {
        notes.push(format!(
            "{} decode warning(s) were raised across the capture",
            c.decode_warnings
        ));
    }
    if c.fragments > 0 {
        notes.push(format!(
            "{} IP fragment(s) seen; this tool does not reassemble, so later \
             fragments contribute bytes but no transport detail",
            c.fragments
        ));
    }
    let re = a.reassembly.stats();
    if re.recovered > 0 {
        notes.push(format!(
            "{} application message(s) were only readable after TCP stream \
             reassembly; single-segment decoding alone would have missed them",
            re.recovered
        ));
    }
    if re.dropped_streams > 0 {
        notes.push(format!(
            "{} TCP direction(s) went untracked because the reassembly stream \
             table was full, so split messages on those were not rebuilt",
            re.dropped_streams
        ));
    }
    let external_only = a.hosts.keys().all(|ip| !is_private(*ip));
    if !a.hosts.is_empty() && external_only {
        notes.push(
            "No RFC1918 / link-local addresses were observed, so internal-vs-external \
             flow classification is not meaningful for this capture"
                .to_string(),
        );
    }

    if notes.is_empty() {
        return;
    }
    out.push(
        Finding::new(
            "capture-quality",
            Severity::Info,
            "Capture caveats affecting confidence",
            "Conditions in the capture itself that limit what the analysis can see.",
        )
        .with(notes),
    );
}

#[cfg(test)]
mod tests {
    use super::super::tests::{at, frame_udp_dns};
    use super::*;
    use crate::analysis::{AnalysisConfig, Analyzer};

    #[test]
    fn severity_serializes_lowercase_to_match_display() {
        // The dashboard derives a CSS class from this string and the terminal
        // prints the Display form; if they diverge, badges lose their colour
        // silently and severity filters match nothing.
        for sev in [
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            assert_eq!(json, format!("\"{sev}\""));
        }
    }

    #[test]
    fn severity_orders_high_first() {
        let mut v = [
            Severity::Info,
            Severity::High,
            Severity::Low,
            Severity::Medium,
        ];
        v.sort_by(|a, b| b.cmp(a));
        assert_eq!(v[0], Severity::High);
        assert_eq!(v[3], Severity::Info);
    }

    #[test]
    fn flags_dns_subdomain_volume() {
        let cfg = AnalysisConfig {
            dns_subdomain_threshold: 5,
            ..Default::default()
        };
        let mut a = Analyzer::new(cfg);
        for i in 0..8 {
            let name = format!("chunk{i}data.tunnel.example");
            let f = frame_udp_dns(&name, [10, 0, 0, 5], [10, 0, 0, 1]);
            a.observe(&at(i as u64, i as f64, &f), &f);
        }
        let findings = a.findings();
        let hit = findings
            .iter()
            .find(|f| f.id == "dns-subdomain-volume")
            .expect("expected the tunnelling finding");
        assert_eq!(hit.severity, Severity::High);
        assert!(hit.evidence[0].contains("tunnel.example"));
    }

    #[test]
    fn obsolete_tls_evidence_names_only_the_obsolete_flows() {
        use crate::analysis::tests::{tcp_data, tls_server_hello};

        // One legacy server and one modern one, both speaking TLS.
        let old = tcp_data(
            [10, 0, 0, 9],
            443,
            [10, 0, 0, 5],
            51000,
            &tls_server_hello(0x0301),
        );
        let new = tcp_data(
            [10, 0, 0, 8],
            443,
            [10, 0, 0, 5],
            51001,
            &tls_server_hello(0x0303),
        );
        let mut a = Analyzer::default();
        a.observe(&at(1, 1.0, &old), &old);
        a.observe(&at(2, 2.0, &new), &new);

        let findings = a.findings();
        let hit = findings
            .iter()
            .find(|f| f.id == "obsolete-tls")
            .expect("expected the obsolete-tls finding");

        // The whole point: a modern flow must never appear as evidence for a
        // deprecated-version finding, or the analyst chases the wrong host.
        assert_eq!(hit.evidence.len(), 1, "evidence: {:?}", hit.evidence);
        assert!(hit.evidence[0].contains("10.0.0.9"));
        assert!(hit.evidence[0].contains("TLS 1.0"));
        assert!(
            !hit.evidence.iter().any(|e| e.contains("10.0.0.8")),
            "the TLS 1.2 flow leaked into the evidence: {:?}",
            hit.evidence
        );
    }

    #[test]
    fn credentials_split_across_segments_are_still_found() {
        use crate::analysis::tests::tcp_seg;

        // Splitting a request across two segments used to hide everything
        // after the split: the first half parses as HTTP with a truncated Host
        // and no Authorization at all, and nothing ever looked at the rest.
        let head = b"POST /login HTTP/1.1\r\nHost: legacy.corp\r\nAuthor";
        let tail = b"ization: Basic YWRtaW46cHc=\r\nAccept: */*\r\n\r\n";

        let f1 = tcp_seg([10, 0, 0, 5], 44000, [10, 0, 0, 80], 80, 1000, head);
        let f2 = tcp_seg(
            [10, 0, 0, 5],
            44000,
            [10, 0, 0, 80],
            80,
            1000 + head.len() as u32,
            tail,
        );

        let mut a = Analyzer::default();
        a.observe(&at(1, 1.0, &f1), &f1);
        a.observe(&at(2, 1.1, &f2), &f2);

        assert_eq!(a.reassembly.stats().recovered, 1);
        let findings = a.findings();
        let hit = findings
            .iter()
            .find(|f| f.id == "cleartext-http-credentials")
            .expect("split credentials must still be reported");
        assert!(
            hit.evidence.iter().any(|e| e.contains("legacy.corp")),
            "evidence should name the real host, not the truncated one: {:?}",
            hit.evidence
        );
    }

    #[test]
    fn quiet_capture_produces_no_alarms() {
        let mut a = Analyzer::default();
        let f = frame_udp_dns("www.example.com", [10, 0, 0, 5], [10, 0, 0, 1]);
        a.observe(&at(1, 1.0, &f), &f);
        let findings = a.findings();
        assert!(
            findings.iter().all(|f| f.severity == Severity::Info),
            "unexpected findings: {findings:?}"
        );
    }
}
