//! Drives a [`Source`] through the decoder into an [`Analyzer`].

use anyhow::{Context, Result};
use cbna_capture::{CaptureError, Source};
use cbna_core::analysis::{AnalysisConfig, Analyzer};
use cbna_core::packet::{decode, DecodedPacket};

/// What to do with each packet as it is decoded.
pub type PacketHook<'a> = &'a mut dyn FnMut(&DecodedPacket);

/// Outcome of a run, separate from the analysis itself.
#[derive(Debug, Default, Clone)]
pub struct RunStats {
    pub packets: u64,
    /// Files that were cut short or contained a bad record still produce
    /// results; the error is reported rather than swallowed.
    pub read_errors: Vec<String>,
}

/// Read every packet from `source` into a fresh analyzer.
pub fn run(
    source: &mut dyn Source,
    config: AnalysisConfig,
    limit: Option<u64>,
    mut hook: Option<PacketHook<'_>>,
) -> Result<(Analyzer, RunStats)> {
    let mut analyzer = Analyzer::new(config);
    let mut stats = RunStats::default();
    let link_type = source.link_type();

    while let Some(next) = source.next_packet() {
        match next {
            Ok(raw) => {
                let pkt = decode(raw.meta, &raw.data, link_type);
                if let Some(h) = hook.as_deref_mut() {
                    h(&pkt);
                }
                analyzer.observe(&pkt, &raw.data);
                stats.packets += 1;
                if limit.is_some_and(|n| stats.packets >= n) {
                    break;
                }
            }
            Err(e) => {
                stats.read_errors.push(e.to_string());
                // A single malformed record should not discard the analysis of
                // everything before it, but repeated failures mean the file is
                // unusable and continuing would just spin.
                if stats.read_errors.len() >= 8 {
                    break;
                }
            }
        }
    }

    Ok((analyzer, stats))
}

/// Convenience wrapper for the offline path.
pub fn run_file(
    path: &std::path::Path,
    config: AnalysisConfig,
    limit: Option<u64>,
    hook: Option<PacketHook<'_>>,
) -> Result<(Analyzer, RunStats, String)> {
    let mut source = cbna_capture::open_file(path)
        .with_context(|| format!("opening capture file {}", path.display()))?;
    let description = source.description();
    let (analyzer, stats) = run(&mut source, config, limit, hook)?;
    Ok((analyzer, stats, description))
}

/// Map a capture error to a message worth showing a user.
pub fn explain(err: &CaptureError) -> String {
    match err {
        CaptureError::LiveUnavailable => {
            "This build has no live-capture support. Rebuild with `cargo build --release \
             --features live` (see README for the Npcap SDK step on Windows)."
                .to_string()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbna_capture::{PcapWriter, RawPacket};
    use cbna_core::packet::LinkType;
    use cbna_core::Timestamp;

    fn dns_frame(name: &str) -> Vec<u8> {
        let mut dns = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
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
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 5]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    #[test]
    fn analyses_a_written_capture_end_to_end() {
        let mut path = std::env::temp_dir();
        path.push(format!("cbna-pipeline-{}.pcap", std::process::id()));
        {
            let mut w = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            for i in 0..10u32 {
                let frame = dns_frame("beacon.example.net");
                w.write(&RawPacket::new(
                    i as u64,
                    Timestamp::new(1_786_365_296 + i as i64 * 60, 0),
                    frame.len() as u32,
                    frame,
                ))
                .unwrap();
            }
        }

        let (analyzer, stats, description) =
            run_file(&path, AnalysisConfig::default(), None, None).unwrap();
        assert_eq!(stats.packets, 10);
        assert!(stats.read_errors.is_empty());
        assert!(description.contains("pcap"));
        assert_eq!(analyzer.counters.packets, 10);
        assert_eq!(analyzer.dns.names.len(), 1);

        // Ten evenly spaced queries is exactly the beacon shape.
        let report = analyzer.report(description);
        assert!(!report.beacons.is_empty());
        assert!((report.beacons[0].interval - 60.0).abs() < 1e-6);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn honours_the_packet_limit_and_hook() {
        let mut path = std::env::temp_dir();
        path.push(format!("cbna-limit-{}.pcap", std::process::id()));
        {
            let mut w = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
            for i in 0..20u32 {
                let frame = dns_frame("a.example.net");
                w.write(&RawPacket::new(
                    i as u64,
                    Timestamp::new(i as i64, 0),
                    frame.len() as u32,
                    frame,
                ))
                .unwrap();
            }
        }

        let mut seen = 0usize;
        let mut hook = |_: &DecodedPacket| seen += 1;
        let (analyzer, stats, _) =
            run_file(&path, AnalysisConfig::default(), Some(5), Some(&mut hook)).unwrap();
        assert_eq!(stats.packets, 5);
        assert_eq!(seen, 5);
        assert_eq!(analyzer.counters.packets, 5);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_reported_with_context() {
        let err = run_file(
            std::path::Path::new("definitely-not-here.pcap"),
            AnalysisConfig::default(),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("definitely-not-here.pcap"));
    }
}
