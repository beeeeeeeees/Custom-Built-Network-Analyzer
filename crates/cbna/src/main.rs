//! `cbna` — Custom Built Network Analyzer.
//!
//! Offline analysis works in every build. Live capture (`devices`, `capture`,
//! `serve --iface`) needs the `live` feature and a platform capture library.

mod pipeline;
mod render;

#[cfg(feature = "live")]
mod livecmd;

use anyhow::{bail, Context, Result};
use cbna_core::analysis::{AnalysisConfig, Analyzer};
use clap::{Args, Parser, Subcommand};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cbna",
    version,
    about = "Custom Built Network Analyzer — capture, decode, and analyse network traffic",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress ANSI colour in terminal output.
    #[arg(long, global = true)]
    plain: bool,

    /// Log level for internal diagnostics (error, warn, info, debug, trace).
    #[arg(long, global = true, default_value = "warn")]
    log: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analyse a pcap or pcapng file and print a report.
    Analyze(AnalyzeArgs),

    /// Serve the web dashboard for a capture file or a live interface.
    Serve(ServeArgs),

    /// List interfaces available for live capture.
    Devices,

    /// Capture live traffic, optionally writing it to a pcap file.
    Capture(CaptureArgs),
}

#[derive(Args, Debug)]
struct AnalyzeArgs {
    /// Capture file to read.
    file: PathBuf,

    /// Write the full report as JSON to this path ("-" for stdout).
    #[arg(long, value_name = "PATH")]
    json: Option<String>,

    /// Rows to show in each table.
    #[arg(long, default_value_t = 20)]
    top: usize,

    /// Stop after this many packets.
    #[arg(long, value_name = "N")]
    limit: Option<u64>,

    /// Print a one-line summary per packet as it is decoded.
    #[arg(long)]
    packets: bool,

    /// Print only the findings section.
    #[arg(long)]
    findings_only: bool,

    #[command(flatten)]
    tuning: TuningArgs,
}

/// Detection thresholds, exposed because the right values depend on the
/// network being looked at.
#[derive(Args, Debug, Clone)]
struct TuningArgs {
    /// Maximum interval jitter for a flow to count as a beacon (0.0-1.0).
    #[arg(long, value_name = "RATIO")]
    beacon_jitter: Option<f64>,

    /// Minimum packets in one direction before beacon scoring runs.
    #[arg(long, value_name = "N")]
    beacon_min_packets: Option<usize>,

    /// Distinct subdomains under one parent before DNS tunnelling is flagged.
    #[arg(long, value_name = "N")]
    dns_subdomains: Option<usize>,

    /// Distinct ports probed on one host before a port scan is flagged.
    #[arg(long, value_name = "N")]
    scan_ports: Option<usize>,
}

impl TuningArgs {
    fn apply(&self, top: usize) -> AnalysisConfig {
        let mut cfg = AnalysisConfig {
            top_n: top,
            ..Default::default()
        };
        if let Some(v) = self.beacon_jitter {
            cfg.beacon_max_jitter = v.clamp(0.0, 1.0);
        }
        if let Some(v) = self.beacon_min_packets {
            cfg.beacon_min_packets = v.max(5);
        }
        if let Some(v) = self.dns_subdomains {
            cfg.dns_subdomain_threshold = v.max(2);
        }
        if let Some(v) = self.scan_ports {
            cfg.scan_port_threshold = v.max(2);
        }
        cfg
    }
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Capture file to serve. Omit when using --iface.
    file: Option<PathBuf>,

    /// Capture live from this interface instead of a file.
    #[arg(long, value_name = "NAME")]
    iface: Option<String>,

    /// BPF filter for live capture, e.g. "tcp port 443".
    #[arg(long, value_name = "EXPR")]
    filter: Option<String>,

    /// Address to bind the dashboard to.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,

    /// Seconds between dashboard snapshots during live capture.
    #[arg(long, default_value_t = 2.0)]
    refresh: f64,

    /// Rows to show in each table.
    #[arg(long, default_value_t = 50)]
    top: usize,

    #[command(flatten)]
    tuning: TuningArgs,
}

#[derive(Args, Debug)]
struct CaptureArgs {
    /// Interface to capture from. Defaults to the system's first usable one.
    #[arg(long, value_name = "NAME")]
    iface: Option<String>,

    /// BPF filter, e.g. "not port 22".
    #[arg(long, value_name = "EXPR")]
    filter: Option<String>,

    /// Stop after this many packets.
    #[arg(long, value_name = "N")]
    count: Option<u64>,

    /// Stop after this many seconds.
    #[arg(long, value_name = "SECS")]
    duration: Option<f64>,

    /// Write captured packets to this pcap file.
    #[arg(long, short = 'w', value_name = "PATH")]
    write: Option<PathBuf>,

    /// Print a line per packet while capturing.
    #[arg(long)]
    packets: bool,

    /// Bytes to capture per packet.
    #[arg(long, default_value_t = 65535)]
    snaplen: i32,

    /// Do not put the interface into promiscuous mode.
    #[arg(long)]
    no_promisc: bool,

    /// Rows to show in the closing report.
    #[arg(long, default_value_t = 20)]
    top: usize,

    #[command(flatten)]
    tuning: TuningArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log.clone().into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let style = render::Style::detect(cli.plain);

    match cli.command {
        Command::Analyze(args) => cmd_analyze(args, &style),
        Command::Serve(args) => cmd_serve(args, &style),
        Command::Devices => cmd_devices(&style),
        Command::Capture(args) => cmd_capture(args, &style),
    }
}

fn cmd_analyze(args: AnalyzeArgs, style: &render::Style) -> Result<()> {
    let config = args.tuning.apply(args.top);
    let stdout = std::io::stdout();

    let (analyzer, stats, description) = if args.packets {
        let mut out = stdout.lock();
        let mut hook = |pkt: &cbna_core::DecodedPacket| {
            // A closed pipe (`| head`) is a normal way to stop; do not panic.
            let _ = writeln!(out, "{}", pkt.summary());
        };
        pipeline::run_file(&args.file, config, args.limit, Some(&mut hook))?
    } else {
        pipeline::run_file(&args.file, config, args.limit, None)?
    };

    for e in &stats.read_errors {
        eprintln!("warning: {e}");
    }
    if analyzer.is_empty() {
        eprintln!(
            "warning: no packets were decoded from {}",
            args.file.display()
        );
    }

    let report = analyzer.report(&description);

    if let Some(target) = &args.json {
        let json = serde_json::to_string_pretty(&report)?;
        if target == "-" {
            // JSON is going to stdout, so the human report would corrupt it.
            println!("{json}");
            return Ok(());
        }
        std::fs::write(target, json).with_context(|| format!("writing JSON report to {target}"))?;
        eprintln!("Report written to {target}");
    }

    let mut out = stdout.lock();
    if args.findings_only {
        for f in &report.findings {
            writeln!(
                out,
                "{} {}",
                style.severity(f.severity, &format!("[{}]", f.severity)),
                f.title
            )?;
            for e in &f.evidence {
                writeln!(out, "    · {e}")?;
            }
        }
        return Ok(());
    }
    render::report(&mut out, &report, style, args.top)?;
    Ok(())
}

fn cmd_serve(args: ServeArgs, _style: &render::Style) -> Result<()> {
    match (&args.file, &args.iface) {
        (Some(_), Some(_)) => bail!("pass either a capture file or --iface, not both"),
        (None, None) => bail!("pass a capture file, or --iface NAME for live capture"),
        (Some(file), None) => serve_file(file.clone(), args),
        (None, Some(_)) => serve_live(args),
    }
}

fn serve_file(file: PathBuf, args: ServeArgs) -> Result<()> {
    let config = args.tuning.apply(args.top);
    let (analyzer, stats, description) = pipeline::run_file(&file, config, None, None)?;
    for e in &stats.read_errors {
        eprintln!("warning: {e}");
    }

    let report = analyzer.report(&description);
    let state = cbna_web::AppState::new(&description, false);
    state.publish(
        report,
        cbna_web::CaptureStatus {
            source: description,
            live: false,
            running: false,
            packets: stats.packets,
            dropped: 0,
            elapsed_secs: analyzer.duration_secs(),
            last_update: cbna_core::Timestamp::new(now_unix(), 0).to_rfc3339(),
        },
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cbna_web::serve(state, args.bind))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// --- live-only commands ---------------------------------------------------

#[cfg(feature = "live")]
fn cmd_devices(style: &render::Style) -> Result<()> {
    livecmd::devices(style)
}

#[cfg(not(feature = "live"))]
fn cmd_devices(_style: &render::Style) -> Result<()> {
    bail!("{}", live_unavailable())
}

#[cfg(feature = "live")]
fn cmd_capture(args: CaptureArgs, style: &render::Style) -> Result<()> {
    livecmd::capture(args, style)
}

#[cfg(not(feature = "live"))]
fn cmd_capture(_args: CaptureArgs, _style: &render::Style) -> Result<()> {
    bail!("{}", live_unavailable())
}

#[cfg(feature = "live")]
fn serve_live(args: ServeArgs) -> Result<()> {
    livecmd::serve_live(args)
}

#[cfg(not(feature = "live"))]
fn serve_live(_args: ServeArgs) -> Result<()> {
    bail!("{}", live_unavailable())
}

#[cfg(not(feature = "live"))]
fn live_unavailable() -> String {
    pipeline::explain(&cbna_capture::CaptureError::LiveUnavailable)
}

/// Used by the live command module; kept here so both builds share it.
#[allow(dead_code)]
fn fresh_analyzer(config: AnalysisConfig) -> Analyzer {
    Analyzer::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_analyze_with_options() {
        let cli = Cli::try_parse_from([
            "cbna",
            "analyze",
            "capture.pcap",
            "--json",
            "out.json",
            "--top",
            "5",
            "--beacon-jitter",
            "0.1",
        ])
        .unwrap();
        match cli.command {
            Command::Analyze(a) => {
                assert_eq!(a.file, PathBuf::from("capture.pcap"));
                assert_eq!(a.json.as_deref(), Some("out.json"));
                assert_eq!(a.top, 5);
                assert_eq!(a.tuning.beacon_jitter, Some(0.1));
            }
            other => panic!("expected analyze, got {other:?}"),
        }
    }

    #[test]
    fn tuning_clamps_out_of_range_values() {
        let t = TuningArgs {
            beacon_jitter: Some(5.0),
            beacon_min_packets: Some(1),
            dns_subdomains: Some(0),
            scan_ports: Some(0),
        };
        let cfg = t.apply(10);
        assert_eq!(cfg.beacon_max_jitter, 1.0);
        assert_eq!(cfg.beacon_min_packets, 5);
        assert_eq!(cfg.dns_subdomain_threshold, 2);
        assert_eq!(cfg.scan_port_threshold, 2);
        assert_eq!(cfg.top_n, 10);
    }

    #[test]
    fn serve_requires_exactly_one_source() {
        let cli = Cli::try_parse_from(["cbna", "serve"]).unwrap();
        let style = render::Style::detect(true);
        match cli.command {
            Command::Serve(a) => {
                let err = cmd_serve(a, &style).unwrap_err();
                assert!(err.to_string().contains("--iface"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn default_bind_is_loopback_only() {
        let cli = Cli::try_parse_from(["cbna", "serve", "x.pcap"]).unwrap();
        match cli.command {
            // Binding to loopback by default matters: the dashboard exposes
            // decoded traffic and should not be reachable off-box by accident.
            Command::Serve(a) => assert!(a.bind.ip().is_loopback()),
            _ => unreachable!(),
        }
    }
}
