//! `cbna` — Custom Built Network Analyzer.
//!
//! Offline analysis works in every build. Live capture (`devices`, `capture`,
//! `serve --iface`) needs the `live` feature and a platform capture library.

mod pipeline;
mod render;

#[cfg(feature = "live")]
mod livecmd;

use anyhow::{bail, Context, Result};
use cbna_core::analysis::{AnalysisConfig, Analyzer, Severity};
use clap::{Args, Parser, Subcommand, ValueEnum};
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

    /// Manage the cache of open-source threat-intel feeds.
    Intel(IntelArgs),
}

#[derive(Args, Debug)]
struct IntelArgs {
    #[command(subcommand)]
    cmd: IntelCmd,
}

#[derive(Subcommand, Debug)]
enum IntelCmd {
    /// Fetch the feeds into the local cache. Failed feeds keep their last good
    /// copy; the rest still update.
    Update(IntelActionArgs),

    /// Show the available feeds and what is currently cached.
    List(IntelActionArgs),
}

#[derive(Args, Debug)]
struct IntelActionArgs {
    #[command(flatten)]
    opts: IntelOpts,
}

#[derive(Args, Debug)]
struct AnalyzeArgs {
    /// Capture file to read.
    file: PathBuf,

    /// Write the full report as JSON to this path ("-" for stdout).
    #[arg(long, value_name = "PATH")]
    json: Option<String>,

    /// Write a self-contained, offline HTML dashboard for this capture. The
    /// page needs no server and makes no network requests — share it as-is.
    #[arg(long, value_name = "PATH")]
    html: Option<String>,

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

    /// Exit non-zero (code 2) if any finding at or above this severity fired.
    /// Lets the run gate a CI or SOAR pipeline. Operational errors stay code 1.
    #[arg(long, value_name = "LEVEL")]
    fail_on: Option<FailOn>,

    /// Match observed traffic against a threat-intel indicator list: one IP,
    /// CIDR, domain or JA3 hash per line, "#" for comments. Hits surface as
    /// ioc-* findings and in the JSON report's "ioc" section.
    #[arg(long, value_name = "PATH")]
    ioc: Option<PathBuf>,

    /// Match against cached open-source threat-intel feeds. Refresh the cache
    /// first with `cbna intel update`. Combines with --ioc. Needs the `intel`
    /// build feature.
    #[arg(long)]
    intel: bool,

    /// Like --intel, but fetch the feeds fresh right now instead of reading the
    /// cache. Requires network access.
    #[arg(long)]
    intel_live: bool,

    #[command(flatten)]
    intel_opts: IntelOpts,

    #[command(flatten)]
    tuning: TuningArgs,
}

/// Shared threat-intel feed options, flattened into the commands that fetch or
/// read feeds so the auth key and cache location are specified the same way
/// everywhere.
#[derive(Args, Debug, Clone)]
struct IntelOpts {
    /// abuse.ch Auth-Key for feeds that require one. Falls back to the
    /// CBNA_ABUSECH_AUTHKEY environment variable.
    #[arg(long, value_name = "KEY")]
    intel_auth_key: Option<String>,

    /// Feed cache directory. Defaults to the per-user platform cache directory.
    #[arg(long, value_name = "DIR")]
    intel_cache_dir: Option<PathBuf>,

    /// Restrict to these feed ids (repeatable). Default: all built-in feeds.
    #[arg(long = "intel-feed", value_name = "ID")]
    intel_feeds: Vec<String>,
}

/// Severity floor for `--fail-on`. Kept separate from the core `Severity` so the
/// CLI owns its own value-parsing surface.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum FailOn {
    Info,
    Low,
    Medium,
    High,
}

impl FailOn {
    fn threshold(self) -> Severity {
        match self {
            FailOn::Info => Severity::Info,
            FailOn::Low => Severity::Low,
            FailOn::Medium => Severity::Medium,
            FailOn::High => Severity::High,
        }
    }
}

/// Exit code emitted when `--fail-on` is armed and a finding meets the floor.
/// Distinct from 1 (an operational error via `anyhow`) so automation can tell a
/// clean-but-flagged run apart from a broken one.
const EXIT_FINDINGS_GATE: i32 = 2;

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

    /// Also write captured packets to this pcap file. Live capture only.
    #[arg(long, short = 'w', value_name = "PATH")]
    write: Option<PathBuf>,

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
        Command::Intel(args) => cmd_intel(args),
    }
}

fn cmd_analyze(args: AnalyzeArgs, style: &render::Style) -> Result<()> {
    let config = args.tuning.apply(args.top);
    let stdout = std::io::stdout();

    let (mut analyzer, stats, description) = if args.packets {
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

    if args.ioc.is_some() || args.intel || args.intel_live {
        let set = build_ioc_set(&args)?;
        analyzer.set_iocs(set);
    }

    let report = analyzer.report(&description);

    // Evaluated up front so every output path exits with the same gate code.
    let gate = args
        .fail_on
        .map(|f| findings_gate(&report, f.threshold()))
        .unwrap_or(0);

    if let Some(target) = &args.html {
        let page = cbna_web::render_static(&report);
        std::fs::write(target, page)
            .with_context(|| format!("writing HTML dashboard to {target}"))?;
        eprintln!("Dashboard written to {target}");
    }

    if let Some(target) = &args.json {
        let json = serde_json::to_string_pretty(&report)?;
        if target == "-" {
            // JSON is going to stdout, so the human report would corrupt it.
            println!("{json}");
            gated_exit(gate);
            return Ok(());
        }
        std::fs::write(target, json).with_context(|| format!("writing JSON report to {target}"))?;
        eprintln!("Report written to {target}");
    }

    let mut out = stdout.lock();
    if args.findings_only {
        for f in &report.findings {
            let attack = if f.technique.is_empty() {
                String::new()
            } else {
                format!("  (ATT&CK {})", f.technique.join(", "))
            };
            writeln!(
                out,
                "{} {}{attack}",
                style.severity(f.severity, &format!("[{}]", f.severity)),
                f.title
            )?;
            for e in &f.evidence {
                writeln!(out, "    · {e}")?;
            }
        }
        gated_exit(gate);
        return Ok(());
    }
    render::report(&mut out, &report, style, args.top)?;
    gated_exit(gate);
    Ok(())
}

/// Build the combined indicator set for an analyze run from whichever sources
/// were requested: a local `--ioc` list, cached feeds (`--intel`), and/or a live
/// feed fetch (`--intel-live`). They merge, so a run can match a bespoke list
/// alongside open-source feeds. Malformed indicators are reported but never fail
/// the run.
fn build_ioc_set(args: &AnalyzeArgs) -> Result<cbna_core::ioc::IocSet> {
    use cbna_core::ioc::IocSet;
    let mut set = IocSet::default();

    if let Some(path) = &args.ioc {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading indicator list {}", path.display()))?;
        let (list, warnings) = cbna_capture::ioc::parse_iocs(&bytes);
        for w in &warnings {
            eprintln!(
                "warning: indicator list line {}: skipped {:?} ({})",
                w.line, w.text, w.reason
            );
        }
        eprintln!("Loaded {} indicator(s) from {}", list.len(), path.display());
        set.extend(list);
    }

    if args.intel || args.intel_live {
        let feeds = load_feeds(args.intel_live, &args.intel_opts)?;
        set.extend(feeds);
    }

    Ok(set)
}

/// Load feeds from the cache, or fetch them live, per `--intel` / `--intel-live`.
/// Gated on the `intel` build feature; without it, requesting feeds is an error
/// pointing at the rebuild.
#[cfg(feature = "intel")]
fn load_feeds(live: bool, opts: &IntelOpts) -> Result<cbna_core::ioc::IocSet> {
    let only = feed_filter(&opts.intel_feeds);
    if live {
        let auth = resolve_auth_key(opts);
        let (set, results) = cbna_intel::fetch_live(auth.as_deref(), only.as_deref())
            .context("fetching threat-intel feeds")?;
        report_feed_results(&results);
        eprintln!("Loaded {} indicator(s) from live feeds", set.len());
        Ok(set)
    } else {
        let dir = opts
            .intel_cache_dir
            .clone()
            .unwrap_or_else(cbna_intel::default_cache_dir);
        let set = cbna_intel::load(&dir).context("reading the threat-intel cache")?;
        if set.is_empty() {
            eprintln!(
                "warning: no cached threat-intel indicators in {} — run `cbna intel update` first",
                dir.display()
            );
        } else {
            eprintln!(
                "Loaded {} indicator(s) from the feed cache ({})",
                set.len(),
                dir.display()
            );
        }
        Ok(set)
    }
}

#[cfg(not(feature = "intel"))]
fn load_feeds(_live: bool, _opts: &IntelOpts) -> Result<cbna_core::ioc::IocSet> {
    bail!(
        "this build has no threat-intel support. Rebuild with \
         `cargo build --release --features intel`."
    )
}

/// The Auth-Key from `--intel-auth-key`, or the `CBNA_ABUSECH_AUTHKEY`
/// environment variable when the flag was not given.
#[cfg(feature = "intel")]
fn resolve_auth_key(opts: &IntelOpts) -> Option<String> {
    opts.intel_auth_key
        .clone()
        .or_else(|| std::env::var("CBNA_ABUSECH_AUTHKEY").ok())
        .filter(|k| !k.is_empty())
}

/// `None` for "all feeds", `Some(ids)` when the user named a subset.
#[cfg(feature = "intel")]
fn feed_filter(feeds: &[String]) -> Option<Vec<String>> {
    if feeds.is_empty() {
        None
    } else {
        Some(feeds.to_vec())
    }
}

/// Print the outcome of each feed in an update or live fetch.
#[cfg(feature = "intel")]
fn report_feed_results(results: &[cbna_intel::FeedResult]) {
    for r in results {
        match &r.result {
            Ok(n) => eprintln!("  {:<9} ok — {n} indicator(s)", r.id),
            Err(e) => eprintln!("  {:<9} FAILED — {e} (kept last good cache)", r.id),
        }
    }
}

// --- intel subcommand -----------------------------------------------------

#[cfg(feature = "intel")]
fn cmd_intel(args: IntelArgs) -> Result<()> {
    match args.cmd {
        IntelCmd::Update(a) => intel_update(a.opts),
        IntelCmd::List(a) => intel_list(a.opts),
    }
}

#[cfg(feature = "intel")]
fn intel_update(opts: IntelOpts) -> Result<()> {
    let dir = opts
        .intel_cache_dir
        .clone()
        .unwrap_or_else(cbna_intel::default_cache_dir);
    let only = feed_filter(&opts.intel_feeds);
    let auth = resolve_auth_key(&opts);
    eprintln!("Updating feed cache in {}", dir.display());
    let results = cbna_intel::update(&cbna_intel::UpdateOptions {
        cache_dir: &dir,
        auth_key: auth.as_deref(),
        only: only.as_deref(),
    })
    .context("updating the threat-intel cache")?;
    report_feed_results(&results);
    // A run where every requested feed failed is worth a non-zero exit so a
    // scheduled refresh surfaces the problem.
    if !results.is_empty() && results.iter().all(|r| r.result.is_err()) {
        bail!("all requested feeds failed to update");
    }
    Ok(())
}

#[cfg(feature = "intel")]
fn intel_list(opts: IntelOpts) -> Result<()> {
    let dir = opts
        .intel_cache_dir
        .clone()
        .unwrap_or_else(cbna_intel::default_cache_dir);
    let manifest = cbna_intel::cache::read_manifest(&dir).unwrap_or_default();

    println!("Feed cache: {}", dir.display());
    for feed in cbna_intel::BUILTIN {
        let cached = manifest.feeds.iter().find(|c| c.id == feed.id);
        let status = match cached {
            Some(c) => format!("{} indicators, fetched {}", c.indicators, c.fetched_at),
            None => "not cached".to_string(),
        };
        let auth = if feed.needs_auth {
            " [needs Auth-Key]"
        } else {
            ""
        };
        println!("  {:<9} {}{auth}\n            {status}", feed.id, feed.name);
    }
    Ok(())
}

#[cfg(not(feature = "intel"))]
fn cmd_intel(_args: IntelArgs) -> Result<()> {
    bail!(
        "this build has no threat-intel support. Rebuild with \
         `cargo build --release --features intel`."
    )
}

/// Highest-severity gate: `EXIT_FINDINGS_GATE` if any finding meets `threshold`,
/// else `0`.
fn findings_gate(report: &cbna_core::analysis::Report, threshold: Severity) -> i32 {
    if report.findings.iter().any(|f| f.severity >= threshold) {
        EXIT_FINDINGS_GATE
    } else {
        0
    }
}

/// Exit the process when the gate is armed; a no-op (returns) when it is `0`, so
/// callers fall through to their normal `Ok(())`.
fn gated_exit(code: i32) {
    if code != 0 {
        std::process::exit(code);
    }
}

fn cmd_serve(args: ServeArgs, _style: &render::Style) -> Result<()> {
    match (&args.file, &args.iface) {
        (Some(_), Some(_)) => bail!("pass either a capture file or --iface, not both"),
        (None, None) => bail!("pass a capture file, or --iface NAME for live capture"),
        (Some(_), None) if args.write.is_some() => {
            bail!("--write only applies to live capture; the source is already a file")
        }
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
    fn parses_analyze_with_an_ioc_list() {
        let cli =
            Cli::try_parse_from(["cbna", "analyze", "capture.pcap", "--ioc", "feed.txt"]).unwrap();
        match cli.command {
            Command::Analyze(a) => {
                assert_eq!(a.ioc.as_deref(), Some(std::path::Path::new("feed.txt")));
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
    fn serve_rejects_write_without_a_live_source() {
        let cli = Cli::try_parse_from(["cbna", "serve", "x.pcap", "-w", "out.pcap"]).unwrap();
        let style = render::Style::detect(true);
        match cli.command {
            Command::Serve(a) => {
                assert_eq!(a.write.as_deref(), Some(std::path::Path::new("out.pcap")));
                let err = cmd_serve(a, &style).unwrap_err();
                assert!(err.to_string().contains("only applies to live capture"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn serve_accepts_write_with_an_interface() {
        let cli = Cli::try_parse_from(["cbna", "serve", "--iface", "eth0", "-w", "session.pcap"])
            .unwrap();
        match cli.command {
            Command::Serve(a) => {
                assert_eq!(a.iface.as_deref(), Some("eth0"));
                assert_eq!(
                    a.write.as_deref(),
                    Some(std::path::Path::new("session.pcap"))
                );
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
