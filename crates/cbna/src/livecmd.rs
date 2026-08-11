//! Live-capture commands. Compiled only with `--features live`.

use crate::render::{self, Align, Style, Table};
use crate::{CaptureArgs, ServeArgs};
use anyhow::{Context, Result};
use cbna_capture::live::{list_interfaces, LiveConfig, LiveSource};
use cbna_capture::{PcapWriter, Source};
use cbna_core::analysis::Analyzer;
use cbna_core::packet::decode;
use cbna_core::Timestamp;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn devices(style: &Style) -> Result<()> {
    let interfaces = list_interfaces().context("listing capture interfaces")?;
    if interfaces.is_empty() {
        println!("No capture interfaces are visible to this process.");
        println!("On Windows, Npcap must be installed and the shell run as Administrator.");
        return Ok(());
    }

    let mut t = Table::new(
        &["NAME", "DESCRIPTION", "ADDRESSES", "FLAGS"],
        &[Align::Left, Align::Left, Align::Left, Align::Left],
    );
    for i in &interfaces {
        let mut flags = Vec::new();
        if i.is_up {
            flags.push("up");
        }
        if i.is_loopback {
            flags.push("loopback");
        }
        t.row(vec![
            i.name.clone(),
            i.description.clone().unwrap_or_default(),
            i.addresses.join(", "),
            flags.join(","),
        ]);
    }
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", style.bold("Capture interfaces"))?;
    t.write(&mut out, style, "  ")?;
    Ok(())
}

/// Ctrl-C handling shared by the capture commands: the first press asks the
/// loop to stop so the report still gets printed.
fn install_stop_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let handler = flag.clone();
    // A failure here is not fatal; the user can still stop with a second
    // Ctrl-C, which the OS handles.
    let _ = ctrlc_hook(move || handler.store(true, Ordering::Release));
    flag
}

/// Minimal Ctrl-C hook built on tokio's signal support, so no extra dependency
/// is needed just to catch one signal.
fn ctrlc_hook(mut on_signal: impl FnMut() + Send + 'static) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    std::thread::spawn(move || {
        runtime.block_on(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                on_signal();
            }
        });
    });
    Ok(())
}

pub fn capture(args: CaptureArgs, style: &Style) -> Result<()> {
    let config = LiveConfig {
        interface: args.iface.clone().unwrap_or_default(),
        promiscuous: !args.no_promisc,
        snaplen: args.snaplen,
        filter: args.filter.clone(),
        ..Default::default()
    };

    let mut source = LiveSource::open(&config).context("opening the capture interface")?;
    let link_type = source.link_type();
    let description = source.description();
    eprintln!("Capturing on {description}. Press Ctrl-C to stop.");
    if let Some(f) = &args.filter {
        eprintln!("Filter: {f}");
    }

    let mut writer = match &args.write {
        Some(path) => Some(
            PcapWriter::create(path, link_type)
                .with_context(|| format!("creating {}", path.display()))?,
        ),
        None => None,
    };

    let stop = install_stop_flag();
    let mut analyzer = Analyzer::new(args.tuning.apply(args.top));
    let started = Instant::now();
    let mut count = 0u64;
    let mut stdout = std::io::stdout().lock();

    while !stop.load(Ordering::Acquire) {
        if args.count.is_some_and(|n| count >= n) {
            break;
        }
        if args
            .duration
            .is_some_and(|d| started.elapsed().as_secs_f64() >= d)
        {
            break;
        }

        let Some(next) = source.next_packet() else {
            break;
        };
        let raw = match next {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("capture error: {}", render_error(&e));
                break;
            }
        };

        if let Some(w) = writer.as_mut() {
            w.write(&raw)?;
        }
        let pkt = decode(raw.meta, &raw.data, link_type);
        if args.packets {
            let _ = writeln!(stdout, "{}", pkt.summary());
        }
        analyzer.observe(&pkt);
        count += 1;
    }

    let dropped = source.dropped();
    eprintln!();
    eprintln!(
        "Captured {count} packet(s) in {:.1}s{}",
        started.elapsed().as_secs_f64(),
        if dropped > 0 {
            format!(", {dropped} dropped by the capture engine")
        } else {
            String::new()
        }
    );
    if let Some(w) = writer.as_mut() {
        w.flush()?;
        if let Some(path) = &args.write {
            eprintln!(
                "Wrote {} packet(s) to {}",
                w.packets_written(),
                path.display()
            );
        }
    }

    if count > 0 {
        render::report(&mut stdout, &analyzer.report(&description), style, args.top)?;
    }
    Ok(())
}

pub fn serve_live(args: ServeArgs) -> Result<()> {
    let iface = args.iface.clone().unwrap_or_default();
    let config = LiveConfig {
        interface: iface,
        filter: args.filter.clone(),
        ..Default::default()
    };

    let mut source = LiveSource::open(&config).context("opening the capture interface")?;
    let link_type = source.link_type();
    let description = source.description();
    let state = cbna_web::AppState::new(&description, true);
    let analysis_config = args.tuning.apply(args.top);
    let refresh = Duration::from_secs_f64(args.refresh.clamp(0.25, 60.0));

    let mut writer = match &args.write {
        Some(path) => {
            let w = PcapWriter::create(path, link_type)
                .with_context(|| format!("creating {}", path.display()))?;
            eprintln!("Writing packets to {}", path.display());
            Some(w)
        }
        None => None,
    };
    let write_path = args.write.clone();

    // The capture loop runs on its own thread and hands finished snapshots to
    // the server, so a slow HTTP client can never stall packet processing.
    let capture_state = state.clone();
    let worker = std::thread::spawn(move || {
        let mut analyzer = Analyzer::new(analysis_config);
        let started = Instant::now();
        let mut last_publish = Instant::now() - refresh;
        let mut packets = 0u64;

        while !capture_state.shutdown_requested() {
            match source.next_packet() {
                Some(Ok(raw)) => {
                    if let Some(w) = writer.as_mut() {
                        // A capture file that silently stops part-way is worse
                        // than one that never existed, so stop on write failure
                        // rather than carrying on with a truncated artefact.
                        if let Err(e) = w.write(&raw) {
                            tracing::error!("writing to the capture file failed: {e}");
                            break;
                        }
                    }
                    let pkt = decode(raw.meta, &raw.data, link_type);
                    analyzer.observe(&pkt);
                    packets += 1;
                }
                Some(Err(e)) => {
                    tracing::error!("live capture error: {e}");
                    break;
                }
                None => break,
            }

            if last_publish.elapsed() >= refresh {
                last_publish = Instant::now();
                // Flush on the same tick as the snapshot: a dashboard session
                // is usually ended by killing the process, and an unflushed
                // buffer would lose the last packets.
                if let Some(w) = writer.as_mut() {
                    let _ = w.flush();
                }
                publish(&capture_state, &analyzer, &description, packets, started, {
                    source.dropped()
                });
            }
        }

        if let Some(w) = writer.as_mut() {
            let _ = w.flush();
            eprintln!(
                "Wrote {} packet(s) to {}",
                w.packets_written(),
                write_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
        publish(
            &capture_state,
            &analyzer,
            &description,
            packets,
            started,
            source.dropped(),
        );
        capture_state.mark_finished();
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(cbna_web::serve(state.clone(), args.bind));

    state.request_shutdown();
    let _ = worker.join();
    result
}

fn publish(
    state: &cbna_web::SharedState,
    analyzer: &Analyzer,
    description: &str,
    packets: u64,
    started: Instant,
    dropped: u64,
) {
    let report = analyzer.report(description);
    state.publish(
        report,
        cbna_web::CaptureStatus {
            source: description.to_string(),
            live: true,
            running: true,
            packets,
            dropped,
            elapsed_secs: started.elapsed().as_secs_f64(),
            last_update: Timestamp::new(crate::now_unix(), 0).to_rfc3339(),
        },
    );
}

fn render_error(e: &cbna_capture::CaptureError) -> String {
    crate::pipeline::explain(e)
}
