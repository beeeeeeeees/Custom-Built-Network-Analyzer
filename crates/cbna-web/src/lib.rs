//! HTTP dashboard.
//!
//! The server owns nothing but a snapshot: the capture side pushes a fresh
//! [`Report`] whenever it has one, and every request serves the latest. That
//! keeps the analysis loop free of request-handling latency and means a live
//! capture and a static file are served by exactly the same code.

mod api;

use axum::routing::get;
use axum::Router;
use cbna_core::analysis::Report;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;

/// Live counters the dashboard shows above the report itself.
#[derive(Debug, Default, Serialize, Clone)]
pub struct CaptureStatus {
    pub source: String,
    pub live: bool,
    pub running: bool,
    pub packets: u64,
    pub dropped: u64,
    pub elapsed_secs: f64,
    pub last_update: String,
}

pub struct AppState {
    report: RwLock<Option<Report>>,
    status: RwLock<CaptureStatus>,
    /// Bumped on every snapshot so the client can skip redundant redraws.
    generation: AtomicU64,
    shutdown: AtomicBool,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(source: impl Into<String>, live: bool) -> SharedState {
        Arc::new(AppState {
            report: RwLock::new(None),
            status: RwLock::new(CaptureStatus {
                source: source.into(),
                live,
                running: true,
                ..Default::default()
            }),
            generation: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Replace the served snapshot.
    pub fn publish(&self, report: Report, status: CaptureStatus) {
        // A poisoned lock here means a previous holder panicked mid-update;
        // the snapshot is replaced wholesale, so recovering is safe.
        match self.report.write() {
            Ok(mut guard) => *guard = Some(report),
            Err(poisoned) => *poisoned.into_inner() = Some(report),
        }
        match self.status.write() {
            Ok(mut guard) => *guard = status,
            Err(poisoned) => *poisoned.into_inner() = status,
        }
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn report(&self) -> Option<Report> {
        self.report
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }

    pub fn status(&self) -> CaptureStatus {
        self.status
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Signal the capture loop to stop; set when the server shuts down.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub fn mark_finished(&self) {
        if let Ok(mut s) = self.status.write() {
            s.running = false;
        }
    }
}

/// Render a fully self-contained dashboard page with one report baked in, for
/// offline sharing. The page reads the embedded snapshot instead of polling, so
/// it needs no server and makes no network requests.
pub fn render_static(report: &Report) -> String {
    let status = serde_json::json!({
        "source": report.source,
        "live": false,
        "running": false,
        "packets": report.summary.packets,
        "dropped": 0,
        "elapsed_secs": report.summary.duration_secs,
        "last_update": report.generated_at,
    });
    let payload = serde_json::json!({
        "generation": 1,
        "status": status,
        "report": report,
    });
    // Escape `<` so the serialized report can never terminate the <script>
    // block early; `<` is valid JSON and JSON.parse restores it.
    let json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "null".to_string())
        .replace('<', "\\u003c");
    let snippet =
        format!("<script type=\"application/json\" id=\"cbna-snapshot\">{json}</script>\n</body>");
    api::INDEX_HTML.replacen("</body>", &snippet, 1)
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(api::index))
        .route("/api/report", get(api::report))
        .route("/api/status", get(api::status))
        .route("/api/findings", get(api::findings))
        .route("/api/flows", get(api::flows))
        .route("/api/health", get(api::health))
        // The dashboard is same-origin, but permissive CORS lets an analyst
        // pull the JSON from a notebook or another tool on the box.
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Bind and serve until ctrl-c.
pub async fn serve(state: SharedState, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tracing::info!("dashboard listening on http://{bound}");
    println!("Dashboard: http://{bound}");

    let shutdown_state = state.clone();
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown requested");
            shutdown_state.request_shutdown();
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbna_core::analysis::Analyzer;

    #[test]
    fn state_starts_empty_and_accepts_a_snapshot() {
        let state = AppState::new("test.pcap", false);
        assert!(state.report().is_none());
        assert_eq!(state.generation(), 0);
        assert!(!state.shutdown_requested());

        let report = Analyzer::default().report("test.pcap");
        state.publish(report, CaptureStatus::default());

        assert!(state.report().is_some());
        assert_eq!(state.generation(), 1);
    }

    #[test]
    fn shutdown_flag_round_trips() {
        let state = AppState::new("live", true);
        assert!(state.status().live);
        state.request_shutdown();
        assert!(state.shutdown_requested());
        state.mark_finished();
        assert!(!state.status().running);
    }

    #[test]
    fn static_export_embeds_snapshot_without_script_breakout() {
        // A hostile source string containing </script> must not close the
        // embedded block early — every `<` is escaped in the JSON.
        let report = Analyzer::default().report("<script>x</script>.pcap");
        let page = render_static(&report);

        assert!(page.contains("id=\"cbna-snapshot\""));

        let idx = page.find("id=\"cbna-snapshot\"").unwrap();
        let after = &page[idx..];
        let close = after.find("</script>").unwrap();
        let block = &after[..close];
        assert!(
            !block.contains("</script>"),
            "source string broke out of the snapshot block"
        );
        // Escaping `<` alone defeats the breakout: `</script>` can never form
        // without a literal `<`. The closing tag in the source is now inert.
        assert!(
            block.contains("\\u003c/script>"),
            "`<` was not escaped inside the embedded JSON; block head: {:?}",
            &block[..block.len().min(200)]
        );
    }
}
