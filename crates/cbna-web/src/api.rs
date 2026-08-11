//! Request handlers. Each serves the current snapshot, or 503 before the first
//! one exists so a client polling at startup gets an honest answer.

use crate::SharedState;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

const INDEX_HTML: &str = include_str!("../assets/index.html");

pub async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

pub async fn health(State(state): State<SharedState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "generation": state.generation(),
        "has_report": state.report().is_some(),
    }))
}

pub async fn status(State(state): State<SharedState>) -> impl IntoResponse {
    Json(state.status())
}

pub async fn report(State(state): State<SharedState>) -> Response {
    match state.report() {
        Some(r) => Json(json!({
            "generation": state.generation(),
            "status": state.status(),
            "report": r,
        }))
        .into_response(),
        None => not_ready(),
    }
}

pub async fn findings(State(state): State<SharedState>) -> Response {
    match state.report() {
        Some(r) => Json(r.findings).into_response(),
        None => not_ready(),
    }
}

#[derive(Debug, Deserialize)]
pub struct FlowQuery {
    /// Substring match against the flow's rendered key, SNI and protocols.
    pub q: Option<String>,
    pub limit: Option<usize>,
}

pub async fn flows(State(state): State<SharedState>, Query(query): Query<FlowQuery>) -> Response {
    let Some(report) = state.report() else {
        return not_ready();
    };
    let needle = query.q.map(|s| s.to_ascii_lowercase());
    let limit = query.limit.unwrap_or(200).min(2000);

    let flows: Vec<_> = report
        .top_flows
        .into_iter()
        .filter(|f| match &needle {
            None => true,
            Some(n) => {
                f.flow.to_ascii_lowercase().contains(n)
                    || f.sni
                        .as_deref()
                        .is_some_and(|s| s.to_ascii_lowercase().contains(n))
                    || f.protocols.iter().any(|p| p.contains(n))
                    || f.service.as_deref().is_some_and(|s| s.contains(n))
            }
        })
        .take(limit)
        .collect();

    Json(flows).into_response()
}

fn not_ready() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "no analysis snapshot yet" })),
    )
        .into_response()
}
