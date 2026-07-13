//! HTTP API server for the analyzer.
//!
//! Serves RESTful endpoints for the TUI dashboard and other consumers.
//! Supports Unix socket and TCP listen modes (Docker daemon style).

use crate::AppState;
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    routing::{delete, get, post},
    Json, Router,
};
use flow_common::types::DpiFingerprint;
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::StreamExt;
use uuid::Uuid;

/// Status response.
#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_secs: u64,
    sampler_connected: bool,
}

/// Stats response.
#[derive(Serialize)]
struct StatsResponse {
    total_packets: u64,
    total_bytes: u64,
    packets_per_second: f64,
    bytes_per_second: f64,
    active_flows: usize,
    top_flows: Vec<FlowInfo>,
}

#[derive(Serialize)]
struct FlowInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    packets: u64,
    bytes: u64,
}

/// Serve the HTTP API on the given listen address.
///
/// Format: `unix:///path/to/socket` or `tcp://host:port`
pub async fn serve(listen: &str, app_state: Arc<AppState>) -> Result<()> {
    let app = Router::new()
        .route("/api/status", get(status_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/fingerprints", get(list_fingerprints).post(create_fingerprint))
        .route("/api/fingerprints/{id}", delete(delete_fingerprint))
        .route("/api/events", get(events_handler))
        .with_state(app_state);

    if let Some(socket_path) = listen.strip_prefix("unix://") {
        let _ = std::fs::remove_file(socket_path);
        let listener = tokio::net::UnixListener::bind(socket_path)
            .context(format!("failed to bind Unix socket: {}", socket_path))?;
        log::info!("HTTP API listening on Unix socket: {}", socket_path);
        axum::serve(listener, app).await?;
    } else if let Some(addr) = listen.strip_prefix("tcp://") {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context(format!("failed to bind TCP: {}", addr))?;
        log::info!("HTTP API listening on TCP: {}", addr);
        axum::serve(listener, app).await?;
    } else {
        anyhow::bail!("invalid listen address: {} (expected unix:// or tcp://)", listen);
    }

    Ok(())
}

async fn status_handler(State(_state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: 0,
        sampler_connected: true,
    })
}

async fn stats_handler(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let stats = state.stats.read().await;
    let top = stats.top_flows(10);

    Json(StatsResponse {
        total_packets: stats.total_packets,
        total_bytes: stats.total_bytes,
        packets_per_second: stats.packets_per_second(),
        bytes_per_second: stats.bytes_per_second(),
        active_flows: stats.active_flows,
        top_flows: top
            .iter()
            .map(|(k, f)| FlowInfo {
                src_ip: k.src_ip.to_string(),
                dst_ip: k.dst_ip.to_string(),
                src_port: k.src_port,
                dst_port: k.dst_port,
                protocol: k.protocol,
                packets: f.packets,
                bytes: f.bytes,
            })
            .collect(),
    })
}

async fn list_fingerprints(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<DpiFingerprint>> {
    let fps = state.fingerprints.read().await;
    Json(fps.clone())
}

async fn create_fingerprint(
    State(state): State<Arc<AppState>>,
    Json(fp): Json<DpiFingerprint>,
) -> Result<Json<DpiFingerprint>, StatusCode> {
    let mut fps = state.fingerprints.write().await;
    fps.push(fp.clone());
    // Write to rules shared memory for the processor
    let _ = state.rules_shm.try_push(&fp);
    Ok(Json(fp))
}

async fn delete_fingerprint(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> StatusCode {
    let mut fps = state.fingerprints.write().await;
    let before = fps.len();
    fps.retain(|f| f.id != id);
    if fps.len() < before {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn events_handler(
    State(_state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(
        std::time::Duration::from_secs(30),
    ))
    .map(|_| Ok(Event::default().data("heartbeat")));

    Sse::new(stream).keep_alive(KeepAlive::default())
}