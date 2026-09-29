use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::time;

use crate::history::MinuteHistory;
use crate::logs::{LogEntry, LogHub};
use crate::{DashboardSnapshot, GroupPage, ProfileSummary};

const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_WEBSOCKET_CLIENTS: usize = 32;
const MAX_LOG_CLIENTS: usize = 8;
const LOG_DROPPED_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const LOG_REPLAY_BATCH_SIZE: usize = 256;
const MAX_GROUP_QUERIES: usize = 4;
const MAX_CLIENT_MESSAGE_BYTES: usize = 1024;
const GROUP_PAGE_SIZE: usize = 100;
const UI_HTML: &str = include_str!("../assets/index.html");
const UI_CSS: &str = include_str!("../assets/style.css");
const UI_JS: &str = include_str!("../assets/app.js");
const UI_FAVICON: &str = include_str!("../assets/favicon.svg");

/// A source of read-only dashboard data. Implementations must omit credentials.
pub trait SnapshotSource: Send + Sync + 'static {
    fn snapshot(&self) -> DashboardSnapshot;
    fn group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Option<GroupPage>, GroupError>;
    fn profile(&self) -> ProfileSummary;
}

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("VPN assignment data unavailable")]
    Unavailable,
}

/// Errors while serving the dashboard.
#[derive(Debug, Error)]
pub enum UiError {
    #[error("cannot serialize dashboard snapshot: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("dashboard HTTP server failed: {0}")]
    Serve(#[from] std::io::Error),
}

#[derive(Clone)]
struct UiState {
    source: Arc<dyn SnapshotSource>,
    updates: watch::Sender<String>,
    connections: Arc<Semaphore>,
    log_connections: Arc<Semaphore>,
    logs: LogHub,
    group_queries: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
}

#[derive(Deserialize)]
struct GroupQuery {
    offset: Option<usize>,
}

/// Serve the embedded dashboard and its live WebSocket feed.
pub async fn serve<S: SnapshotSource>(
    listener: TcpListener,
    source: S,
    shutdown: watch::Receiver<bool>,
    logs: LogHub,
) -> Result<(), UiError> {
    let source: Arc<dyn SnapshotSource> = Arc::new(source);
    let mut history = MinuteHistory::new();
    let initial = serde_json::to_string(&history.observe(source.snapshot()))?;
    let (updates, _) = watch::channel(initial);
    let state = UiState {
        source: Arc::clone(&source),
        updates: updates.clone(),
        connections: Arc::new(Semaphore::new(MAX_WEBSOCKET_CLIENTS)),
        log_connections: Arc::new(Semaphore::new(MAX_LOG_CLIENTS)),
        logs,
        group_queries: Arc::new(Semaphore::new(MAX_GROUP_QUERIES)),
        shutdown: shutdown.clone(),
    };
    let router = Router::new()
        .route("/", get(index))
        .route("/style.css", get(style))
        .route("/app.js", get(script))
        .route("/favicon.svg", get(favicon))
        .route("/api/hosts/{host_id}/groups", get(groups))
        .route("/api/profile", get(profile))
        .route("/ws", any(websocket))
        .route("/ws/logs", any(log_websocket))
        .with_state(state);
    tracing::info!(address = %listener.local_addr()?, "dashboard listening");

    let sampler = tokio::spawn(sample(source, updates, shutdown.clone(), history));
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await;
    sampler.abort();
    let _ = sampler.await;
    result.map_err(UiError::from)
}

async fn sample(
    source: Arc<dyn SnapshotSource>,
    updates: watch::Sender<String>,
    mut shutdown: watch::Receiver<bool>,
    mut history: MinuteHistory,
) {
    let mut interval =
        time::interval_at(time::Instant::now() + SNAPSHOT_INTERVAL, SNAPSHOT_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => match serde_json::to_string(&history.observe(source.snapshot())) {
                Ok(snapshot) => { updates.send_replace(snapshot); }
                Err(error) => tracing::error!(%error, "dashboard snapshot serialization failed"),
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn index() -> impl IntoResponse {
    ([(CACHE_CONTROL, "no-store")], Html(UI_HTML))
}

async fn style() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, "no-store"),
        ],
        UI_CSS,
    )
}

async fn script() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, "no-store"),
        ],
        UI_JS,
    )
}

async fn favicon() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "image/svg+xml"),
            (CACHE_CONTROL, "public, max-age=86400"),
        ],
        UI_FAVICON,
    )
}

async fn groups(
    Path(host_id): Path<usize>,
    Query(query): Query<GroupQuery>,
    State(state): State<UiState>,
) -> Response {
    let Ok(permit) = Arc::clone(&state.group_queries).try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let source = Arc::clone(&state.source);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        source.group_page(host_id, query.offset.unwrap_or(0), GROUP_PAGE_SIZE)
    })
    .await;
    match result {
        Ok(Ok(Some(page))) => ([(CACHE_CONTROL, "no-store")], Json(page)).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => {
            tracing::error!(host_id, %error, "dashboard assignment lookup failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(error) => {
            tracing::error!(host_id, %error, "dashboard assignment task failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn profile(State(state): State<UiState>) -> impl IntoResponse {
    ([(CACHE_CONTROL, "no-store")], Json(state.source.profile()))
}

async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<UiState>,
    headers: HeaderMap,
) -> Response {
    let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let allowed_origin = format!("http://{host}");
    if headers.get(ORIGIN).and_then(|value| value.to_str().ok()) != Some(allowed_origin.as_str()) {
        tracing::warn!("rejected dashboard WebSocket from another origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = Arc::clone(&state.connections).try_acquire_owned() else {
        tracing::warn!(
            limit = MAX_WEBSOCKET_CLIENTS,
            "dashboard WebSocket client limit reached"
        );
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_CLIENT_MESSAGE_BYTES)
        .max_frame_size(MAX_CLIENT_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            tracing::debug!("dashboard WebSocket client connected");
            stream_snapshots(socket, state.updates.subscribe(), state.shutdown).await;
            tracing::debug!("dashboard WebSocket client disconnected");
        })
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LogMessage<'a> {
    Reset { capacity: usize, dropped: u64 },
    Batch { entries: Vec<&'a LogEntry> },
    Entry { entry: &'a LogEntry },
    Dropped { count: u64 },
}

async fn log_websocket(
    ws: WebSocketUpgrade,
    State(state): State<UiState>,
    headers: HeaderMap,
) -> Response {
    let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let allowed_origin = format!("http://{host}");
    if headers.get(ORIGIN).and_then(|value| value.to_str().ok()) != Some(allowed_origin.as_str()) {
        tracing::warn!("rejected dashboard log WebSocket from another origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = Arc::clone(&state.log_connections).try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_CLIENT_MESSAGE_BYTES)
        .max_frame_size(MAX_CLIENT_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            stream_logs(socket, state.logs, state.shutdown).await;
        })
}

async fn stream_logs(mut socket: WebSocket, logs: LogHub, mut shutdown: watch::Receiver<bool>) {
    let mut updates = logs.subscribe();
    let Some(mut last_sequence) = send_log_snapshot(&mut socket, &logs).await else {
        return;
    };
    let mut dropped = logs.dropped();
    let mut dropped_tick = time::interval(LOG_DROPPED_UPDATE_INTERVAL);
    loop {
        tokio::select! {
            changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() { break; },
            received = updates.recv() => match received {
                Ok(entry) if entry.sequence > last_sequence => {
                    last_sequence = entry.sequence;
                    if !send_log_message(&mut socket, &LogMessage::Entry { entry: &entry }).await { break; }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let Some(sequence) = send_log_snapshot(&mut socket, &logs).await else { break; };
                    last_sequence = sequence;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = dropped_tick.tick() => {
                let count = logs.dropped();
                if count != dropped {
                    dropped = count;
                    if !send_log_message(&mut socket, &LogMessage::Dropped { count }).await { break; }
                }
            }
            received = socket.recv() => match received {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            }
        }
    }
}

async fn send_log_snapshot(socket: &mut WebSocket, logs: &LogHub) -> Option<u64> {
    let hub = logs.clone();
    let Ok(Some(entries)) = tokio::task::spawn_blocking(move || hub.snapshot()).await else {
        tracing::error!("dashboard log buffer unavailable");
        return None;
    };
    let sequence = entries.last().map_or(0, |entry| entry.sequence);
    if !send_log_message(
        socket,
        &LogMessage::Reset {
            capacity: logs.capacity(),
            dropped: logs.dropped(),
        },
    )
    .await
    {
        return None;
    }
    for batch in entries.chunks(LOG_REPLAY_BATCH_SIZE) {
        let batch = batch.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            serde_json::to_string(&LogMessage::Batch {
                entries: batch.iter().map(AsRef::as_ref).collect(),
            })
        })
        .await;
        let json = match result {
            Ok(Ok(json)) => json,
            Ok(Err(error)) => {
                tracing::error!(%error, "dashboard log batch serialization failed");
                return None;
            }
            Err(error) => {
                tracing::error!(%error, "dashboard log batch task failed");
                return None;
            }
        };
        if socket.send(Message::Text(json.into())).await.is_err() {
            return None;
        }
    }
    Some(sequence)
}

async fn send_log_message(socket: &mut WebSocket, message: &LogMessage<'_>) -> bool {
    let Ok(json) = serde_json::to_string(message) else {
        tracing::error!("dashboard log serialization failed");
        return false;
    };
    socket.send(Message::Text(json.into())).await.is_ok()
}

async fn stream_snapshots(
    mut socket: WebSocket,
    mut updates: watch::Receiver<String>,
    mut shutdown: watch::Receiver<bool>,
) {
    let initial = updates.borrow_and_update().clone();
    if socket.send(Message::Text(initial.into())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() { break; },
            changed = updates.changed() => {
                if changed.is_err() { break; }
                let snapshot = updates.borrow_and_update().clone();
                if socket.send(Message::Text(snapshot.into())).await.is_err() { break; }
            }
            received = socket.recv() => match received {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            }
        }
    }
}
