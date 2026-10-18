mod configuration;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::map_response;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::time;

use self::configuration::{
    activate_configuration, create_configuration, delete_configuration, list_configurations,
    update_configuration,
};
use crate::assets;
use crate::logs::{LogEntry, LogHub};
use crate::{ConfigurationControl, GroupPage, ProfileSummary};

const MAX_WEBSOCKET_CLIENTS: usize = 32;
const MAX_LOG_CLIENTS: usize = 8;
const LOG_DROPPED_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const LOG_REPLAY_BATCH_SIZE: usize = 256;
const MAX_GROUP_QUERIES: usize = 4;
const MAX_CLIENT_MESSAGE_BYTES: usize = 1024;
const GROUP_PAGE_SIZE: usize = 100;

/// A source of read-only dashboard data. Implementations must omit credentials.
pub trait DashboardSource: Send + Sync + 'static {
    fn subscribe(&self) -> watch::Receiver<String>;
    fn group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Option<GroupPage>, GroupError>> + Send + '_>>;
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
    configurations: Option<Arc<dyn ConfigurationControl>>,
    configuration_queries: Arc<Semaphore>,
    source: Arc<dyn DashboardSource>,
    updates: watch::Receiver<String>,
    connections: Arc<Semaphore>,
    log_connections: Arc<Semaphore>,
    logs: LogHub,
    group_queries: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
    shutdown_request: watch::Sender<bool>,
}

#[derive(Deserialize)]
struct GroupQuery {
    offset: Option<usize>,
}

/// Serve the embedded dashboard and its live WebSocket feed.
/// Shutdown requests are sent to the application; `shutdown` stops this server after cleanup.
pub async fn serve<S: DashboardSource>(
    listener: TcpListener,
    source: S,
    shutdown: watch::Receiver<bool>,
    logs: LogHub,
    shutdown_request: watch::Sender<bool>,
    configurations: Option<Arc<dyn ConfigurationControl>>,
) -> Result<(), UiError> {
    let source: Arc<dyn DashboardSource> = Arc::new(source);
    let updates = source.subscribe();
    let state = UiState {
        configurations,
        configuration_queries: Arc::new(Semaphore::new(4)),
        source,
        updates,
        connections: Arc::new(Semaphore::new(MAX_WEBSOCKET_CLIENTS)),
        log_connections: Arc::new(Semaphore::new(MAX_LOG_CLIENTS)),
        logs,
        group_queries: Arc::new(Semaphore::new(MAX_GROUP_QUERIES)),
        shutdown: shutdown.clone(),
        shutdown_request,
    };
    let router = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/{*path}", get(asset))
        .route("/api/hosts/{host_id}/groups", get(groups))
        .route("/api/profile", get(profile))
        .route("/api/shutdown", post(request_shutdown))
        .route(
            "/api/configurations",
            get(list_configurations).post(create_configuration),
        )
        .route(
            "/api/configurations/{id}",
            axum::routing::put(update_configuration).delete(delete_configuration),
        )
        .route(
            "/api/configurations/{id}/activate",
            post(activate_configuration),
        )
        .route("/ws", any(websocket))
        .route("/ws/logs", any(log_websocket))
        .layer(map_response(no_cache))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state);
    tracing::info!(address = %listener.local_addr()?, "dashboard listening");

    let result = axum::serve(listener, router)
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await;
    result.map_err(UiError::from)
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn no_cache(mut response: Response) -> Response {
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    response
}

async fn index() -> impl IntoResponse {
    Html(assets::index())
}

async fn asset(Path(path): Path<String>) -> Response {
    match assets::get(&path) {
        Some((content_type, body)) => ([(CONTENT_TYPE, content_type)], body).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn groups(
    Path(host_id): Path<usize>,
    Query(query): Query<GroupQuery>,
    State(state): State<UiState>,
) -> Response {
    let Ok(permit) = Arc::clone(&state.group_queries).try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let result = state
        .source
        .group_page(host_id, query.offset.unwrap_or(0), GROUP_PAGE_SIZE)
        .await;
    drop(permit);
    match result {
        Ok(Some(page)) => Json(page).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(host_id, %error, "dashboard assignment lookup failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn profile(State(state): State<UiState>) -> impl IntoResponse {
    Json(state.source.profile())
}

fn check_origin(headers: &HeaderMap) -> Result<(), StatusCode> {
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let allowed_origin = format!("http://{host}");
    if headers.get(ORIGIN).and_then(|value| value.to_str().ok()) != Some(allowed_origin.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn request_shutdown(State(state): State<UiState>, headers: HeaderMap) -> StatusCode {
    if let Err(status) = check_origin(&headers) {
        return status;
    }
    tracing::info!("shutdown requested from dashboard");
    state.shutdown_request.send_replace(true);
    StatusCode::ACCEPTED
}

async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<UiState>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = check_origin(&headers) {
        tracing::warn!("rejected dashboard WebSocket from another origin");
        return status.into_response();
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
            stream_snapshots(socket, state.updates.clone(), state.shutdown).await;
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
    if let Err(status) = check_origin(&headers) {
        tracing::warn!("rejected dashboard log WebSocket from another origin");
        return status.into_response();
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
