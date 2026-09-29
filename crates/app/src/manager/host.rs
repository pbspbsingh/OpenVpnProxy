use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ovpn_client::{ClientConfig, Session};
use ovpn_netstack::{Ipv6Config, Ipv6Route, Stack, TunnelConfig};
use ovpn_profile::Profile;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time;

use super::discovery::HostCandidate;
use super::probe::{LatencyScore, PROBE_INTERVAL, measure, measure_with_session};
use super::routing::{HostActivation, HostPhase, Shared};
use super::telemetry::HostTraffic;

const TUNNEL_PACKET_QUEUE_CAPACITY: usize = 1024;
pub(super) const CONTROL_SETUP_ALLOWANCE: Duration = Duration::from_secs(30);
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const STABLE_SESSION_WINDOW: Duration = Duration::from_secs(30);
const HOST_STATUS_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_STAGGER_SECONDS: u64 = 3;
const PROBE_STAGGER_SLOTS: u64 = 20;

pub(super) struct HostWorker {
    pub(super) id: usize,
    pub(super) candidate: HostCandidate,
    pub(super) profile: Arc<Profile>,
    pub(super) username: Arc<str>,
    pub(super) password: Arc<str>,
    pub(super) dns_override: Option<Ipv4Addr>,
    pub(super) permits: Arc<Semaphore>,
    pub(super) enabled: watch::Receiver<HostActivation>,
    pub(super) traffic: Arc<HostTraffic>,
    pub(super) shared: Arc<Shared>,
    pub(super) stop: watch::Receiver<bool>,
}

enum HostExit {
    Idle,
    Shutdown,
}

impl HostWorker {
    pub(super) async fn run(self) {
        let Self {
            id,
            candidate,
            profile,
            username,
            password,
            dns_override,
            permits,
            mut enabled,
            traffic,
            shared,
            mut stop,
        } = self;
        let mut delay = INITIAL_RETRY_DELAY;
        let mut next_endpoint = 0;
        'worker: loop {
            if *stop.borrow() {
                break;
            }
            shared.phase(id, HostPhase::Dormant);
            while *enabled.borrow() == HostActivation::Dormant {
                tokio::select! {
                    changed = enabled.changed() => if changed.is_err() { break 'worker; },
                    _ = stop.changed() => break,
                }
                if *stop.borrow() {
                    break;
                }
            }
            if *stop.borrow() || *enabled.borrow() == HostActivation::Dormant {
                if *stop.borrow() {
                    break;
                }
                continue;
            }
            let HostActivation::Active(epoch) = *enabled.borrow() else {
                continue;
            };
            let permit = tokio::select! {
                result = permits.acquire() => match result {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
                _ = enabled.changed() => continue,
                _ = stop.changed() => break,
            };
            if *stop.borrow() || *enabled.borrow() != HostActivation::Active(epoch) {
                if *stop.borrow() {
                    break;
                }
                continue;
            }
            shared.phase(id, HostPhase::Connecting);
            let Some(&endpoint) = candidate.endpoints.get(next_endpoint) else {
                tracing::error!(host_id = id, "VPN host lost its endpoints");
                break;
            };
            next_endpoint = (next_endpoint + 1) % candidate.endpoints.len();
            let started = Instant::now();
            tracing::info!(host_id = id, address = %candidate.address, %endpoint, epoch, "connecting selected VPN host");
            let connect_timeout = profile
                .handshake_window
                .saturating_add(CONTROL_SETUP_ALLOWANCE);
            let result = tokio::select! {
                result = time::timeout(connect_timeout, connect_host(endpoint, &profile, &username, &password, dns_override)) =>
                    result.map_err(|_| anyhow!("VPN host connection timed out")).and_then(|result| result),
                _ = enabled.changed() => continue,
                _ = stop.changed() => break,
            };
            match result {
                Ok((mut session, stack, mut outbound)) => {
                    let fresh_score = tokio::select! {
                        result = measure_with_session(&mut session, &stack, &mut outbound) => result,
                        _ = enabled.changed() => {
                            let _ = stack.reset().await;
                            continue;
                        },
                        _ = stop.changed() => {
                            let _ = stack.reset().await;
                            break;
                        },
                    };
                    let score = match fresh_score {
                        Ok(score) => score,
                        Err(error) => {
                            tracing::warn!(host_id = id, %endpoint, %error, "fresh VPN host probe failed");
                            shared.down(id, false);
                            let _ = stack.reset().await;
                            drop(permit);
                            tokio::select! {
                                _ = time::sleep(delay) => {},
                                _ = enabled.changed() => {},
                                _ = stop.changed() => break,
                            }
                            delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
                            continue;
                        }
                    };
                    if *enabled.borrow() != HostActivation::Active(epoch) {
                        let _ = stack.reset().await;
                        continue;
                    }
                    shared.ready(id, endpoint, &stack, started.elapsed(), score);
                    let active_since = Instant::now();
                    let result = drive_host(
                        id,
                        endpoint,
                        &stack,
                        session,
                        outbound,
                        &shared,
                        &traffic,
                        &mut enabled,
                        epoch,
                        &mut stop,
                    )
                    .await;
                    let shutdown = *stop.borrow() || matches!(&result, Ok(HostExit::Shutdown));
                    let idle = matches!(&result, Ok(HostExit::Idle));
                    if idle {
                        shared.parked(id);
                    } else {
                        shared.down(id, shutdown);
                    }
                    if let Err(error) = stack.reset().await {
                        tracing::error!(host_id = id, %endpoint, %error, "VPN packet stack reset failed");
                    }
                    drop(permit);
                    if shutdown {
                        break;
                    }
                    if idle {
                        delay = INITIAL_RETRY_DELAY;
                        continue;
                    }
                    if let Err(error) = result {
                        tracing::warn!(host_id = id, %endpoint, %error, cause = %error.root_cause(), "VPN host disconnected");
                    }
                    if active_since.elapsed() >= STABLE_SESSION_WINDOW {
                        delay = INITIAL_RETRY_DELAY;
                    }
                }
                Err(error) => {
                    shared.down(id, false);
                    tracing::warn!(host_id = id, %endpoint, %error, cause = %error.root_cause(), "VPN host connection failed");
                    drop(permit);
                }
            }
            tracing::debug!(host_id = id, %endpoint, ?delay, "waiting before VPN host retry");
            tokio::select! {
                _ = time::sleep(delay) => {}
                _ = enabled.changed() => {}
                _ = stop.changed() => break,
            }
            delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        }
        shared.down(id, true);
        tracing::debug!(host_id = id, address = %candidate.address, "VPN host worker stopped");
    }
}

pub(super) async fn benchmark_host(
    id: usize,
    candidate: &HostCandidate,
    profile: &Profile,
    username: &str,
    password: &str,
    dns_override: Option<Ipv4Addr>,
) -> Result<(SocketAddr, LatencyScore)> {
    let host_started = Instant::now();
    let connect_timeout = profile
        .handshake_window
        .saturating_add(CONTROL_SETUP_ALLOWANCE);
    let mut last_error = None;
    for &endpoint in &candidate.endpoints {
        let started = Instant::now();
        let connection = time::timeout(
            connect_timeout,
            connect_host(endpoint, profile, username, password, dns_override),
        )
        .await;
        let (mut session, stack, mut outbound) = match connection {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                tracing::warn!(host_id = id, %endpoint, %error, "VPN baseline connection failed");
                last_error = Some(error);
                continue;
            }
            Err(_) => {
                tracing::warn!(host_id = id, %endpoint, ?connect_timeout, "VPN baseline connection timed out");
                last_error = Some(anyhow!("VPN baseline connection timed out"));
                continue;
            }
        };
        let setup_elapsed = started.elapsed();
        let score = measure_with_session(&mut session, &stack, &mut outbound).await;
        if let Err(error) = stack.reset().await {
            tracing::warn!(host_id = id, %endpoint, %error, "VPN baseline stack reset failed");
        }
        match score {
            Ok(score) => {
                tracing::info!(host_id = id, %endpoint, ?setup_elapsed, latency_score = ?score.median, score_elapsed = ?score.elapsed, total_elapsed = ?host_started.elapsed(), successful_samples = score.successful_samples, "VPN baseline latency score measured");
                return Ok((endpoint, score));
            }
            Err(error) => {
                tracing::warn!(host_id = id, %endpoint, ?setup_elapsed, total_elapsed = ?started.elapsed(), %error, "VPN baseline probe failed");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("VPN host has no endpoints")))
}

async fn connect_host(
    endpoint: SocketAddr,
    profile: &Profile,
    username: &str,
    password: &str,
    dns_override: Option<Ipv4Addr>,
) -> Result<(Session, Stack, mpsc::Receiver<Vec<u8>>)> {
    let config = ClientConfig {
        endpoint,
        ca_pem: &profile.ca_pem,
        tls_crypt_key: &profile.tls_crypt_key,
        require_server_certificate_purpose: profile.require_server_certificate_purpose,
        renegotiate_after: profile.renegotiate_after,
        handshake_window: profile.handshake_window,
        transition_window: profile.transition_window,
    };
    let session = Session::connect(&config, username, password)
        .await
        .context("OpenVPN session failed")?;
    let settings = &session.config().tunnel;
    let dns = dns_override
        .map(|address| vec![IpAddr::V4(address)])
        .unwrap_or_else(|| settings.dns.clone());
    let ipv6 = settings
        .ipv6
        .as_ref()
        .filter(|_| !profile.block_ipv6)
        .map(|config| Ipv6Config {
            local: config.local,
            prefix_len: config.prefix_len,
            routes: config
                .routes
                .iter()
                .map(|route| Ipv6Route {
                    network: route.network,
                    prefix_len: route.prefix_len,
                    gateway: route.gateway,
                })
                .collect(),
        });
    let tunnel = TunnelConfig::new(settings.local, settings.gateway, dns, settings.mtu, ipv6)
        .context("invalid VPN tunnel settings")?;
    let stack = Stack::start();
    let (tx, rx) = mpsc::channel(TUNNEL_PACKET_QUEUE_CAPACITY);
    stack
        .configure(tunnel, tx)
        .await
        .context("VPN packet stack setup failed")?;
    stack
        .activate()
        .context("VPN packet stack activation failed")?;
    Ok((session, stack, rx))
}

async fn drive_host(
    id: usize,
    endpoint: SocketAddr,
    stack: &Stack,
    mut session: Session,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    shared: &Arc<Shared>,
    traffic: &HostTraffic,
    enabled: &mut watch::Receiver<HostActivation>,
    epoch: u64,
    stop: &mut watch::Receiver<bool>,
) -> Result<HostExit> {
    let started = Instant::now();
    let stack_id = stack.id();
    let mut status = time::interval(HOST_STATUS_INTERVAL);
    status.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let stagger = Duration::from_secs(PROBE_STAGGER_SECONDS * (id as u64 % PROBE_STAGGER_SLOTS));
    let mut probe_interval = time::interval_at(
        time::Instant::now() + PROBE_INTERVAL + stagger,
        PROBE_INTERVAL,
    );
    probe_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut probe_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut sent_packets = 0_u64;
    let mut received_packets = 0_u64;
    let mut sent_bytes = 0_u64;
    let mut received_bytes = 0_u64;
    let mut last_sent_bytes = 0_u64;
    let mut last_received_bytes = 0_u64;
    let mut last_status = Instant::now();
    let mut max_send_time = Duration::ZERO;
    let result = async {
        loop {
            if !stack.is_ready() {
                bail!("VPN packet stack stopped");
            }
            tokio::select! {
                _ = stop.changed() => return Ok(HostExit::Shutdown),
                changed = enabled.changed() => {
                    changed.context("VPN host activation channel closed")?;
                    if *enabled.borrow() != HostActivation::Active(epoch) { return Ok(HostExit::Idle); }
                }
                _ = probe_interval.tick() => {
                    if probe_task.as_ref().is_none_or(tokio::task::JoinHandle::is_finished) {
                        let stack = stack.clone();
                        let shared = Arc::clone(shared);
                        probe_task = Some(tokio::spawn(async move {
                            let started = Instant::now();
                            let result = measure(&stack).await;
                            shared.record_probe(id, stack.id(), result, started.elapsed());
                        }));
                    }
                }
                packet = outbound.recv() => {
                    let packet = packet.context("VPN packet output channel closed")?;
                    tracing::trace!(host_id = id, %endpoint, bytes = packet.len(), "sending VPN packet");
                    let send_started = Instant::now();
                    session.send_packet(&packet).await?;
                    traffic.add_tx(packet.len());
                    max_send_time = max_send_time.max(send_started.elapsed());
                    sent_packets += 1;
                    sent_bytes += packet.len() as u64;
                }
                received = session.step() => {
                    if let Some(packet) = received? {
                        tracing::trace!(host_id = id, %endpoint, bytes = packet.len(), "received VPN packet");
                        stack.packet(&packet)?;
                        traffic.add_rx(packet.len());
                        received_packets += 1;
                        received_bytes += packet.len() as u64;
                    }
                }
                _ = status.tick() => {
                    if sent_bytes != last_sent_bytes || received_bytes != last_received_bytes {
                        tracing::debug!(host_id = id, %endpoint, stack_id, window = ?last_status.elapsed(), sent_packets, received_packets, sent_bytes, received_bytes, window_sent_bytes = sent_bytes - last_sent_bytes, window_received_bytes = received_bytes - last_received_bytes, ?max_send_time, "VPN host traffic");
                    }
                    last_sent_bytes = sent_bytes;
                    last_received_bytes = received_bytes;
                    last_status = Instant::now();
                    max_send_time = Duration::ZERO;
                }
            }
        }
    }.await;
    if let Some(task) = probe_task {
        task.abort();
        let _ = task.await;
    }
    tracing::debug!(host_id = id, %endpoint, stack_id, elapsed = ?started.elapsed(), sent_packets, received_packets, sent_bytes, received_bytes, outcome = match &result { Ok(HostExit::Idle) => "idle", Ok(HostExit::Shutdown) => "shutdown", Err(_) => "error" }, "VPN host traffic summary");
    result
}
