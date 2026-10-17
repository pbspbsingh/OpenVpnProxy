use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ovpn_client::{ClientConfig, Session};
use ovpn_netstack::{Ipv6Config, Ipv6Route, StackOwner, TunnelConfig};
use ovpn_profile::Profile;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time;

use super::discovery::HostCandidate;
use super::probe::{LatencyScore, PROBE_INTERVAL, measure, measure_with_session};
use super::routing::{HostActivation, Shared};
use super::telemetry::{HostPhase, HostTraffic};

const TUNNEL_PACKET_QUEUE_CAPACITY: usize = 1024;
pub(super) const CONTROL_SETUP_ALLOWANCE: Duration = Duration::from_secs(30);
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const STABLE_SESSION_WINDOW: Duration = Duration::from_secs(30);
const HOST_STATUS_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_STAGGER_SECONDS: u64 = 3;
const PROBE_STAGGER_SLOTS: u64 = 20;

pub(super) struct HostWorker {
    pub id: usize,
    pub candidate: HostCandidate,
    pub profile: Arc<Profile>,
    pub username: Arc<str>,
    pub password: Arc<str>,
    pub dns_override: Option<Ipv4Addr>,
    pub permits: Arc<Semaphore>,
    pub enabled: watch::Receiver<HostActivation>,
    pub traffic: HostTraffic,
    pub shared: Arc<Shared>,
    pub stop: watch::Receiver<bool>,
}

enum HostExit {
    Idle,
    Shutdown,
}

impl HostWorker {
    pub(super) async fn run(mut self) {
        let id = self.id;
        let mut delay = INITIAL_RETRY_DELAY;
        let mut next_endpoint = 0;
        let mut activation_epoch = None;
        'worker: loop {
            if *self.stop.borrow() {
                break;
            }
            self.shared.phase(id, HostPhase::Dormant).await;
            while *self.enabled.borrow() == HostActivation::Dormant {
                tokio::select! {
                    changed = self.enabled.changed() => if changed.is_err() { break 'worker; },
                    _ = self.stop.changed() => break,
                }
                if *self.stop.borrow() {
                    break;
                }
            }
            if *self.stop.borrow() || *self.enabled.borrow() == HostActivation::Dormant {
                if *self.stop.borrow() {
                    break;
                }
                continue;
            }
            let activation = *self.enabled.borrow();
            let HostActivation::Active {
                epoch,
                preferred_endpoint,
            } = activation
            else {
                continue;
            };
            if activation_epoch != Some(epoch) {
                next_endpoint = self
                    .candidate
                    .endpoints
                    .iter()
                    .position(|&endpoint| endpoint == preferred_endpoint)
                    .unwrap_or(0);
                activation_epoch = Some(epoch);
            }
            let permit = tokio::select! {
                result = Arc::clone(&self.permits).acquire_owned() => match result {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
                _ = self.enabled.changed() => continue,
                _ = self.stop.changed() => break,
            };
            if *self.stop.borrow() || *self.enabled.borrow() != activation {
                if *self.stop.borrow() {
                    break;
                }
                continue;
            }
            self.shared.phase(id, HostPhase::Connecting).await;
            let Some(&endpoint) = self.candidate.endpoints.get(next_endpoint) else {
                tracing::error!(host_id = id, "VPN host lost its endpoints");
                break;
            };
            next_endpoint = (next_endpoint + 1) % self.candidate.endpoints.len();
            let started = Instant::now();
            tracing::info!(host_id = id, address = %self.candidate.address, %endpoint, epoch, "connecting selected VPN host");
            let connect_timeout = self
                .profile
                .handshake_window
                .saturating_add(CONTROL_SETUP_ALLOWANCE);
            let result = tokio::select! {
                result = time::timeout(connect_timeout, connect_host(endpoint, &self.profile, &self.username, &self.password, self.dns_override)) =>
                    result.map_err(|_| anyhow!("VPN host connection timed out")).and_then(|result| result),
                _ = self.enabled.changed() => continue,
                _ = self.stop.changed() => break,
            };
            match result {
                Ok(mut tunnel) => {
                    let fresh_score = tokio::select! {
                        result = tunnel.measure() => result,
                        _ = self.enabled.changed() => {
                            tunnel.shutdown().await;
                            continue;
                        },
                        _ = self.stop.changed() => {
                            tunnel.shutdown().await;
                            break;
                        },
                    };
                    let score = match fresh_score {
                        Ok(score) => score,
                        Err(error) => {
                            tracing::warn!(host_id = id, %endpoint, %error, "fresh VPN host probe failed");
                            self.shared.down(id, false).await;
                            tunnel.shutdown().await;
                            drop(permit);
                            tokio::select! {
                                _ = time::sleep(delay) => {},
                                _ = self.enabled.changed() => {},
                                _ = self.stop.changed() => break,
                            }
                            delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
                            continue;
                        }
                    };
                    if *self.enabled.borrow() != activation {
                        tunnel.shutdown().await;
                        continue;
                    }
                    self.shared
                        .ready(
                            id,
                            epoch,
                            endpoint,
                            &tunnel.stack.client(),
                            started.elapsed(),
                            score,
                        )
                        .await;
                    let active_since = Instant::now();
                    let result = tunnel.run(&mut self, epoch).await;
                    let shutdown = *self.stop.borrow() || matches!(&result, Ok(HostExit::Shutdown));
                    let idle = matches!(&result, Ok(HostExit::Idle));
                    if idle {
                        self.shared.parked(id).await;
                    } else {
                        self.shared.down(id, shutdown).await;
                    }
                    tunnel.shutdown().await;
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
                    self.shared.down(id, false).await;
                    tracing::warn!(host_id = id, %endpoint, %error, cause = %error.root_cause(), "VPN host connection failed");
                    drop(permit);
                }
            }
            tracing::debug!(host_id = id, %endpoint, ?delay, "waiting before VPN host retry");
            tokio::select! {
                _ = time::sleep(delay) => {}
                _ = self.enabled.changed() => {}
                _ = self.stop.changed() => break,
            }
            delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        }
        self.shared.down(id, true).await;
        tracing::debug!(host_id = id, address = %self.candidate.address, "VPN host worker stopped");
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
        let mut tunnel = match connection {
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
        let score = tunnel.measure().await;
        tunnel.shutdown().await;
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
) -> Result<HostSession> {
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
    let (tx, rx) = mpsc::channel(TUNNEL_PACKET_QUEUE_CAPACITY);
    let stack = StackOwner::start(tunnel, tx)
        .await
        .context("VPN packet stack setup failed")?;
    Ok(HostSession {
        endpoint,
        session,
        stack,
        outbound: rx,
    })
}

/// All live resources for one connection attempt share a single lifetime.
struct HostSession {
    endpoint: SocketAddr,
    session: Session,
    stack: StackOwner,
    outbound: mpsc::Receiver<Vec<u8>>,
}

impl HostSession {
    async fn measure(&mut self) -> Result<LatencyScore> {
        measure_with_session(&mut self.session, &self.stack, &mut self.outbound).await
    }

    async fn shutdown(self) {
        self.stack.shutdown().await;
    }

    async fn run(&mut self, worker: &mut HostWorker, epoch: u64) -> Result<HostExit> {
        let id = worker.id;
        let endpoint = self.endpoint;
        let owner = &self.stack;
        let session = &mut self.session;
        let outbound = &mut self.outbound;
        let shared = &worker.shared;
        let traffic = &mut worker.traffic;
        let enabled = &mut worker.enabled;
        let stop = &mut worker.stop;
        let started = Instant::now();
        let stack = owner.client();
        let stack_id = stack.id();
        let mut status = time::interval(HOST_STATUS_INTERVAL);
        status.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let stagger =
            Duration::from_secs(PROBE_STAGGER_SECONDS * (id as u64 % PROBE_STAGGER_SLOTS));
        let mut probe_interval = time::interval_at(
            time::Instant::now() + PROBE_INTERVAL + stagger,
            PROBE_INTERVAL,
        );
        probe_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut traffic_tick = time::interval(Duration::from_secs(1));
        traffic_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut probes = JoinSet::new();
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
                        if enabled.borrow().epoch() != Some(epoch) { return Ok(HostExit::Idle); }
                    }
                    _ = probe_interval.tick() => {
                        if probes.is_empty() {
                            let stack = stack.clone();
                            let shared = Arc::clone(shared);
                            probes.spawn(async move {
                                let started = Instant::now();
                                let result = measure(&stack).await;
                                shared.record_probe(id, stack.id(), result, started.elapsed()).await;
                            });
                        }
                    }
                    Some(result) = probes.join_next(), if !probes.is_empty() => {
                        if let Err(error) = result { tracing::warn!(host_id = id, %error, "VPN probe task failed"); }
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
                            let packet_bytes = packet.len();
                            owner.packet(packet)?;
                            traffic.add_rx(packet_bytes);
                            received_packets += 1;
                            received_bytes += packet_bytes as u64;
                        }
                    }
                    _ = traffic_tick.tick(), if traffic.is_enabled() => traffic.publish(),
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
        traffic.publish();
        probes.shutdown().await;
        tracing::debug!(host_id = id, %endpoint, stack_id, elapsed = ?started.elapsed(), sent_packets, received_packets, sent_bytes, received_bytes, outcome = match &result { Ok(HostExit::Idle) => "idle", Ok(HostExit::Shutdown) => "shutdown", Err(_) => "error" }, "VPN host traffic summary");
        result
    }
}
