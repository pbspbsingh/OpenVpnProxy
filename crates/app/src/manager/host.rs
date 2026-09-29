use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ovpn_client::{ClientConfig, Session};
use ovpn_netstack::{Stack, TunnelConfig};
use ovpn_profile::Profile;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time;

use super::discovery::HostCandidate;
use super::routing::{HostPhase, Shared};

const TUNNEL_PACKET_QUEUE_CAPACITY: usize = 1024;
pub(super) const CONTROL_SETUP_ALLOWANCE: Duration = Duration::from_secs(50);
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const STABLE_SESSION_WINDOW: Duration = Duration::from_secs(30);
const HOST_STATUS_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct HostWorker {
    pub(super) id: usize,
    pub(super) candidate: HostCandidate,
    pub(super) profile: Arc<Profile>,
    pub(super) username: Arc<str>,
    pub(super) password: Arc<str>,
    pub(super) dns_override: Option<Ipv4Addr>,
    pub(super) permits: Arc<Semaphore>,
    pub(super) shared: Arc<Shared>,
    pub(super) stop: watch::Receiver<bool>,
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
            shared,
            mut stop,
        } = self;
        let mut delay = INITIAL_RETRY_DELAY;
        let mut next_endpoint = 0;
        loop {
            if *stop.borrow() {
                break;
            }
            shared.phase(id, HostPhase::Waiting);
            let permit = tokio::select! {
                result = permits.acquire() => match result {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
                _ = stop.changed() => break,
            };
            if *stop.borrow() {
                break;
            }
            shared.phase(id, HostPhase::Connecting);
            let Some(&endpoint) = candidate.endpoints.get(next_endpoint) else {
                tracing::error!(host_id = id, "VPN host lost its endpoints");
                break;
            };
            next_endpoint = (next_endpoint + 1) % candidate.endpoints.len();
            let started = Instant::now();
            tracing::info!(host_id = id, address = %candidate.address, %endpoint, "connecting VPN host");
            let connect_timeout = profile
                .handshake_window
                .saturating_add(CONTROL_SETUP_ALLOWANCE);
            let result = tokio::select! {
                result = time::timeout(connect_timeout, connect_host(endpoint, &profile, &username, &password, dns_override)) =>
                    result.map_err(|_| anyhow!("VPN host connection timed out")).and_then(|result| result),
                _ = stop.changed() => break,
            };
            match result {
                Ok((session, stack, outbound)) => {
                    shared.ready(id, endpoint, &stack, started.elapsed());
                    let active_since = Instant::now();
                    let result =
                        drive_host(id, endpoint, &stack, session, outbound, &mut stop).await;
                    let shutdown = *stop.borrow();
                    shared.down(id, shutdown);
                    if let Err(error) = stack.reset().await {
                        tracing::error!(host_id = id, %endpoint, %error, "VPN packet stack reset failed");
                    }
                    if shutdown {
                        break;
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
                }
            }
            drop(permit);
            tracing::debug!(host_id = id, %endpoint, ?delay, "waiting before VPN host retry");
            tokio::select! {
                _ = time::sleep(delay) => {}
                _ = stop.changed() => break,
            }
            delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        }
        shared.down(id, true);
        tracing::debug!(host_id = id, address = %candidate.address, "VPN host worker stopped");
    }
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
        .map(|address| vec![address])
        .unwrap_or_else(|| settings.dns.clone());
    let tunnel = TunnelConfig::new(settings.local, settings.gateway, dns, settings.mtu)
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
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut status = time::interval(HOST_STATUS_INTERVAL);
    status.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut sent_packets = 0_u64;
    let mut received_packets = 0_u64;
    loop {
        if !stack.is_ready() {
            bail!("VPN packet stack stopped");
        }
        tokio::select! {
            _ = stop.changed() => return Ok(()),
            packet = outbound.recv() => {
                let packet = packet.context("VPN packet output channel closed")?;
                tracing::trace!(host_id = id, %endpoint, bytes = packet.len(), "sending VPN packet");
                session.send_packet(&packet).await?;
                sent_packets += 1;
            }
            received = session.step() => {
                if let Some(packet) = received? {
                    tracing::trace!(host_id = id, %endpoint, bytes = packet.len(), "received VPN packet");
                    stack.packet(&packet)?;
                    received_packets += 1;
                }
            }
            _ = status.tick() => {
                tracing::debug!(host_id = id, %endpoint, sent_packets, received_packets, "VPN host activity");
            }
        }
    }
}
