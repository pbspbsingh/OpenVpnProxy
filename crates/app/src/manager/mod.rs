mod discovery;
mod host;
mod routing;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ovpn_profile::Profile;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time;

use self::discovery::{MAX_ENDPOINTS, resolve_candidates};
use self::host::{CONTROL_SETUP_ALLOWANCE, HostWorker};
use self::routing::{Host, HostPhase, RoutingState, Shared};

const MAX_ACTIVE_VPN_HOSTS: usize = MAX_ENDPOINTS;
const DEFAULT_MAX_ACTIVE_VPN_HOSTS: usize = 16;
const STARTUP_ALLOWANCE: Duration = Duration::from_secs(15);

pub(crate) use self::routing::RouterHandle;

pub(crate) struct ConnectionManager {
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    workers: JoinSet<()>,
    startup_timeout: Duration,
}

impl ConnectionManager {
    pub(crate) async fn start(
        profile: Profile,
        username: String,
        password: String,
        dns_override: Option<Ipv4Addr>,
        max_active_vpn_hosts: Option<NonZeroUsize>,
    ) -> Result<Self> {
        let candidates = resolve_candidates(&profile).await?;
        let max_active_vpn_hosts = max_active_vpn_hosts
            .map(NonZeroUsize::get)
            .unwrap_or(DEFAULT_MAX_ACTIVE_VPN_HOSTS);
        if max_active_vpn_hosts > MAX_ACTIVE_VPN_HOSTS {
            bail!("max_active_vpn_hosts exceeds supported host limit");
        }
        let hosts = candidates
            .iter()
            .map(|candidate| {
                Ok(Host {
                    endpoint: *candidate
                        .endpoints
                        .first()
                        .ok_or_else(|| anyhow!("VPN host has no endpoint"))?,
                    phase: HostPhase::Waiting,
                    stack: None,
                    active: Arc::new(AtomicUsize::new(0)),
                    generation: 0,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let (ready, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            state: Mutex::new(RoutingState {
                hosts,
                sticky: HashMap::new(),
                next_choice: 0,
            }),
            ready,
        });
        let (stop, _) = watch::channel(false);
        let profile = Arc::new(profile);
        let startup_timeout = profile
            .handshake_window
            .saturating_add(CONTROL_SETUP_ALLOWANCE)
            .saturating_add(STARTUP_ALLOWANCE);
        let username: Arc<str> = username.into();
        let password: Arc<str> = password.into();
        let permits = Arc::new(Semaphore::new(max_active_vpn_hosts));
        let mut workers = JoinSet::new();
        for (id, candidate) in candidates.into_iter().enumerate() {
            workers.spawn(
                HostWorker {
                    id,
                    candidate,
                    profile: Arc::clone(&profile),
                    username: Arc::clone(&username),
                    password: Arc::clone(&password),
                    dns_override,
                    permits: Arc::clone(&permits),
                    shared: Arc::clone(&shared),
                    stop: stop.subscribe(),
                }
                .run(),
            );
        }
        tracing::info!(
            candidates = workers.len(),
            max_active = max_active_vpn_hosts,
            "VPN host pool started"
        );
        Ok(Self {
            shared,
            stop,
            workers,
            startup_timeout,
        })
    }

    pub(crate) fn router(&self) -> RouterHandle {
        RouterHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    pub(crate) async fn wait_ready(&self) -> Result<()> {
        let mut ready = self.shared.ready.subscribe();
        time::timeout(self.startup_timeout, async {
            loop {
                if *ready.borrow() > 0 {
                    return Ok(());
                }
                ready.changed().await.context("VPN host pool stopped")?;
            }
        })
        .await
        .context("no VPN host became ready before startup timeout")?
    }

    pub(crate) async fn shutdown(mut self) {
        self.stop.send_replace(true);
        while let Some(result) = self.workers.join_next().await {
            if let Err(error) = result {
                tracing::error!(%error, "VPN host task stopped unexpectedly");
            }
        }
        tracing::info!("VPN host pool stopped");
    }
}
