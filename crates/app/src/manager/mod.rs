mod discovery;
mod host;
mod routing;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, bail};
use ovpn_profile::Profile;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use self::discovery::{MAX_ENDPOINTS, resolve_candidates};
use self::host::{CONTROL_SETUP_ALLOWANCE, HostWorker};
use self::routing::{Host, HostPhase, HostUsage, RoutingState, Shared};

const MAX_ACTIVE_VPN_HOSTS: usize = MAX_ENDPOINTS;
const DEFAULT_MAX_ACTIVE_VPN_HOSTS: usize = 16;

pub(crate) use self::routing::RouterHandle;

pub(crate) struct ConnectionManager {
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    workers: JoinSet<()>,
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
                    phase: HostPhase::Dormant,
                    stack: None,
                    usage: HostUsage::new(),
                    generation: 0,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let usages: Vec<_> = hosts.iter().map(|host| Arc::clone(&host.usage)).collect();
        let (ready, _) = watch::channel(0);
        let acquire_timeout = profile
            .handshake_window
            .saturating_add(CONTROL_SETUP_ALLOWANCE);
        let shared = Arc::new(Shared {
            state: Mutex::new(RoutingState {
                hosts,
                sticky: HashMap::new(),
                next_choice: 0,
            }),
            ready,
            acquire_timeout,
        });
        let (stop, _) = watch::channel(false);
        let profile = Arc::new(profile);
        let username: Arc<str> = username.into();
        let password: Arc<str> = password.into();
        let permits = Arc::new(Semaphore::new(max_active_vpn_hosts));
        let mut workers = JoinSet::new();
        for (id, (candidate, usage)) in candidates.into_iter().zip(usages).enumerate() {
            workers.spawn(
                HostWorker {
                    id,
                    candidate,
                    profile: Arc::clone(&profile),
                    username: Arc::clone(&username),
                    password: Arc::clone(&password),
                    dns_override,
                    permits: Arc::clone(&permits),
                    usage,
                    shared: Arc::clone(&shared),
                    stop: stop.subscribe(),
                }
                .run(),
            );
        }
        tracing::info!(
            candidates = workers.len(),
            max_active = max_active_vpn_hosts,
            "VPN host pool initialized; hosts connect on demand"
        );
        Ok(Self {
            shared,
            stop,
            workers,
        })
    }

    pub(crate) fn router(&self) -> RouterHandle {
        RouterHandle {
            shared: Arc::clone(&self.shared),
        }
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
