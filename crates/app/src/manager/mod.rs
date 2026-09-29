mod discovery;
mod host;
mod probe;
mod routing;

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow, bail};
use ovpn_profile::Profile;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use self::discovery::{HostCandidate, MAX_ENDPOINTS, resolve_candidates};
use self::host::{CONTROL_SETUP_ALLOWANCE, HostWorker, benchmark_host};
use self::probe::LatencyScore;
use self::routing::{Host, Shared};

const MAX_ACTIVE_VPN_HOSTS: usize = MAX_ENDPOINTS;
const DEFAULT_MAX_ACTIVE_VPN_HOSTS: usize = 16;
const INITIAL_PROBE_PARALLELISM: usize = 4;

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
        let mut candidates = resolve_candidates(&profile).await?;
        let max_active_vpn_hosts = max_active_vpn_hosts
            .map(NonZeroUsize::get)
            .unwrap_or(DEFAULT_MAX_ACTIVE_VPN_HOSTS);
        if max_active_vpn_hosts > MAX_ACTIVE_VPN_HOSTS {
            bail!("max_active_vpn_hosts exceeds supported host limit");
        }
        let profile = Arc::new(profile);
        let username: Arc<str> = username.into();
        let password: Arc<str> = password.into();
        let probe_permits = Arc::new(Semaphore::new(INITIAL_PROBE_PARALLELISM));
        let baselines = benchmark_hosts(
            &candidates,
            Arc::clone(&profile),
            Arc::clone(&username),
            Arc::clone(&password),
            dns_override,
            probe_permits,
        )
        .await;
        let mut ranked: Vec<_> = baselines
            .iter()
            .enumerate()
            .filter_map(|(id, baseline)| baseline.as_ref().map(|(_, score)| (id, score.median)))
            .collect();
        ranked.sort_unstable_by_key(|&(id, latency)| (latency, id));
        if ranked.is_empty() {
            bail!("no VPN host passed the startup latency probe");
        }
        let selected: Vec<_> = ranked
            .iter()
            .take(max_active_vpn_hosts)
            .map(|&(id, _)| id)
            .collect();
        for (rank, &(id, latency)) in ranked.iter().enumerate() {
            tracing::info!(
                host_id = id,
                rank = rank + 1,
                ?latency,
                selected = rank < max_active_vpn_hosts,
                "VPN host ranked by startup probe"
            );
        }
        let permits = Arc::new(Semaphore::new(max_active_vpn_hosts));
        for (candidate, baseline) in candidates.iter_mut().zip(&baselines) {
            if let Some((endpoint, _)) = baseline
                && let Some(index) = candidate
                    .endpoints
                    .iter()
                    .position(|candidate_endpoint| candidate_endpoint == endpoint)
            {
                candidate.endpoints.swap(0, index);
            }
        }
        let candidate_count = candidates.len();
        let hosts = candidates
            .iter()
            .zip(baselines)
            .enumerate()
            .map(|(id, (candidate, baseline))| {
                Ok(Host::new(
                    *candidate
                        .endpoints
                        .first()
                        .ok_or_else(|| anyhow!("VPN host has no endpoint"))?,
                    selected.contains(&id),
                    baseline.map(|(_, score)| score),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let enabled: Vec<_> = hosts.iter().map(Host::activation).collect();
        let acquire_timeout = profile
            .handshake_window
            .saturating_add(CONTROL_SETUP_ALLOWANCE);
        let shared = Shared::new(hosts, acquire_timeout, max_active_vpn_hosts);
        let (stop, _) = watch::channel(false);
        let mut workers = JoinSet::new();
        for (id, (candidate, enabled)) in candidates.into_iter().zip(enabled).enumerate() {
            workers.spawn(
                HostWorker {
                    id,
                    candidate,
                    profile: Arc::clone(&profile),
                    username: Arc::clone(&username),
                    password: Arc::clone(&password),
                    dns_override,
                    permits: Arc::clone(&permits),
                    enabled,
                    shared: Arc::clone(&shared),
                    stop: stop.subscribe(),
                }
                .run(),
            );
        }
        {
            let shared = Arc::clone(&shared);
            let stop = stop.subscribe();
            workers.spawn(async move { routing::manage_pool_idle(shared, stop).await });
        }
        tracing::info!(
            candidates = candidate_count,
            healthy = ranked.len(),
            selected = selected.len(),
            max_active = max_active_vpn_hosts,
            initial_probe_parallelism = INITIAL_PROBE_PARALLELISM,
            "VPN host pool initialized; selected hosts connect on demand"
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

async fn benchmark_hosts(
    candidates: &[HostCandidate],
    profile: Arc<Profile>,
    username: Arc<str>,
    password: Arc<str>,
    dns_override: Option<Ipv4Addr>,
    permits: Arc<Semaphore>,
) -> Vec<Option<(SocketAddr, LatencyScore)>> {
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for (id, candidate) in candidates.iter().cloned().enumerate() {
        let profile = Arc::clone(&profile);
        let username = Arc::clone(&username);
        let password = Arc::clone(&password);
        let permits = Arc::clone(&permits);
        tasks.spawn(async move {
            let permit = permits.acquire_owned().await;
            let result = match permit {
                Ok(_permit) => {
                    benchmark_host(id, &candidate, &profile, &username, &password, dns_override)
                        .await
                }
                Err(error) => Err(error.into()),
            };
            (id, result)
        });
    }
    let mut scores: Vec<Option<(SocketAddr, LatencyScore)>> =
        (0..candidates.len()).map(|_| None).collect();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((id, Ok(score))) => scores[id] = Some(score),
            Ok((id, Err(error))) => {
                tracing::warn!(host_id = id, %error, "VPN host baseline unavailable");
            }
            Err(error) => tracing::error!(%error, "VPN host baseline task failed"),
        }
    }
    tracing::info!(hosts = candidates.len(), measured = scores.iter().filter(|score| score.is_some()).count(), elapsed = ?started.elapsed(), parallelism = INITIAL_PROBE_PARALLELISM, "VPN baseline round completed");
    scores
}
