use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ovpn_netstack::Stack;
use ovpn_socks5::{DestinationHost, RouteLease, RouteProvider};
use tokio::sync::watch;
use tokio::time;

use super::probe::LatencyScore;

const MAX_STICKY_GROUPS: usize = 100_000;
const STICKY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const STICKY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const LOAD_SCORE_SCALE: u128 = 8;
const LATENCY_HISTORY_WEIGHT: u32 = 3;
const LATENCY_SAMPLE_WEIGHT: u32 = 1;

#[derive(Clone)]
pub(crate) struct RouterHandle {
    pub(super) shared: Arc<Shared>,
}

pub(crate) struct HostLease {
    stack: Stack,
    _reservation: HostReservation,
    _pool: PoolReservation,
    shared: Arc<Shared>,
    sticky_key: StickyKey,
    sticky_generation: u64,
}

struct HostUsage {
    state: watch::Sender<UsageState>,
}

#[derive(Clone, Copy)]
struct UsageState {
    active: usize,
}

struct HostReservation {
    usage: Arc<HostUsage>,
    host_id: usize,
}

struct PoolReservation {
    shared: Arc<Shared>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostPhase {
    Dormant,
    Connecting,
    Ready,
    Backoff,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostActivation {
    Dormant,
    Active(u64),
}

pub(super) struct Host {
    endpoint: SocketAddr,
    phase: HostPhase,
    stack: Option<Stack>,
    usage: Arc<HostUsage>,
    enabled: watch::Sender<HostActivation>,
    selected: bool,
    unhealthy: bool,
    latency_score: Option<Duration>,
    score_measured_at: Option<Instant>,
    generation: u64,
}

#[derive(Clone, Copy, Default)]
struct PoolUsage {
    active: usize,
    idle_since: Option<Instant>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
struct StickyKey {
    source: IpAddr,
    destination: StickyDestination,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
enum StickyDestination {
    Ip(IpAddr),
    Domain(String),
}

struct StickyEntry {
    host_id: usize,
    active: usize,
    idle_since: Option<Instant>,
    generation: u64,
}

struct RoutingState {
    hosts: Vec<Host>,
    sticky: HashMap<StickyKey, StickyEntry>,
    next_choice: usize,
    next_sticky_generation: u64,
    pool_usage: PoolUsage,
    pool_epoch: Option<u64>,
    next_pool_epoch: u64,
}

pub(super) struct Shared {
    state: Mutex<RoutingState>,
    ready: watch::Sender<usize>,
    pool_updates: watch::Sender<PoolUsage>,
    acquire_timeout: Duration,
    max_active_vpn_hosts: usize,
}

impl Host {
    pub(super) fn new(endpoint: SocketAddr, selected: bool, score: Option<LatencyScore>) -> Self {
        let (enabled, _) = watch::channel(HostActivation::Dormant);
        Self {
            endpoint,
            phase: HostPhase::Dormant,
            stack: None,
            usage: HostUsage::new(),
            enabled,
            selected,
            unhealthy: false,
            latency_score: score.as_ref().map(|score| score.median),
            score_measured_at: score.map(|score| score.measured_at),
            generation: 0,
        }
    }

    pub(super) fn activation(&self) -> watch::Receiver<HostActivation> {
        self.enabled.subscribe()
    }
}

impl HostUsage {
    fn new() -> Arc<Self> {
        let (state, _) = watch::channel(UsageState { active: 0 });
        Arc::new(Self { state })
    }

    fn snapshot(&self) -> UsageState {
        *self.state.borrow()
    }

    fn reserve(self: &Arc<Self>, host_id: usize) -> Option<HostReservation> {
        let mut reserved = false;
        self.state.send_modify(|usage| {
            if let Some(active) = usage.active.checked_add(1) {
                usage.active = active;
                reserved = true;
            } else {
                tracing::error!(host_id, "VPN host reservation count overflow");
            }
        });
        reserved.then(|| HostReservation {
            usage: Arc::clone(self),
            host_id,
        })
    }

    fn release(&self, host_id: usize) {
        self.state.send_modify(|usage| {
            if usage.active == 0 {
                tracing::error!(host_id, "VPN host reservation count underflow");
            } else {
                usage.active -= 1;
            }
        });
    }
}

impl RoutingState {
    fn new(hosts: Vec<Host>) -> Self {
        Self {
            hosts,
            sticky: HashMap::new(),
            next_choice: 0,
            next_sticky_generation: 0,
            pool_usage: PoolUsage::default(),
            pool_epoch: None,
            next_pool_epoch: 0,
        }
    }
}

impl Shared {
    pub(super) fn new(
        hosts: Vec<Host>,
        acquire_timeout: Duration,
        max_active_vpn_hosts: usize,
    ) -> Arc<Self> {
        let (ready, _) = watch::channel(0);
        let (pool_updates, _) = watch::channel(PoolUsage::default());
        Arc::new(Self {
            state: Mutex::new(RoutingState::new(hosts)),
            ready,
            pool_updates,
            acquire_timeout,
            max_active_vpn_hosts,
        })
    }

    fn reserve_pool(self: &Arc<Self>) -> Option<PoolReservation> {
        let mut state = self.state.lock().ok()?;
        state.pool_usage.active = state.pool_usage.active.checked_add(1)?;
        state.pool_usage.idle_since = None;
        if state.pool_epoch.is_none() {
            state.next_pool_epoch = state.next_pool_epoch.wrapping_add(1).max(1);
            let epoch = state.next_pool_epoch;
            state.pool_epoch = Some(epoch);
            let mut ranked: Vec<_> = state
                .hosts
                .iter()
                .enumerate()
                .filter_map(|(id, host)| host.latency_score.map(|score| (id, score)))
                .collect();
            ranked.sort_unstable_by_key(|&(id, score)| (score, id));
            let selected: Vec<_> = ranked
                .iter()
                .take(self.max_active_vpn_hosts)
                .map(|&(id, _)| id)
                .collect();
            for (id, host) in state.hosts.iter_mut().enumerate() {
                host.unhealthy = false;
                host.selected = selected.contains(&id);
                if host.selected {
                    host.enabled.send_replace(HostActivation::Active(epoch));
                    tracing::debug!(host_id = id, epoch, "waking selected VPN host");
                }
            }
            tracing::info!(
                epoch,
                selected = state.hosts.iter().filter(|host| host.selected).count(),
                max_active = self.max_active_vpn_hosts,
                "VPN pool waking"
            );
        }
        self.pool_updates.send_replace(state.pool_usage);
        Some(PoolReservation {
            shared: Arc::clone(self),
        })
    }

    fn release_pool(&self) {
        let Ok(mut state) = self.state.lock() else {
            tracing::error!("VPN routing state lock poisoned while releasing pool lease");
            return;
        };
        if state.pool_usage.active == 0 {
            tracing::error!("VPN pool reservation count underflow");
            return;
        }
        state.pool_usage.active -= 1;
        if state.pool_usage.active == 0 {
            state.pool_usage.idle_since = Some(Instant::now());
            tracing::info!(?POOL_IDLE_TIMEOUT, "VPN pool idle timer started");
        }
        self.pool_updates.send_replace(state.pool_usage);
    }

    fn park_pool(&self) {
        let Ok(mut state) = self.state.lock() else {
            tracing::error!("VPN routing state lock poisoned during pool idle shutdown");
            return;
        };
        if state.pool_usage.active != 0
            || !state
                .pool_usage
                .idle_since
                .is_some_and(|since| since.elapsed() >= POOL_IDLE_TIMEOUT)
        {
            return;
        }
        for host in &mut state.hosts {
            host.enabled.send_replace(HostActivation::Dormant);
            host.stack = None;
            host.phase = HostPhase::Dormant;
        }
        state.pool_epoch = None;
        state.sticky.clear();
        state.pool_usage.idle_since = None;
        self.notify_ready(&state);
        self.pool_updates.send_replace(state.pool_usage);
        tracing::info!("VPN pool idle timeout reached; closing all sessions");
    }

    fn sweep_sticky(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let before = state.sticky.len();
        state.sticky.retain(|_, entry| !sticky_expired(entry));
        let removed = before - state.sticky.len();
        if removed > 0 {
            tracing::debug!(
                removed,
                remaining = state.sticky.len(),
                "expired idle sticky groups"
            );
        }
    }

    pub(super) fn phase(&self, id: usize, phase: HostPhase) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.hosts[id].phase = phase;
        tracing::debug!(host_id = id, endpoint = %state.hosts[id].endpoint, ?phase, "VPN host state changed");
        self.notify_ready(&state);
    }

    pub(super) fn ready(
        &self,
        id: usize,
        endpoint: SocketAddr,
        stack: &Stack,
        elapsed: Duration,
        score: LatencyScore,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let host = &mut state.hosts[id];
        host.endpoint = endpoint;
        host.phase = HostPhase::Ready;
        host.generation = host.generation.wrapping_add(1);
        host.stack = Some(stack.clone());
        host.latency_score = Some(score.median);
        host.score_measured_at = Some(score.measured_at);
        host.unhealthy = false;
        let generation = host.generation;
        self.notify_ready(&state);
        tracing::info!(host_id = id, %endpoint, stack_id = stack.id(), ipv6 = stack.supports_ipv6(), generation, ?elapsed, latency_score = ?score.median, "VPN host ready after fresh latency probe");
    }

    pub(super) fn record_probe(
        &self,
        id: usize,
        stack_id: u64,
        result: anyhow::Result<LatencyScore>,
        elapsed: Duration,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let host = &mut state.hosts[id];
        if host.stack.as_ref().map(Stack::id) != Some(stack_id) {
            tracing::debug!(
                host_id = id,
                stack_id,
                "discarded latency probe result for an old tunnel"
            );
            return;
        }
        match result {
            Ok(score) => {
                let smoothed = host.latency_score.map_or(score.median, |previous| {
                    previous
                        .saturating_mul(LATENCY_HISTORY_WEIGHT)
                        .saturating_add(score.median.saturating_mul(LATENCY_SAMPLE_WEIGHT))
                        / (LATENCY_HISTORY_WEIGHT + LATENCY_SAMPLE_WEIGHT)
                });
                host.latency_score = Some(smoothed);
                host.score_measured_at = Some(score.measured_at);
                tracing::info!(host_id = id, stack_id, endpoint = %host.endpoint, sample_median = ?score.median, latency_score = ?smoothed, score_elapsed = ?score.elapsed, successful_samples = score.successful_samples, "VPN latency score measured");
            }
            Err(error) => {
                tracing::warn!(host_id = id, stack_id, endpoint = %host.endpoint, score_elapsed = ?elapsed, %error, "VPN latency score unavailable")
            }
        }
        self.notify_ready(&state);
    }

    pub(super) fn parked(&self, id: usize) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.hosts[id].stack = None;
        state.hosts[id].phase = HostPhase::Dormant;
        self.notify_ready(&state);
        tracing::debug!(host_id = id, "VPN host parked");
    }

    pub(super) fn down(&self, id: usize, shutdown: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let host = &mut state.hosts[id];
        let was_ready = host.stack.take().is_some();
        host.phase = if shutdown {
            HostPhase::Stopped
        } else {
            HostPhase::Backoff
        };
        host.unhealthy = true;
        let endpoint = host.endpoint;
        let before = state.sticky.len();
        state.sticky.retain(|_, entry| entry.host_id != id);
        let cleared = before - state.sticky.len();
        if !shutdown && state.pool_usage.active > 0 && state.hosts[id].selected {
            let replacement = state
                .hosts
                .iter()
                .enumerate()
                .filter(|(_, host)| {
                    !host.selected
                        && host.latency_score.is_some()
                        && host.phase == HostPhase::Dormant
                })
                .min_by_key(|(_, host)| (host.unhealthy, host.latency_score))
                .map(|(id, _)| id);
            if let Some(next) = replacement {
                state.hosts[id].selected = false;
                state.hosts[id]
                    .enabled
                    .send_replace(HostActivation::Dormant);
                state.hosts[next].selected = true;
                if let Some(epoch) = state.pool_epoch {
                    state.hosts[next]
                        .enabled
                        .send_replace(HostActivation::Active(epoch));
                }
                tracing::warn!(
                    failed_host_id = id,
                    replacement_host_id = next,
                    "waking probed standby VPN host"
                );
            }
        }
        self.notify_ready(&state);
        if was_ready || cleared > 0 {
            tracing::warn!(host_id = id, %endpoint, cleared_groups = cleared, shutdown, "VPN host unavailable; sticky assignments cleared");
        }
    }

    fn notify_ready(&self, state: &RoutingState) {
        self.ready.send_replace(
            state
                .hosts
                .iter()
                .filter(|host| host.stack.is_some())
                .count(),
        );
    }

    fn release_sticky(&self, key: &StickyKey, generation: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(entry) = state.sticky.get_mut(key) {
            if entry.generation != generation {
                return;
            }
            if entry.active == 0 {
                tracing::error!("sticky group reservation count underflow");
                return;
            }
            entry.active -= 1;
            if entry.active == 0 {
                entry.idle_since = Some(Instant::now());
            }
        }
    }
}

impl RouteLease for HostLease {
    fn stack(&self) -> &Stack {
        &self.stack
    }
}

impl Drop for HostLease {
    fn drop(&mut self) {
        self.shared
            .release_sticky(&self.sticky_key, self.sticky_generation);
    }
}

impl Drop for HostReservation {
    fn drop(&mut self) {
        self.usage.release(self.host_id);
    }
}

impl Drop for PoolReservation {
    fn drop(&mut self) {
        self.shared.release_pool();
    }
}

impl RouteProvider for RouterHandle {
    type Lease = HostLease;

    fn select(
        &self,
        source: IpAddr,
        destination: DestinationHost,
    ) -> impl Future<Output = Option<Self::Lease>> + Send {
        async move {
            let key = sticky_key(source, &destination)?;
            let deadline = Instant::now() + self.shared.acquire_timeout;
            let mut updates = self.shared.ready.subscribe();
            let pool = self.shared.reserve_pool()?;
            loop {
                let choice = {
                    let Ok(mut state) = self.shared.state.lock() else {
                        tracing::error!("VPN routing state lock poisoned; rejecting SOCKS request");
                        return None;
                    };
                    if state.sticky.get(&key).is_some_and(sticky_expired) {
                        state.sticky.remove(&key);
                    }
                    let sticky_id = state.sticky.get(&key).map(|entry| entry.host_id);
                    if sticky_id.is_some_and(|id| !host_eligible(&state.hosts[id], &destination)) {
                        state.sticky.remove(&key);
                    }
                    if !state.sticky.contains_key(&key) && state.sticky.len() >= MAX_STICKY_GROUPS {
                        tracing::warn!(
                            limit = MAX_STICKY_GROUPS,
                            "sticky routing table full; rejecting SOCKS request"
                        );
                        return None;
                    }
                    let id = state
                        .sticky
                        .get(&key)
                        .map(|entry| entry.host_id)
                        .or_else(|| choose_host(&mut state, &destination));
                    id.and_then(|id| {
                        let host = &state.hosts[id];
                        let stack = host.stack.clone()?;
                        let reservation = host.usage.reserve(id)?;
                        let generation = if let Some(entry) = state.sticky.get_mut(&key) {
                            entry.active = entry.active.checked_add(1)?;
                            entry.idle_since = None;
                            entry.generation
                        } else {
                            state.next_sticky_generation = state.next_sticky_generation.wrapping_add(1);
                            let generation = state.next_sticky_generation;
                            state.sticky.insert(key.clone(), StickyEntry { host_id: id, active: 1, idle_since: None, generation });
                            tracing::info!(source = %source, destination = ?key.destination, host_id = id, endpoint = %state.hosts[id].endpoint, latency_score = ?state.hosts[id].latency_score, score_age = ?state.hosts[id].score_measured_at.map(|at| at.elapsed()), active = state.hosts[id].usage.snapshot().active, "assigned destination group to VPN host");
                            generation
                        };
                        Some((stack, reservation, generation))
                    })
                };
                if let Some((stack, reservation, generation)) = choice {
                    return Some(HostLease {
                        stack,
                        _reservation: reservation,
                        _pool: pool,
                        shared: Arc::clone(&self.shared),
                        sticky_key: key,
                        sticky_generation: generation,
                    });
                }
                if !wait_for_update(&mut updates, deadline).await {
                    tracing::warn!(source = %source, ?destination, "no ready VPN host before request deadline");
                    return None;
                }
            }
        }
    }
}

pub(super) async fn manage_pool_idle(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut usage = shared.pool_updates.subscribe();
    let mut sweep = time::interval(STICKY_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        let deadline = usage
            .borrow()
            .idle_since
            .map(|since| since + POOL_IDLE_TIMEOUT);
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() { break; },
            changed = usage.changed() => if changed.is_err() { break; },
            _ = sweep.tick() => shared.sweep_sticky(),
            _ = wait_until(deadline) => shared.park_pool(),
        }
    }
}

async fn wait_until(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        time::sleep_until(time::Instant::from_std(deadline)).await;
    } else {
        std::future::pending().await
    }
}

async fn wait_for_update(updates: &mut watch::Receiver<usize>, deadline: Instant) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    !remaining.is_zero()
        && matches!(
            time::timeout(remaining, updates.changed()).await,
            Ok(Ok(()))
        )
}

fn sticky_expired(entry: &StickyEntry) -> bool {
    entry.active == 0
        && entry
            .idle_since
            .is_some_and(|since| since.elapsed() >= STICKY_IDLE_TIMEOUT)
}

fn host_eligible(host: &Host, destination: &DestinationHost) -> bool {
    host.selected
        && host.phase == HostPhase::Ready
        && host.latency_score.is_some()
        && host
            .stack
            .as_ref()
            .is_some_and(|stack| stack.is_ready() && destination_supported(stack, destination))
}

fn choose_host(state: &mut RoutingState, destination: &DestinationHost) -> Option<usize> {
    let mut eligible: Vec<_> = state
        .hosts
        .iter()
        .enumerate()
        .filter_map(|(id, host)| host_eligible(host, destination).then_some(id))
        .collect();
    if matches!(destination, DestinationHost::Domain(_))
        && eligible.iter().any(|&id| {
            state.hosts[id]
                .stack
                .as_ref()
                .is_some_and(Stack::supports_ipv6)
        })
    {
        eligible.retain(|&id| {
            state.hosts[id]
                .stack
                .as_ref()
                .is_some_and(Stack::supports_ipv6)
        });
    }
    let host_count = state.hosts.len();
    let start = state.next_choice % host_count;
    state.next_choice = state.next_choice.wrapping_add(1);
    eligible.into_iter().min_by_key(|&id| {
        let host = &state.hosts[id];
        let latency = host.latency_score.unwrap_or_default().as_nanos();
        let load = host.usage.snapshot().active as u128;
        (
            latency.saturating_mul(LOAD_SCORE_SCALE.saturating_add(load)),
            (id + host_count - start) % host_count,
        )
    })
}

fn sticky_key(source: IpAddr, destination: &DestinationHost) -> Option<StickyKey> {
    let destination = match destination {
        DestinationHost::Ipv4(address) => StickyDestination::Ip(IpAddr::V4(*address)),
        DestinationHost::Ipv6(address) => StickyDestination::Ip(IpAddr::V6(*address)),
        DestinationHost::Domain(name) => {
            let normalized = name.trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                return None;
            }
            StickyDestination::Domain(
                psl::domain_str(&normalized)
                    .unwrap_or(&normalized)
                    .to_owned(),
            )
        }
    };
    Some(StickyKey {
        source,
        destination,
    })
}

fn destination_supported(stack: &Stack, destination: &DestinationHost) -> bool {
    match destination {
        DestinationHost::Ipv6(address) => stack.can_route_ipv6(*address),
        DestinationHost::Ipv4(_) | DestinationHost::Domain(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains_share_a_sticky_key_per_source() {
        let source = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let key = sticky_key(source, &DestinationHost::Domain("ABC.COM".into()));
        assert_eq!(
            key,
            sticky_key(source, &DestinationHost::Domain("xyz.abc.com".into()))
        );
        assert_ne!(
            key,
            sticky_key(source, &DestinationHost::Domain("other.com".into()))
        );
        assert_ne!(
            key,
            sticky_key(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                &DestinationHost::Domain("abc.com".into())
            )
        );
    }
}
