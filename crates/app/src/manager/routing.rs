use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ovpn_netstack::Stack;
use ovpn_socks5::{DestinationHost, RouteLease, RouteProvider};
use ovpn_ui::{
    DashboardSnapshot, GroupError, GroupPage, GroupSnapshot, HostPhase as UiHostPhase,
    HostSnapshot, PoolPhase, PoolSnapshot, ProfileSummary,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time;

use super::probe::LatencyScore;
use super::telemetry::HostTraffic;

const MAX_STICKY_GROUPS: usize = 100_000;
const STICKY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const STICKY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const ROUTING_COMMAND_QUEUE: usize = 2048;
const LOAD_SCORE_SCALE: u128 = 8;
const LATENCY_HISTORY_WEIGHT: u32 = 3;
const LATENCY_SAMPLE_WEIGHT: u32 = 1;

#[derive(Clone)]
pub(crate) struct RouterHandle {
    pub(super) shared: Arc<Shared>,
    pub(super) profile_summary: Arc<ProfileSummary>,
}

pub(crate) struct HostLease {
    stack: Stack,
    _pool: PoolReservation,
}

struct PoolReservation {
    releases: mpsc::UnboundedSender<Release>,
    token: u64,
    sticky: Option<(StickyKey, u64, usize)>,
}

struct StickyReservation {
    releases: mpsc::UnboundedSender<Release>,
    sticky: Option<(StickyKey, u64, usize)>,
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
    active: usize,
    traffic: Arc<HostTraffic>,
    enabled: watch::Sender<HostActivation>,
    selected: bool,
    unhealthy: bool,
    latency_score: Option<Duration>,
    score_measured_at: Option<Instant>,
    generation: u64,
}

#[derive(Default)]
struct PoolUsage {
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
    groups_by_host: Vec<BTreeMap<(String, String), StickyKey>>,
    pool_tokens: HashSet<u64>,
    next_pool_token: u64,
    next_choice: usize,
    next_sticky_generation: u64,
    pool_usage: PoolUsage,
    pool_epoch: Option<u64>,
    next_pool_epoch: u64,
}

pub(super) struct Shared {
    commands: mpsc::Sender<RoutingCommand>,
    ready: watch::Sender<usize>,
    acquire_timeout: Duration,
    max_active_vpn_hosts: usize,
}

struct RoutingActor {
    state: RoutingState,
    ready: watch::Sender<usize>,
    releases: mpsc::UnboundedSender<Release>,
    max_active_vpn_hosts: usize,
}

enum RoutingCommand {
    Begin(oneshot::Sender<Option<PoolReservation>>),
    Select {
        token: u64,
        key: StickyKey,
        destination: DestinationHost,
        reply: oneshot::Sender<SelectReply>,
    },
    Update(RoutingUpdate, oneshot::Sender<()>),
    Snapshot(oneshot::Sender<DashboardSnapshot>),
    GroupPage(usize, usize, usize, oneshot::Sender<Option<GroupPage>>),
    StopAccepting(oneshot::Sender<()>),
}

enum RoutingUpdate {
    Phase(usize, HostPhase),
    Ready(usize, SocketAddr, Stack, Duration, LatencyScore),
    Probe(usize, u64, anyhow::Result<LatencyScore>, Duration),
    Parked(usize),
    Down(usize, bool),
}

enum Release {
    Pool {
        token: u64,
        sticky: Option<(StickyKey, u64, usize)>,
    },
    Sticky(StickyKey, u64, usize),
}

struct SelectedRoute {
    stack: Stack,
    reservation: StickyReservation,
}

type SelectReply = Result<Option<SelectedRoute>, ()>;

impl Host {
    pub(super) fn new(endpoint: SocketAddr, selected: bool, score: Option<LatencyScore>) -> Self {
        let (enabled, _) = watch::channel(HostActivation::Dormant);
        Self {
            endpoint,
            phase: HostPhase::Dormant,
            stack: None,
            active: 0,
            traffic: Arc::new(HostTraffic::default()),
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

    pub(super) fn traffic(&self) -> Arc<HostTraffic> {
        Arc::clone(&self.traffic)
    }
}

impl RoutingState {
    fn new(hosts: Vec<Host>) -> Self {
        let groups_by_host = (0..hosts.len()).map(|_| BTreeMap::new()).collect();
        Self {
            hosts,
            sticky: HashMap::new(),
            groups_by_host,
            pool_tokens: HashSet::new(),
            next_pool_token: 0,
            next_choice: 0,
            next_sticky_generation: 0,
            pool_usage: PoolUsage::default(),
            pool_epoch: None,
            next_pool_epoch: 0,
        }
    }

    fn remove_sticky(&mut self, key: &StickyKey) {
        if let Some(entry) = self.sticky.remove(key) {
            self.groups_by_host[entry.host_id].remove(&group_sort_key(key));
        }
    }

    fn clear_host(&mut self, host_id: usize) -> usize {
        let groups = std::mem::take(&mut self.groups_by_host[host_id]);
        let count = groups.len();
        for (_, key) in groups {
            self.sticky.remove(&key);
        }
        count
    }

    fn clear_sticky(&mut self) {
        self.sticky.clear();
        for groups in &mut self.groups_by_host {
            groups.clear();
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
        let (commands, command_rx) = mpsc::channel(ROUTING_COMMAND_QUEUE);
        let (releases, release_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Self {
            commands,
            ready: ready.clone(),
            acquire_timeout,
            max_active_vpn_hosts,
        });
        tokio::spawn(
            RoutingActor {
                state: RoutingState::new(hosts),
                ready,
                releases: releases.clone(),
                max_active_vpn_hosts,
            }
            .run(command_rx, release_rx),
        );
        shared
    }

    async fn command(&self, command: RoutingCommand) -> bool {
        self.commands.send(command).await.is_ok()
    }

    async fn update(&self, update: RoutingUpdate) {
        let (reply, received) = oneshot::channel();
        if !self.command(RoutingCommand::Update(update, reply)).await || received.await.is_err() {
            tracing::error!("VPN routing actor unavailable during host update");
        }
    }

    pub(super) async fn phase(&self, id: usize, phase: HostPhase) {
        self.update(RoutingUpdate::Phase(id, phase)).await;
    }

    pub(super) async fn ready(
        &self,
        id: usize,
        endpoint: SocketAddr,
        stack: &Stack,
        elapsed: Duration,
        score: LatencyScore,
    ) {
        self.update(RoutingUpdate::Ready(
            id,
            endpoint,
            stack.clone(),
            elapsed,
            score,
        ))
        .await;
    }

    pub(super) async fn record_probe(
        &self,
        id: usize,
        stack_id: u64,
        result: anyhow::Result<LatencyScore>,
        elapsed: Duration,
    ) {
        self.update(RoutingUpdate::Probe(id, stack_id, result, elapsed))
            .await;
    }

    pub(super) async fn parked(&self, id: usize) {
        self.update(RoutingUpdate::Parked(id)).await;
    }

    pub(super) async fn down(&self, id: usize, shutdown: bool) {
        self.update(RoutingUpdate::Down(id, shutdown)).await;
    }

    pub(super) async fn stop_accepting(&self) {
        let (reply, received) = oneshot::channel();
        if self.command(RoutingCommand::StopAccepting(reply)).await {
            let _ = received.await;
        }
    }
}

impl RoutingActor {
    async fn run(
        mut self,
        mut commands: mpsc::Receiver<RoutingCommand>,
        mut releases: mpsc::UnboundedReceiver<Release>,
    ) {
        let mut accepting = true;
        let mut sweep = time::interval(STICKY_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            if commands.is_closed()
                && commands.is_empty()
                && self.state.pool_tokens.is_empty()
                && releases.is_empty()
            {
                break;
            }
            let deadline = self
                .state
                .pool_usage
                .idle_since
                .map(|since| since + POOL_IDLE_TIMEOUT);
            tokio::select! {
                Some(release) = releases.recv() => self.release(release),
                Some(command) = commands.recv() => match command {
                    RoutingCommand::Begin(reply) => {
                        let reservation = accepting.then(|| self.begin()).flatten().map(|token| {
                            PoolReservation {
                                releases: self.releases.clone(),
                                token,
                                sticky: None,
                            }
                        });
                        let _ = reply.send(reservation);
                    }
                    RoutingCommand::Select { token, key, destination, reply } => {
                        let choice = if accepting {
                            self.select(token, &key, &destination)
                        } else {
                            Err(())
                        };
                        let _ = reply.send(choice);
                    }
                    RoutingCommand::Update(update, reply) => {
                        self.update(update);
                        let _ = reply.send(());
                    }
                    RoutingCommand::Snapshot(reply) => {
                        let _ = reply.send(self.snapshot());
                    }
                    RoutingCommand::GroupPage(host_id, offset, limit, reply) => {
                        let _ = reply.send(self.group_page(host_id, offset, limit));
                    }
                    RoutingCommand::StopAccepting(reply) => {
                        accepting = false;
                        let _ = reply.send(());
                    }
                },
                _ = sweep.tick() => self.sweep_sticky(),
                _ = wait_until(deadline) => self.park_pool(),
                else => break,
            }
        }
    }

    fn begin(&mut self) -> Option<u64> {
        self.state.next_pool_token = self.state.next_pool_token.wrapping_add(1).max(1);
        let token = self.state.next_pool_token;
        if !self.state.pool_tokens.insert(token) {
            return None;
        }
        self.state.pool_usage.idle_since = None;
        if self.state.pool_epoch.is_none() {
            self.state.next_pool_epoch = self.state.next_pool_epoch.wrapping_add(1).max(1);
            let epoch = self.state.next_pool_epoch;
            self.state.pool_epoch = Some(epoch);
            let mut ranked: Vec<_> = self
                .state
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
            for (id, host) in self.state.hosts.iter_mut().enumerate() {
                host.unhealthy = false;
                host.selected = selected.contains(&id);
                if host.selected {
                    host.enabled.send_replace(HostActivation::Active(epoch));
                    tracing::debug!(host_id = id, epoch, "waking selected VPN host");
                }
            }
            tracing::info!(
                epoch,
                selected = self.state.hosts.iter().filter(|host| host.selected).count(),
                max_active = self.max_active_vpn_hosts,
                "VPN pool waking"
            );
        }
        Some(token)
    }

    fn release(&mut self, release: Release) {
        match release {
            Release::Pool { token, sticky } => {
                if let Some((key, generation, host_id)) = sticky {
                    self.release_sticky(&key, generation, host_id);
                }
                self.release_pool(token);
            }
            Release::Sticky(key, generation, host_id) => {
                self.release_sticky(&key, generation, host_id);
            }
        }
    }

    fn release_pool(&mut self, token: u64) {
        if !self.state.pool_tokens.remove(&token) {
            tracing::error!(token, "unknown VPN pool reservation");
            return;
        }
        if self.state.pool_tokens.is_empty() {
            self.state.pool_usage.idle_since = Some(Instant::now());
            tracing::info!(?POOL_IDLE_TIMEOUT, "VPN pool idle timer started");
        }
    }

    fn park_pool(&mut self) {
        let state = &mut self.state;
        if !state.pool_tokens.is_empty()
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
        state.clear_sticky();
        state.pool_usage.idle_since = None;
        self.notify_ready();
        tracing::info!("VPN pool idle timeout reached; closing all sessions");
    }

    fn sweep_sticky(&mut self) {
        let at = Instant::now();
        let expired: Vec<_> = self
            .state
            .sticky
            .iter()
            .filter(|(_, entry)| sticky_expired_at(entry, at))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            self.state.remove_sticky(key);
        }
        if !expired.is_empty() {
            tracing::debug!(
                removed = expired.len(),
                remaining = self.state.sticky.len(),
                "expired idle sticky groups"
            );
        }
    }

    fn update(&mut self, update: RoutingUpdate) {
        match update {
            RoutingUpdate::Phase(id, phase) => {
                let host = &mut self.state.hosts[id];
                host.phase = phase;
                tracing::debug!(host_id = id, endpoint = %host.endpoint, ?phase, "VPN host state changed");
            }
            RoutingUpdate::Ready(id, endpoint, stack, elapsed, score) => {
                let host = &mut self.state.hosts[id];
                host.endpoint = endpoint;
                host.phase = HostPhase::Ready;
                host.generation = host.generation.wrapping_add(1);
                host.stack = Some(stack.clone());
                host.latency_score = Some(score.median);
                host.score_measured_at = Some(score.measured_at);
                host.unhealthy = false;
                tracing::info!(host_id = id, %endpoint, stack_id = stack.id(), ipv6 = stack.supports_ipv6(), generation = host.generation, ?elapsed, latency_score = ?score.median, "VPN host ready after fresh latency probe");
            }
            RoutingUpdate::Probe(id, stack_id, result, elapsed) => {
                let host = &mut self.state.hosts[id];
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
            }
            RoutingUpdate::Parked(id) => {
                self.state.hosts[id].stack = None;
                self.state.hosts[id].phase = HostPhase::Dormant;
                tracing::debug!(host_id = id, "VPN host parked");
            }
            RoutingUpdate::Down(id, shutdown) => self.down(id, shutdown),
        }
        self.notify_ready();
    }

    fn down(&mut self, id: usize, shutdown: bool) {
        let state = &mut self.state;
        let host = &mut state.hosts[id];
        let was_ready = host.stack.take().is_some();
        host.phase = if shutdown {
            HostPhase::Stopped
        } else {
            HostPhase::Backoff
        };
        host.unhealthy = true;
        let endpoint = host.endpoint;
        let cleared = state.clear_host(id);
        if !shutdown && !state.pool_tokens.is_empty() && state.hosts[id].selected {
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
        if was_ready || cleared > 0 {
            tracing::warn!(host_id = id, %endpoint, cleared_groups = cleared, shutdown, "VPN host unavailable; sticky assignments cleared");
        }
    }

    fn notify_ready(&self) {
        self.ready.send_replace(
            self.state
                .hosts
                .iter()
                .filter(|host| host.stack.is_some())
                .count(),
        );
    }

    fn select(
        &mut self,
        token: u64,
        key: &StickyKey,
        destination: &DestinationHost,
    ) -> SelectReply {
        if !self.state.pool_tokens.contains(&token) {
            return Err(());
        }
        let state = &mut self.state;
        if state.sticky.get(key).is_some_and(sticky_expired) {
            state.remove_sticky(key);
        }
        let sticky_id = state.sticky.get(key).map(|entry| entry.host_id);
        if sticky_id.is_some_and(|id| !host_eligible(&state.hosts[id], destination)) {
            state.remove_sticky(key);
        }
        if !state.sticky.contains_key(key) && state.sticky.len() >= MAX_STICKY_GROUPS {
            tracing::warn!(
                limit = MAX_STICKY_GROUPS,
                "sticky routing table full; rejecting SOCKS request"
            );
            return Err(());
        }
        let id = state
            .sticky
            .get(key)
            .map(|entry| entry.host_id)
            .or_else(|| choose_host(state, destination));
        let Some(id) = id else {
            return Ok(None);
        };
        let Some(stack) = state.hosts[id].stack.clone() else {
            return Ok(None);
        };
        let Some(next_active) = state.hosts[id].active.checked_add(1) else {
            return Err(());
        };
        let generation = if let Some(entry) = state.sticky.get_mut(key) {
            entry.active = entry.active.checked_add(1).ok_or(())?;
            entry.idle_since = None;
            entry.generation
        } else {
            state.next_sticky_generation = state.next_sticky_generation.wrapping_add(1);
            let generation = state.next_sticky_generation;
            state.sticky.insert(
                key.clone(),
                StickyEntry {
                    host_id: id,
                    active: 1,
                    idle_since: None,
                    generation,
                },
            );
            state.groups_by_host[id].insert(group_sort_key(key), key.clone());
            tracing::info!(source = %key.source, destination = ?key.destination, host_id = id, endpoint = %state.hosts[id].endpoint, latency_score = ?state.hosts[id].latency_score, score_age = ?state.hosts[id].score_measured_at.map(|at| at.elapsed()), active = next_active, "assigned destination group to VPN host");
            generation
        };
        state.hosts[id].active = next_active;
        Ok(Some(SelectedRoute {
            stack,
            reservation: StickyReservation {
                releases: self.releases.clone(),
                sticky: Some((key.clone(), generation, id)),
            },
        }))
    }

    fn release_sticky(&mut self, key: &StickyKey, generation: u64, host_id: usize) {
        let host = &mut self.state.hosts[host_id];
        if host.active == 0 {
            tracing::error!(host_id, "VPN host reservation count underflow");
        } else {
            host.active -= 1;
        }
        if let Some(entry) = self.state.sticky.get_mut(key) {
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

    fn snapshot(&self) -> DashboardSnapshot {
        let state = &self.state;
        let sampled_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        let mut tx_bytes = 0_u64;
        let mut rx_bytes = 0_u64;
        let mut ready_hosts = 0;
        let mut selected_hosts = 0;
        let mut active_routes = 0_usize;
        let hosts = state
            .hosts
            .iter()
            .enumerate()
            .map(|(id, host)| {
                let (tx, rx) = host.traffic.snapshot();
                tx_bytes = tx_bytes.saturating_add(tx);
                rx_bytes = rx_bytes.saturating_add(rx);
                ready_hosts += usize::from(
                    host.phase == HostPhase::Ready
                        && host.stack.as_ref().is_some_and(Stack::is_ready),
                );
                selected_hosts += usize::from(host.selected);
                active_routes = active_routes.saturating_add(host.active);
                HostSnapshot {
                    id,
                    endpoint: host.endpoint.to_string(),
                    phase: match host.phase {
                        HostPhase::Dormant => UiHostPhase::Dormant,
                        HostPhase::Connecting => UiHostPhase::Connecting,
                        HostPhase::Ready => UiHostPhase::Ready,
                        HostPhase::Backoff => UiHostPhase::Backoff,
                        HostPhase::Stopped => UiHostPhase::Stopped,
                    },
                    selected: host.selected,
                    active_routes: host.active,
                    sticky_groups: state.groups_by_host[id].len(),
                    latency_ms: host.latency_score.map(|score| score.as_secs_f64() * 1000.0),
                    score_age_seconds: host.score_measured_at.map(|at| at.elapsed().as_secs()),
                    ipv6: host.stack.as_ref().is_some_and(Stack::supports_ipv6),
                    tx_bytes: tx,
                    rx_bytes: rx,
                }
            })
            .collect();
        let phase = if state.pool_epoch.is_none() {
            PoolPhase::Dormant
        } else if state.pool_tokens.is_empty() {
            PoolPhase::Idle
        } else if ready_hosts == 0 {
            PoolPhase::Waking
        } else if ready_hosts < selected_hosts {
            PoolPhase::Degraded
        } else {
            PoolPhase::Ready
        };
        DashboardSnapshot {
            version: 1,
            sampled_at_ms,
            message: None,
            pool: PoolSnapshot {
                phase,
                candidate_hosts: state.hosts.len(),
                selected_hosts,
                ready_hosts,
                max_active_hosts: self.max_active_vpn_hosts,
                active_routes,
                sticky_groups: state.sticky.len(),
                idle_remaining_seconds: state
                    .pool_usage
                    .idle_since
                    .map(|since| POOL_IDLE_TIMEOUT.saturating_sub(since.elapsed()).as_secs()),
                tx_bytes,
                rx_bytes,
            },
            hosts,
        }
    }

    fn group_page(&self, host_id: usize, offset: usize, limit: usize) -> Option<GroupPage> {
        let groups = self.state.groups_by_host.get(host_id)?;
        let page = groups
            .iter()
            .skip(offset)
            .take(limit)
            .filter_map(|(_, key)| {
                let entry = self.state.sticky.get(key)?;
                Some(GroupSnapshot {
                    source: key.source.to_string(),
                    destination: destination_label(&key.destination),
                    active_connections: entry.active,
                    idle_remaining_seconds: entry.idle_since.map(|since| {
                        STICKY_IDLE_TIMEOUT
                            .saturating_sub(since.elapsed())
                            .as_secs()
                    }),
                })
            })
            .collect();
        Some(GroupPage {
            total: groups.len(),
            offset,
            groups: page,
        })
    }
}

impl Drop for PoolReservation {
    fn drop(&mut self) {
        if self
            .releases
            .send(Release::Pool {
                token: self.token,
                sticky: self.sticky.take(),
            })
            .is_err()
        {
            tracing::error!("VPN routing actor unavailable during lease release");
        }
    }
}

impl Drop for StickyReservation {
    fn drop(&mut self) {
        if let Some((key, generation, host_id)) = self.sticky.take()
            && self
                .releases
                .send(Release::Sticky(key, generation, host_id))
                .is_err()
        {
            tracing::error!("VPN routing actor unavailable during abandoned selection release");
        }
    }
}

impl RouteLease for HostLease {
    fn stack(&self) -> &Stack {
        &self.stack
    }
}

impl RouterHandle {
    pub(super) async fn dashboard_snapshot(&self) -> DashboardSnapshot {
        let (reply, received) = oneshot::channel();
        if self.shared.command(RoutingCommand::Snapshot(reply)).await
            && let Ok(snapshot) = received.await
        {
            return snapshot;
        }
        DashboardSnapshot {
            version: 1,
            sampled_at_ms: 0,
            message: Some("VPN routing state unavailable".into()),
            pool: PoolSnapshot {
                phase: PoolPhase::Unavailable,
                candidate_hosts: 0,
                selected_hosts: 0,
                ready_hosts: 0,
                max_active_hosts: self.shared.max_active_vpn_hosts,
                active_routes: 0,
                sticky_groups: 0,
                idle_remaining_seconds: None,
                tx_bytes: 0,
                rx_bytes: 0,
            },
            hosts: Vec::new(),
        }
    }

    pub(super) async fn dashboard_group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Option<GroupPage>, GroupError> {
        let (reply, received) = oneshot::channel();
        if !self
            .shared
            .command(RoutingCommand::GroupPage(host_id, offset, limit, reply))
            .await
        {
            return Err(GroupError::Unavailable);
        }
        received.await.map_err(|_| GroupError::Unavailable)
    }
}

impl RouteProvider for RouterHandle {
    type Lease = HostLease;

    async fn select(&self, source: IpAddr, destination: DestinationHost) -> Option<Self::Lease> {
        let key = sticky_key(source, &destination)?;
        let deadline = Instant::now() + self.shared.acquire_timeout;
        let deadline_tokio = time::Instant::from_std(deadline);
        let mut updates = self.shared.ready.subscribe();
        let (reply, received) = oneshot::channel();
        let pool = time::timeout_at(deadline_tokio, async {
            if !self.shared.command(RoutingCommand::Begin(reply)).await {
                return None;
            }
            received.await.ok().flatten()
        })
        .await
        .ok()
        .flatten()?;
        let mut pool = pool;
        let token = pool.token;
        loop {
            let (reply, received) = oneshot::channel();
            let choice = time::timeout_at(deadline_tokio, async {
                if !self
                    .shared
                    .command(RoutingCommand::Select {
                        token,
                        key: key.clone(),
                        destination: destination.clone(),
                        reply,
                    })
                    .await
                {
                    return Err(());
                }
                received.await.unwrap_or(Err(()))
            })
            .await
            .ok()?;
            match choice {
                Ok(Some(route)) => {
                    let mut reservation = route.reservation;
                    pool.sticky = reservation.sticky.take();
                    return Some(HostLease {
                        stack: route.stack,
                        _pool: pool,
                    });
                }
                Ok(None) => {}
                Err(()) => return None,
            }
            if !wait_for_update(&mut updates, deadline).await {
                tracing::warn!(source = %source, ?destination, "no ready VPN host before request deadline");
                return None;
            }
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
    sticky_expired_at(entry, Instant::now())
}

fn destination_label(destination: &StickyDestination) -> String {
    match destination {
        StickyDestination::Ip(ip) => ip.to_string(),
        StickyDestination::Domain(domain) => domain.clone(),
    }
}

fn group_sort_key(key: &StickyKey) -> (String, String) {
    (destination_label(&key.destination), key.source.to_string())
}

fn sticky_expired_at(entry: &StickyEntry, at: Instant) -> bool {
    entry.active == 0
        && entry
            .idle_since
            .is_some_and(|since| at.saturating_duration_since(since) >= STICKY_IDLE_TIMEOUT)
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
        let load = host.active as u128;
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
    fn stale_lease_release_keeps_new_assignment() {
        let (ready, _) = watch::channel(0);
        let (releases, _) = mpsc::unbounded_channel();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![Host::new(
                "127.0.0.1:1194".parse().unwrap(),
                true,
                None,
            )]),
            ready,
            releases,
            max_active_vpn_hosts: 1,
        };
        let key = StickyKey {
            source: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            destination: StickyDestination::Domain("example.com".into()),
        };
        actor.state.hosts[0].active = 2;
        actor.state.sticky.insert(
            key.clone(),
            StickyEntry {
                host_id: 0,
                active: 1,
                idle_since: None,
                generation: 2,
            },
        );
        actor.state.groups_by_host[0].insert(group_sort_key(&key), key.clone());
        actor.release_sticky(&key, 1, 0);
        assert_eq!(actor.state.hosts[0].active, 1);
        assert_eq!(actor.state.sticky[&key].active, 1);
        actor.release_sticky(&key, 2, 0);
        assert_eq!(actor.state.hosts[0].active, 0);
        assert_eq!(actor.state.sticky[&key].active, 0);
        assert_eq!(actor.group_page(0, 0, 100).unwrap().total, 1);
    }

    #[tokio::test]
    async fn abandoned_begin_releases_pool_reservation() {
        let shared = Shared::new(
            vec![Host::new("127.0.0.1:1194".parse().unwrap(), true, None)],
            Duration::from_secs(1),
            1,
        );
        let (reply, received) = oneshot::channel();
        drop(received);
        shared
            .commands
            .send(RoutingCommand::Begin(reply))
            .await
            .unwrap();
        let (reply, received) = oneshot::channel();
        shared
            .commands
            .send(RoutingCommand::Snapshot(reply))
            .await
            .unwrap();
        let snapshot = received.await.unwrap();
        assert!(matches!(snapshot.pool.phase, PoolPhase::Idle));
    }

    #[tokio::test]
    async fn delivered_begin_releases_pool_when_receiver_is_dropped() {
        let shared = Shared::new(
            vec![Host::new("127.0.0.1:1194".parse().unwrap(), true, None)],
            Duration::from_secs(1),
            1,
        );
        let (reply, received) = oneshot::channel();
        shared
            .commands
            .send(RoutingCommand::Begin(reply))
            .await
            .unwrap();
        let (barrier, processed) = oneshot::channel();
        shared
            .commands
            .send(RoutingCommand::Snapshot(barrier))
            .await
            .unwrap();
        let _ = processed.await.unwrap();
        drop(received);
        time::timeout(Duration::from_secs(1), async {
            loop {
                let (reply, received) = oneshot::channel();
                shared
                    .commands
                    .send(RoutingCommand::Snapshot(reply))
                    .await
                    .unwrap();
                if matches!(received.await.unwrap().pool.phase, PoolPhase::Idle) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delivered_selection_releases_host_and_sticky_counts_when_receiver_is_dropped() {
        let (ready, _) = watch::channel(0);
        let (releases, mut release_rx) = mpsc::unbounded_channel();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![Host::new(
                "127.0.0.1:1194".parse().unwrap(),
                true,
                None,
            )]),
            ready,
            releases: releases.clone(),
            max_active_vpn_hosts: 1,
        };
        let key = StickyKey {
            source: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            destination: StickyDestination::Domain("example.com".into()),
        };
        actor.state.hosts[0].active = 1;
        actor.state.sticky.insert(
            key.clone(),
            StickyEntry {
                host_id: 0,
                active: 1,
                idle_since: None,
                generation: 1,
            },
        );
        let (reply, received) = oneshot::channel::<SelectReply>();
        reply
            .send(Ok(Some(SelectedRoute {
                stack: Stack::start(),
                reservation: StickyReservation {
                    releases,
                    sticky: Some((key.clone(), 1, 0)),
                },
            })))
            .ok()
            .unwrap();
        drop(received);
        actor.release(release_rx.recv().await.unwrap());
        assert_eq!(actor.state.hosts[0].active, 0);
        assert_eq!(actor.state.sticky[&key].active, 0);
    }

    #[test]
    fn group_page_preserves_display_order() {
        let (ready, _) = watch::channel(0);
        let (releases, _) = mpsc::unbounded_channel();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![Host::new(
                "127.0.0.1:1194".parse().unwrap(),
                true,
                None,
            )]),
            ready,
            releases,
            max_active_vpn_hosts: 1,
        };
        for destination in ["10.0.0.2", "abc.com", "10.0.0.10"] {
            let key = StickyKey {
                source: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                destination: destination
                    .parse()
                    .map(StickyDestination::Ip)
                    .unwrap_or_else(|_| StickyDestination::Domain(destination.into())),
            };
            actor.state.groups_by_host[0].insert(group_sort_key(&key), key.clone());
            actor.state.sticky.insert(
                key,
                StickyEntry {
                    host_id: 0,
                    active: 0,
                    idle_since: None,
                    generation: 1,
                },
            );
        }
        let page = actor.group_page(0, 1, 1).unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.groups.len(), 1);
        assert_eq!(page.groups[0].destination, "10.0.0.2");
    }

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
