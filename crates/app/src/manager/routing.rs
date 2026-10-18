use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ovpn_netstack::Stack;
use ovpn_socks5::DestinationHost;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time;

use super::probe::LatencyScore;
use super::telemetry::{
    HostObservation, HostPhase, Observation, POOL_IDLE_TIMEOUT, PoolObservation,
    STICKY_IDLE_TIMEOUT, StickyDestination, StickyKey, Telemetry,
};

const MAX_STICKY_GROUPS: usize = 100_000;
const STICKY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const ROUTING_COMMAND_QUEUE: usize = 2048;
const LOAD_SCORE_SCALE: u128 = 8;
const LATENCY_HISTORY_WEIGHT: u32 = 3;
const LATENCY_SAMPLE_WEIGHT: u32 = 1;

#[derive(Clone)]
pub(crate) struct RouterHandle {
    pub(super) shared: Arc<Shared>,
}

pub(crate) struct HostLease {
    stack: Stack,
    _pool: PoolReservation,
}

struct PoolReservation {
    releases: mpsc::UnboundedSender<Release>,
    token: Option<u64>,
    sticky: Option<(StickyKey, u64, usize)>,
}

struct StickyReservation {
    releases: mpsc::UnboundedSender<Release>,
    sticky: Option<(StickyKey, u64, usize)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostActivation {
    Dormant,
    Active {
        epoch: u64,
        preferred_endpoint: SocketAddr,
    },
}

impl HostActivation {
    pub(super) fn epoch(self) -> Option<u64> {
        match self {
            Self::Dormant => None,
            Self::Active { epoch, .. } => Some(epoch),
        }
    }
}

pub(super) struct Host {
    endpoint: SocketAddr,
    phase: HostPhase,
    stack: Option<Stack>,
    active: usize,
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

struct StickyEntry {
    host_id: usize,
    active: usize,
    idle_since: Option<Instant>,
    generation: u64,
}

struct RoutingState {
    hosts: Vec<Host>,
    sticky: HashMap<StickyKey, StickyEntry>,
    groups_by_host: Vec<HashSet<StickyKey>>,
    pool_tokens: HashSet<u64>,
    next_pool_token: u64,
    next_choice: usize,
    next_sticky_generation: u64,
    pool_usage: PoolUsage,
    pool_epoch: Option<u64>,
    next_pool_epoch: u64,
    telemetry: Telemetry,
}

pub(super) struct Shared {
    commands: mpsc::Sender<RoutingCommand>,
    ready: watch::Sender<usize>,
    acquire_timeout: Duration,
}

/// Owns the routing task independently of any cloned request handles.
pub(super) struct RoutingOwner {
    shared: Arc<Shared>,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl RoutingOwner {
    pub(super) fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    pub(super) async fn wait_for_exit(&mut self) -> anyhow::Result<()> {
        let Some(worker) = self.worker.as_mut() else {
            return std::future::pending().await;
        };
        let result = worker.await;
        self.worker.take();
        result.map_err(anyhow::Error::from)?;
        anyhow::bail!("routing actor stopped unexpectedly")
    }

    pub(super) async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.as_mut() {
            let result = worker.await;
            self.worker.take();
            if let Err(error) = result {
                tracing::error!(%error, "routing actor failed during shutdown");
            }
        }
    }
}

impl Drop for RoutingOwner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
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
    #[cfg(test)]
    Inspect(oneshot::Sender<usize>),
    StopAccepting(oneshot::Sender<()>),
}

enum RoutingUpdate {
    Phase(usize, HostPhase),
    Ready {
        id: usize,
        epoch: u64,
        endpoint: SocketAddr,
        stack: Stack,
        elapsed: Duration,
        score: LatencyScore,
    },
    Probe(usize, u64, anyhow::Result<LatencyScore>, Duration),
    Parked(usize),
    Down(usize, bool),
    Baseline(usize, SocketAddr, LatencyScore),
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

impl RoutingState {
    fn new(hosts: Vec<Host>) -> Self {
        let groups_by_host = (0..hosts.len()).map(|_| HashSet::new()).collect();
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
            telemetry: Telemetry::default(),
        }
    }

    fn remove_sticky(&mut self, key: &StickyKey) {
        if let Some((key, entry)) = self.sticky.remove_entry(key) {
            self.groups_by_host[entry.host_id].remove(&key);
            self.telemetry.emit(|| Observation::AssignmentRemoved(key));
        }
    }

    fn clear_host(&mut self, host_id: usize) -> usize {
        let groups = std::mem::take(&mut self.groups_by_host[host_id]);
        let count = groups.len();
        for key in groups {
            self.sticky.remove(&key);
        }
        self.telemetry
            .emit(|| Observation::HostAssignmentsCleared(host_id));
        count
    }

    fn clear_sticky(&mut self) {
        self.telemetry.emit(|| Observation::AssignmentsCleared);
        self.sticky.clear();
        for groups in &mut self.groups_by_host {
            groups.clear();
        }
    }

    fn observe_host(&self, id: usize) {
        self.telemetry.emit(|| Observation::Host {
            id,
            state: self.host_observation(id),
        });
    }

    fn host_observation(&self, id: usize) -> HostObservation {
        let host = &self.hosts[id];
        HostObservation {
            endpoint: host.endpoint,
            phase: host.phase,
            selected: host.selected,
            active_routes: host.active,
            latency_score: host.latency_score,
            score_measured_at: host.score_measured_at,
            ready: host.phase == HostPhase::Ready
                && host.stack.as_ref().is_some_and(Stack::is_ready),
            ipv6: host.stack.as_ref().is_some_and(Stack::supports_ipv6),
        }
    }

    fn observe_pool(&self) {
        self.telemetry.emit(|| {
            Observation::Pool(PoolObservation {
                awake: self.pool_epoch.is_some(),
                has_requests: !self.pool_tokens.is_empty(),
                idle_since: self.pool_usage.idle_since,
            })
        });
    }

    fn observe_assignment(&self, key: &StickyKey) {
        self.telemetry.emit(|| {
            let entry = &self.sticky[key];
            Observation::Assignment {
                key: key.clone(),
                host_id: entry.host_id,
                active: entry.active,
                idle_since: entry.idle_since,
            }
        });
    }
}

impl RoutingOwner {
    pub(super) fn start(
        hosts: Vec<Host>,
        acquire_timeout: Duration,
        max_active_vpn_hosts: usize,
        telemetry: Telemetry,
    ) -> Self {
        let (ready, _) = watch::channel(0);
        let (commands, command_rx) = mpsc::channel(ROUTING_COMMAND_QUEUE);
        let (releases, release_rx) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let shared = Arc::new(Shared {
            commands,
            ready: ready.clone(),
            acquire_timeout,
        });
        let mut state = RoutingState::new(hosts);
        state.telemetry = telemetry;
        state.telemetry.emit(|| Observation::Initialized {
            hosts: (0..state.hosts.len())
                .map(|id| state.host_observation(id))
                .collect(),
            max_active_hosts: max_active_vpn_hosts,
        });
        let actor = RoutingActor {
            state,
            ready,
            releases,
            max_active_vpn_hosts,
        };
        Self {
            shared,
            stop: Some(stop),
            worker: Some(tokio::spawn(actor.run(command_rx, release_rx, stopped))),
        }
    }
}

impl Shared {
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
        epoch: u64,
        endpoint: SocketAddr,
        stack: &Stack,
        elapsed: Duration,
        score: LatencyScore,
    ) {
        self.update(RoutingUpdate::Ready {
            id,
            epoch,
            endpoint,
            stack: stack.clone(),
            elapsed,
            score,
        })
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

    pub(super) async fn baseline(&self, id: usize, endpoint: SocketAddr, score: LatencyScore) {
        self.update(RoutingUpdate::Baseline(id, endpoint, score))
            .await;
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
        mut stop: oneshot::Receiver<()>,
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
                _ = &mut stop => break,
                Some(release) = releases.recv() => self.release(release),
                Some(command) = commands.recv() => match command {
                    RoutingCommand::Begin(reply) => {
                        let reservation = accepting.then(|| self.begin()).flatten().map(|token| {
                            PoolReservation {
                                releases: self.releases.clone(),
                                token: Some(token),
                                sticky: None,
                            }
                        });
                        if let Err(Some(reservation)) = reply.send(reservation) {
                            // The actor already owns this abandoned reservation:
                            // release it before processing any later command.
                            let mut reservation = reservation;
                            if let Some(token) = reservation.token.take() { self.release_pool(token); }
                        }
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
                    #[cfg(test)]
                    RoutingCommand::Inspect(reply) => {
                        let _ = reply.send(self.state.pool_tokens.len());
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
                    host.enabled.send_replace(HostActivation::Active {
                        epoch,
                        preferred_endpoint: host.endpoint,
                    });
                    tracing::debug!(host_id = id, epoch, "waking selected VPN host");
                }
            }
            for id in 0..self.state.hosts.len() {
                self.state.observe_host(id);
            }
            tracing::info!(
                epoch,
                selected = self.state.hosts.iter().filter(|host| host.selected).count(),
                max_active = self.max_active_vpn_hosts,
                "VPN pool waking"
            );
        }
        self.state.observe_pool();
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
        self.state.observe_pool();
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
        for id in 0..state.hosts.len() {
            state.observe_host(id);
        }
        state.observe_pool();
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
        let id = match &update {
            RoutingUpdate::Phase(id, _)
            | RoutingUpdate::Probe(id, ..)
            | RoutingUpdate::Parked(id)
            | RoutingUpdate::Down(id, _)
            | RoutingUpdate::Baseline(id, ..)
            | RoutingUpdate::Ready { id, .. } => *id,
        };
        match update {
            RoutingUpdate::Phase(id, phase) => {
                let host = &mut self.state.hosts[id];
                host.phase = phase;
                tracing::debug!(host_id = id, endpoint = %host.endpoint, ?phase, "VPN host state changed");
            }
            RoutingUpdate::Ready {
                id,
                epoch,
                endpoint,
                stack,
                elapsed,
                score,
            } => {
                let host = &mut self.state.hosts[id];
                if !host.selected || host.enabled.borrow().epoch() != Some(epoch) {
                    tracing::debug!(
                        host_id = id,
                        epoch,
                        "discarded readiness from an inactive host session"
                    );
                    return;
                }
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
            RoutingUpdate::Baseline(id, endpoint, score) => {
                let host = &mut self.state.hosts[id];
                if host
                    .score_measured_at
                    .is_none_or(|previous| score.measured_at > previous)
                    && host.stack.is_none()
                {
                    host.endpoint = endpoint;
                    host.latency_score = Some(score.median);
                    host.score_measured_at = Some(score.measured_at);
                }
                // Fill available slots without displacing hosts serving requests.
                let selected = self.state.hosts.iter().filter(|host| host.selected).count();
                if !self.state.hosts[id].selected && selected < self.max_active_vpn_hosts {
                    let host = &mut self.state.hosts[id];
                    host.selected = true;
                    if let Some(epoch) = self.state.pool_epoch {
                        host.enabled.send_replace(HostActivation::Active {
                            epoch,
                            preferred_endpoint: host.endpoint,
                        });
                    }
                }
                if !self.state.pool_tokens.is_empty()
                    && let Some(failed) =
                        self.state.hosts.iter().position(|host| {
                            host.selected && host.unhealthy && host.stack.is_none()
                        })
                {
                    self.replace_failed_host(failed);
                }
            }
        }
        self.state.observe_host(id);
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
            self.replace_failed_host(id);
        }
        if was_ready || cleared > 0 {
            tracing::warn!(host_id = id, %endpoint, cleared_groups = cleared, shutdown, "VPN host unavailable; sticky assignments cleared");
        }
    }

    fn replace_failed_host(&mut self, id: usize) {
        let state = &mut self.state;
        let replacement = state
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| {
                !host.selected && host.latency_score.is_some() && host.phase == HostPhase::Dormant
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
                let host = &mut state.hosts[next];
                host.enabled.send_replace(HostActivation::Active {
                    epoch,
                    preferred_endpoint: host.endpoint,
                });
            }
            state.observe_host(id);
            state.observe_host(next);
            tracing::warn!(
                failed_host_id = id,
                replacement_host_id = next,
                "waking probed standby VPN host"
            );
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
            state.groups_by_host[id].insert(key.clone());
            tracing::info!(source = %key.source, destination = ?key.destination, host_id = id, endpoint = %state.hosts[id].endpoint, latency_score = ?state.hosts[id].latency_score, score_age = ?state.hosts[id].score_measured_at.map(|at| at.elapsed()), active = next_active, "assigned destination group to VPN host");
            generation
        };
        state.hosts[id].active = next_active;
        state.observe_host(id);
        state.observe_assignment(key);
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
        self.state.observe_host(host_id);
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
            self.state.observe_assignment(key);
        }
    }
}

impl Drop for PoolReservation {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        if self
            .releases
            .send(Release::Pool {
                token,
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

impl HostLease {
    pub(crate) fn stack(&self) -> &Stack {
        &self.stack
    }
}

impl RouterHandle {
    pub(crate) async fn select(
        &self,
        source: IpAddr,
        destination: DestinationHost,
    ) -> Option<HostLease> {
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
        let token = pool.token?;
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

    async fn test_stack() -> ovpn_netstack::StackOwner {
        let (tx, _rx) = mpsc::channel(1024);
        ovpn_netstack::StackOwner::start(
            ovpn_netstack::TunnelConfig::new(
                "10.8.0.2".parse().unwrap(),
                "10.8.0.1".parse().unwrap(),
                vec![],
                1400,
                None,
            )
            .unwrap(),
            tx,
        )
        .await
        .unwrap()
    }

    fn score(milliseconds: u64) -> LatencyScore {
        LatencyScore {
            median: Duration::from_millis(milliseconds),
            elapsed: Duration::ZERO,
            successful_samples: 3,
            measured_at: Instant::now(),
        }
    }

    #[tokio::test]
    async fn session_failure_clears_assignments_and_wakes_a_ranked_standby() {
        let (ready, _) = watch::channel(0);
        let (releases, _) = mpsc::unbounded_channel();
        let endpoint = "127.0.0.1:1194".parse().unwrap();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![
                Host::new(endpoint, true, Some(score(10))),
                Host::new("127.0.0.2:1194".parse().unwrap(), false, Some(score(20))),
            ]),
            ready,
            releases,
            max_active_vpn_hosts: 1,
        };
        let token = actor.begin().unwrap();
        let epoch = actor.state.pool_epoch.unwrap();
        let owner = test_stack().await;
        actor.update(RoutingUpdate::Ready {
            id: 0,
            epoch,
            endpoint,
            stack: owner.client(),
            elapsed: Duration::ZERO,
            score: score(10),
        });
        let destination = DestinationHost::Domain("example.com".into());
        let key = sticky_key("127.0.0.1".parse().unwrap(), &destination).unwrap();
        let _route = actor
            .select(token, &key, &destination)
            .ok()
            .flatten()
            .unwrap();

        // Health failures use the same transition as every other session error.
        actor.update(RoutingUpdate::Down(0, false));

        assert!(actor.state.hosts[0].stack.is_none());
        assert!(actor.state.sticky.is_empty());
        assert!(!actor.state.hosts[0].selected);
        assert_eq!(
            *actor.state.hosts[0].enabled.borrow(),
            HostActivation::Dormant
        );
        assert!(actor.state.hosts[1].selected);
        assert_eq!(actor.state.hosts[1].enabled.borrow().epoch(), Some(epoch));
        assert!(matches!(actor.select(token, &key, &destination), Ok(None)));
        owner.shutdown().await;
    }

    #[test]
    fn background_assessments_fill_pool_without_displacing_selected_hosts() {
        let (ready, _) = watch::channel(0);
        let (releases, _) = mpsc::unbounded_channel();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![
                Host::new("127.0.0.1:1194".parse().unwrap(), true, Some(score(20))),
                Host::new("127.0.0.2:1194".parse().unwrap(), false, None),
                Host::new("127.0.0.3:1194".parse().unwrap(), false, None),
            ]),
            ready,
            releases,
            max_active_vpn_hosts: 2,
        };
        actor.begin().unwrap();
        let preferred = "127.0.0.2:443".parse().unwrap();
        actor.update(RoutingUpdate::Baseline(1, preferred, score(10)));
        actor.update(RoutingUpdate::Baseline(
            2,
            "127.0.0.3:1194".parse().unwrap(),
            score(5),
        ));
        assert!(actor.state.hosts[0].selected);
        assert!(actor.state.hosts[1].selected);
        assert!(!actor.state.hosts[2].selected);
        assert!(
            matches!(*actor.state.hosts[1].enabled.borrow(), HostActivation::Active { preferred_endpoint, .. } if preferred_endpoint == preferred)
        );
    }

    #[tokio::test]
    async fn routing_shutdown_completes_with_surviving_request_handles() {
        let owner = RoutingOwner::start(vec![], Duration::from_secs(1), 1, Telemetry::default());
        let shared = owner.shared();
        owner.shutdown().await;
        let (reply, _received) = oneshot::channel();
        assert!(!shared.command(RoutingCommand::Inspect(reply)).await);
    }

    #[test]
    fn late_baseline_replaces_failed_selected_host() {
        let (ready, _) = watch::channel(0);
        let (releases, _) = mpsc::unbounded_channel();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![
                Host::new("127.0.0.1:1194".parse().unwrap(), true, Some(score(20))),
                Host::new("127.0.0.2:1194".parse().unwrap(), false, None),
            ]),
            ready,
            releases,
            max_active_vpn_hosts: 1,
        };
        actor.begin().unwrap();
        actor.down(0, false);
        assert!(actor.state.hosts[0].selected);
        actor.update(RoutingUpdate::Baseline(
            1,
            "127.0.0.2:443".parse().unwrap(),
            score(10),
        ));
        assert!(!actor.state.hosts[0].selected);
        assert_eq!(
            *actor.state.hosts[0].enabled.borrow(),
            HostActivation::Dormant
        );
        assert!(actor.state.hosts[1].selected);
        assert!(actor.state.hosts[1].enabled.borrow().epoch().is_some());
    }

    #[tokio::test]
    async fn old_readiness_and_probe_cannot_replace_current_session() {
        let (ready, _) = watch::channel(0);
        let (releases, _) = mpsc::unbounded_channel();
        let endpoint = "127.0.0.1:1194".parse().unwrap();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![Host::new(endpoint, true, Some(score(20)))]),
            ready,
            releases,
            max_active_vpn_hosts: 1,
        };
        actor.state.hosts[0]
            .enabled
            .send_replace(HostActivation::Active {
                epoch: 2,
                preferred_endpoint: endpoint,
            });
        let old = test_stack().await;
        let current = test_stack().await;
        actor.update(RoutingUpdate::Ready {
            id: 0,
            epoch: 1,
            endpoint,
            stack: old.client(),
            elapsed: Duration::ZERO,
            score: score(50),
        });
        assert!(actor.state.hosts[0].stack.is_none());
        actor.update(RoutingUpdate::Ready {
            id: 0,
            epoch: 2,
            endpoint,
            stack: current.client(),
            elapsed: Duration::ZERO,
            score: score(10),
        });
        actor.update(RoutingUpdate::Probe(
            0,
            old.client().id(),
            Ok(score(100)),
            Duration::ZERO,
        ));
        assert_eq!(
            actor.state.hosts[0].stack.as_ref().unwrap().id(),
            current.client().id()
        );
        assert_eq!(
            actor.state.hosts[0].latency_score,
            Some(Duration::from_millis(10))
        );
    }

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
        actor.state.groups_by_host[0].insert(key.clone());
        actor.release_sticky(&key, 1, 0);
        assert_eq!(actor.state.hosts[0].active, 1);
        assert_eq!(actor.state.sticky[&key].active, 1);
        actor.release_sticky(&key, 2, 0);
        assert_eq!(actor.state.hosts[0].active, 0);
        assert_eq!(actor.state.sticky[&key].active, 0);
        assert_eq!(actor.state.groups_by_host[0].len(), 1);
    }

    #[tokio::test]
    async fn abandoned_begin_releases_pool_reservation() {
        let owner = RoutingOwner::start(
            vec![Host::new("127.0.0.1:1194".parse().unwrap(), true, None)],
            Duration::from_secs(1),
            1,
            Telemetry::default(),
        );
        let shared = owner.shared();
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
            .send(RoutingCommand::Inspect(reply))
            .await
            .unwrap();
        let snapshot = received.await.unwrap();
        assert_eq!(snapshot, 0);
    }

    #[tokio::test]
    async fn delivered_begin_releases_pool_when_receiver_is_dropped() {
        let owner = RoutingOwner::start(
            vec![Host::new("127.0.0.1:1194".parse().unwrap(), true, None)],
            Duration::from_secs(1),
            1,
            Telemetry::default(),
        );
        let shared = owner.shared();
        let (reply, received) = oneshot::channel();
        shared
            .commands
            .send(RoutingCommand::Begin(reply))
            .await
            .unwrap();
        let (barrier, processed) = oneshot::channel();
        shared
            .commands
            .send(RoutingCommand::Inspect(barrier))
            .await
            .unwrap();
        let _ = processed.await.unwrap();
        drop(received);
        time::timeout(Duration::from_secs(1), async {
            loop {
                let (reply, received) = oneshot::channel();
                shared
                    .commands
                    .send(RoutingCommand::Inspect(reply))
                    .await
                    .unwrap();
                if received.await.unwrap() == 0 {
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
        let stack_owner = test_stack().await;
        let (reply, received) = oneshot::channel::<SelectReply>();
        reply
            .send(Ok(Some(SelectedRoute {
                stack: stack_owner.client(),
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

    #[tokio::test]
    async fn dashboard_observes_routes_failures_and_stale_releases_without_querying_routing() {
        let dashboard = crate::dashboard::Dashboard::start().unwrap();
        let view = dashboard.handle();
        view.running();
        let telemetry = view.telemetry();
        let (ready, _) = watch::channel(0);
        let (releases, mut release_rx) = mpsc::unbounded_channel();
        let endpoint = "127.0.0.1:1194".parse().unwrap();
        let mut actor = RoutingActor {
            state: RoutingState::new(vec![Host::new(endpoint, true, Some(score(20)))]),
            ready,
            releases,
            max_active_vpn_hosts: 1,
        };
        actor.state.telemetry = telemetry.clone();
        telemetry.emit(|| Observation::Initialized {
            hosts: vec![actor.state.host_observation(0)],
            max_active_hosts: 1,
        });
        let token = actor.begin().unwrap();
        let stack = test_stack().await;
        let epoch = actor.state.pool_epoch.unwrap();
        actor.update(RoutingUpdate::Ready {
            id: 0,
            epoch,
            endpoint,
            stack: stack.client(),
            elapsed: Duration::ZERO,
            score: score(10),
        });
        let destination = DestinationHost::Domain("example.com".into());
        let key = sticky_key("127.0.0.1".parse().unwrap(), &destination).unwrap();
        let first = actor
            .select(token, &key, &destination)
            .ok()
            .flatten()
            .unwrap();
        view.flush_observations().await;
        let snapshot = view.snapshot().await;
        assert_eq!(snapshot.pool.active_routes, 1);
        assert_eq!(snapshot.pool.sticky_groups, 1);
        assert!(matches!(snapshot.pool.phase, ovpn_ui::PoolPhase::Ready));

        // A host failure clears assignments while the old lease is still alive.
        actor.update(RoutingUpdate::Down(0, false));
        view.flush_observations().await;
        let snapshot = view.snapshot().await;
        assert_eq!(snapshot.pool.active_routes, 1);
        assert_eq!(snapshot.pool.sticky_groups, 0);
        assert_eq!(snapshot.pool.ready_hosts, 0);
        actor.update(RoutingUpdate::Ready {
            id: 0,
            epoch,
            endpoint,
            stack: stack.client(),
            elapsed: Duration::ZERO,
            score: score(10),
        });
        let second = actor
            .select(token, &key, &destination)
            .ok()
            .flatten()
            .unwrap();
        drop(first);
        actor.release(release_rx.recv().await.unwrap());
        view.flush_observations().await;
        let snapshot = view.snapshot().await;
        assert_eq!(snapshot.pool.active_routes, 1);
        assert_eq!(snapshot.pool.sticky_groups, 1);
        let page = ovpn_ui::DashboardSource::group_page(&view, 0, 0, 100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.groups[0].active_connections, 1);
        drop(second);
        actor.release(release_rx.recv().await.unwrap());
        actor.release_pool(token);
        view.flush_observations().await;
        let snapshot = view.snapshot().await;
        assert_eq!(snapshot.pool.active_routes, 0);
        assert!(matches!(snapshot.pool.phase, ovpn_ui::PoolPhase::Idle));
        actor.state.pool_usage.idle_since = Some(Instant::now() - POOL_IDLE_TIMEOUT);
        actor.park_pool();
        view.flush_observations().await;
        let snapshot = view.snapshot().await;
        assert!(matches!(snapshot.pool.phase, ovpn_ui::PoolPhase::Dormant));
        assert_eq!(snapshot.pool.sticky_groups, 0);
        drop(actor);
        stack.shutdown().await;
        dashboard.shutdown().await;
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
