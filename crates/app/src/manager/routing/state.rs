//! Synchronous routing policy. The routing actor is the sole owner of this state.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ovpn_netstack::Stack;
use ovpn_socks5::DestinationHost;
use tokio::sync::watch;

use crate::manager::domain::{
    HostActivation, HostPhase, POOL_IDLE_TIMEOUT, STICKY_IDLE_TIMEOUT, StickyKey,
};
use crate::manager::probe::LatencyScore;
use crate::manager::telemetry::{HostObservation, Observation, PoolObservation, Telemetry};

const MAX_STICKY_GROUPS: usize = 100_000;
const LOAD_SCORE_SCALE: u128 = 8;
const LATENCY_HISTORY_WEIGHT: u32 = 3;
const LATENCY_SAMPLE_WEIGHT: u32 = 1;

/// An accounted route; the actor attaches its cancellation-safe lease before delivery.
pub(super) struct RouteSelection {
    pub stack: Stack,
    pub generation: u64,
    pub host_id: usize,
}

pub(in crate::manager) struct Host {
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

struct StickyEntry {
    host_id: usize,
    active: usize,
    idle_since: Option<Instant>,
    generation: u64,
}

pub(super) struct RoutingState {
    hosts: Vec<Host>,
    sticky: HashMap<StickyKey, StickyEntry>,
    groups_by_host: Vec<HashSet<StickyKey>>,
    pool_tokens: HashSet<u64>,
    next_pool_token: u64,
    next_choice: usize,
    next_sticky_generation: u64,
    pool_idle_since: Option<Instant>,
    pool_epoch: Option<u64>,
    next_pool_epoch: u64,
    telemetry: Telemetry,
    max_active_vpn_hosts: usize,
}

pub(super) enum RoutingUpdate {
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
}

impl Host {
    pub(in crate::manager) fn new(
        endpoint: SocketAddr,
        selected: bool,
        score: Option<LatencyScore>,
    ) -> Self {
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

    pub(in crate::manager) fn activation(&self) -> watch::Receiver<HostActivation> {
        self.enabled.subscribe()
    }
}

impl RoutingState {
    pub(super) fn new(hosts: Vec<Host>, max_active_vpn_hosts: usize, telemetry: Telemetry) -> Self {
        let groups_by_host = (0..hosts.len()).map(|_| HashSet::new()).collect();
        let state = Self {
            hosts,
            sticky: HashMap::new(),
            groups_by_host,
            pool_tokens: HashSet::new(),
            next_pool_token: 0,
            next_choice: 0,
            next_sticky_generation: 0,
            pool_idle_since: None,
            pool_epoch: None,
            next_pool_epoch: 0,
            telemetry,
            max_active_vpn_hosts,
        };
        state.telemetry.emit(|| Observation::Initialized {
            hosts: (0..state.hosts.len())
                .map(|id| state.host_observation(id))
                .collect(),
            max_active_hosts: max_active_vpn_hosts,
        });
        state
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
                idle_since: self.pool_idle_since,
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

    pub(super) fn has_requests(&self) -> bool {
        !self.pool_tokens.is_empty()
    }

    #[cfg(test)]
    pub(super) fn request_count(&self) -> usize {
        self.pool_tokens.len()
    }

    pub(super) fn idle_deadline(&self) -> Option<Instant> {
        self.pool_idle_since.map(|since| since + POOL_IDLE_TIMEOUT)
    }

    pub(super) fn ready_count(&self) -> usize {
        self.hosts
            .iter()
            .filter(|host| host.stack.is_some())
            .count()
    }

    pub(super) fn begin(&mut self) -> Option<u64> {
        self.next_pool_token = self.next_pool_token.wrapping_add(1).max(1);
        let token = self.next_pool_token;
        if !self.pool_tokens.insert(token) {
            return None;
        }
        self.pool_idle_since = None;
        if self.pool_epoch.is_none() {
            self.next_pool_epoch = self.next_pool_epoch.wrapping_add(1).max(1);
            let epoch = self.next_pool_epoch;
            self.pool_epoch = Some(epoch);
            let mut ranked: Vec<_> = self
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
            for (id, host) in self.hosts.iter_mut().enumerate() {
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
            for id in 0..self.hosts.len() {
                self.observe_host(id);
            }
            tracing::info!(
                epoch,
                selected = self.hosts.iter().filter(|host| host.selected).count(),
                max_active = self.max_active_vpn_hosts,
                "VPN pool waking"
            );
        }
        self.observe_pool();
        Some(token)
    }

    pub(super) fn release_pool(&mut self, token: u64) {
        if !self.pool_tokens.remove(&token) {
            tracing::error!(token, "unknown VPN pool reservation");
            return;
        }
        if self.pool_tokens.is_empty() {
            self.pool_idle_since = Some(Instant::now());
            tracing::info!(?POOL_IDLE_TIMEOUT, "VPN pool idle timer started");
        }
        self.observe_pool();
    }

    pub(super) fn park_pool(&mut self) -> bool {
        if !self.pool_tokens.is_empty()
            || !self
                .pool_idle_since
                .is_some_and(|since| since.elapsed() >= POOL_IDLE_TIMEOUT)
        {
            return false;
        }
        for host in &mut self.hosts {
            host.enabled.send_replace(HostActivation::Dormant);
            host.stack = None;
            host.phase = HostPhase::Dormant;
        }
        self.pool_epoch = None;
        self.clear_sticky();
        self.pool_idle_since = None;
        for id in 0..self.hosts.len() {
            self.observe_host(id);
        }
        self.observe_pool();
        tracing::info!("VPN pool idle timeout reached; closing all sessions");
        true
    }

    pub(super) fn sweep_sticky(&mut self) {
        let at = Instant::now();
        let expired: Vec<_> = self
            .sticky
            .iter()
            .filter(|(_, entry)| sticky_expired_at(entry, at))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            self.remove_sticky(key);
        }
        if !expired.is_empty() {
            tracing::debug!(
                removed = expired.len(),
                remaining = self.sticky.len(),
                "expired idle sticky groups"
            );
        }
    }

    /// Stale session updates return false and must not publish readiness changes.
    pub(super) fn update(&mut self, update: RoutingUpdate) -> bool {
        let id = match &update {
            RoutingUpdate::Phase(id, _)
            | RoutingUpdate::Probe(id, ..)
            | RoutingUpdate::Parked(id)
            | RoutingUpdate::Down(id, _)
            | RoutingUpdate::Ready { id, .. } => *id,
        };
        match update {
            RoutingUpdate::Phase(id, phase) => {
                let host = &mut self.hosts[id];
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
                let host = &mut self.hosts[id];
                if !host.selected || host.enabled.borrow().epoch() != Some(epoch) {
                    tracing::debug!(
                        host_id = id,
                        epoch,
                        "discarded readiness from an inactive host session"
                    );
                    return false;
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
                let host = &mut self.hosts[id];
                if host.stack.as_ref().map(Stack::id) != Some(stack_id) {
                    tracing::debug!(
                        host_id = id,
                        stack_id,
                        "discarded latency probe result for an old tunnel"
                    );
                    return false;
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
                self.hosts[id].stack = None;
                self.hosts[id].phase = HostPhase::Dormant;
                tracing::debug!(host_id = id, "VPN host parked");
            }
            RoutingUpdate::Down(id, shutdown) => self.down(id, shutdown),
        }
        self.observe_host(id);
        true
    }

    fn down(&mut self, id: usize, shutdown: bool) {
        let host = &mut self.hosts[id];
        let was_ready = host.stack.take().is_some();
        host.phase = if shutdown {
            HostPhase::Stopped
        } else {
            HostPhase::Backoff
        };
        host.unhealthy = true;
        let endpoint = host.endpoint;
        let cleared = self.clear_host(id);
        if !shutdown && !self.pool_tokens.is_empty() && self.hosts[id].selected {
            self.replace_failed_host(id);
        }
        if was_ready || cleared > 0 {
            tracing::warn!(host_id = id, %endpoint, cleared_groups = cleared, shutdown, "VPN host unavailable; sticky assignments cleared");
        }
    }

    fn replace_failed_host(&mut self, id: usize) {
        let replacement = self
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| {
                !host.selected && host.latency_score.is_some() && host.phase == HostPhase::Dormant
            })
            .min_by_key(|(_, host)| (host.unhealthy, host.latency_score))
            .map(|(id, _)| id);
        if let Some(next) = replacement {
            self.hosts[id].selected = false;
            self.hosts[id].enabled.send_replace(HostActivation::Dormant);
            self.hosts[next].selected = true;
            if let Some(epoch) = self.pool_epoch {
                let host = &mut self.hosts[next];
                host.enabled.send_replace(HostActivation::Active {
                    epoch,
                    preferred_endpoint: host.endpoint,
                });
            }
            self.observe_host(id);
            self.observe_host(next);
            tracing::warn!(
                failed_host_id = id,
                replacement_host_id = next,
                "waking probed standby VPN host"
            );
        }
    }

    pub(super) fn select(
        &mut self,
        token: u64,
        key: &StickyKey,
        destination: &DestinationHost,
    ) -> Result<Option<RouteSelection>, ()> {
        if !self.pool_tokens.contains(&token) {
            return Err(());
        }
        if self.sticky.get(key).is_some_and(sticky_expired) {
            self.remove_sticky(key);
        }
        let sticky_id = self.sticky.get(key).map(|entry| entry.host_id);
        if sticky_id.is_some_and(|id| !host_eligible(&self.hosts[id], destination)) {
            self.remove_sticky(key);
        }
        if !self.sticky.contains_key(key) && self.sticky.len() >= MAX_STICKY_GROUPS {
            tracing::warn!(
                limit = MAX_STICKY_GROUPS,
                "sticky routing table full; rejecting SOCKS request"
            );
            return Err(());
        }
        let id = self
            .sticky
            .get(key)
            .map(|entry| entry.host_id)
            .or_else(|| choose_host(self, destination));
        let Some(id) = id else {
            return Ok(None);
        };
        let Some(stack) = self.hosts[id].stack.clone() else {
            return Ok(None);
        };
        let Some(next_active) = self.hosts[id].active.checked_add(1) else {
            return Err(());
        };
        let generation = if let Some(entry) = self.sticky.get_mut(key) {
            entry.active = entry.active.checked_add(1).ok_or(())?;
            entry.idle_since = None;
            entry.generation
        } else {
            self.next_sticky_generation = self.next_sticky_generation.wrapping_add(1);
            let generation = self.next_sticky_generation;
            self.sticky.insert(
                key.clone(),
                StickyEntry {
                    host_id: id,
                    active: 1,
                    idle_since: None,
                    generation,
                },
            );
            self.groups_by_host[id].insert(key.clone());
            tracing::info!(source = %key.source, destination = ?key.destination, host_id = id, endpoint = %self.hosts[id].endpoint, latency_score = ?self.hosts[id].latency_score, score_age = ?self.hosts[id].score_measured_at.map(|at| at.elapsed()), active = next_active, "assigned destination group to VPN host");
            generation
        };
        self.hosts[id].active = next_active;
        self.observe_host(id);
        self.observe_assignment(key);
        Ok(Some(RouteSelection {
            stack,
            generation,
            host_id: id,
        }))
    }

    pub(super) fn release_sticky(&mut self, key: &StickyKey, generation: u64, host_id: usize) {
        let host = &mut self.hosts[host_id];
        if host.active == 0 {
            tracing::error!(host_id, "VPN host reservation count underflow");
        } else {
            host.active -= 1;
        }
        self.observe_host(host_id);
        if let Some(entry) = self.sticky.get_mut(key) {
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
            self.observe_assignment(key);
        }
    }
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

fn destination_supported(stack: &Stack, destination: &DestinationHost) -> bool {
    match destination {
        DestinationHost::Ipv6(address) => stack.can_route_ipv6(*address),
        DestinationHost::Ipv4(_) | DestinationHost::Domain(_) => true,
    }
}

#[cfg(test)]
mod tests;
