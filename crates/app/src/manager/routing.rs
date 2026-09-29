use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use ovpn_netstack::Stack;
use ovpn_socks5::{DestinationHost, RouteLease, RouteProvider};
use tokio::sync::watch;
use tokio::time;

const MAX_STICKY_GROUPS: usize = 100_000;
const COLD_HOST_COST: usize = 2;

#[derive(Clone)]
pub(crate) struct RouterHandle {
    pub(super) shared: Arc<Shared>,
}

pub(crate) struct HostLease {
    stack: Stack,
    _reservation: HostReservation,
}

pub(super) struct HostUsage {
    state: watch::Sender<UsageState>,
}

#[derive(Clone, Copy)]
pub(super) struct UsageState {
    pub(super) active: usize,
    pub(super) idle_since: Option<Instant>,
}

struct HostReservation {
    usage: Arc<HostUsage>,
    host_id: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostPhase {
    Dormant,
    Connecting,
    Ready,
    Backoff,
    Stopped,
}

pub(super) struct Host {
    pub(super) endpoint: SocketAddr,
    pub(super) phase: HostPhase,
    pub(super) stack: Option<Stack>,
    pub(super) usage: Arc<HostUsage>,
    pub(super) generation: u64,
}

pub(super) struct RoutingState {
    pub(super) hosts: Vec<Host>,
    pub(super) sticky: HashMap<String, usize>,
    pub(super) next_choice: usize,
}

pub(super) struct Shared {
    pub(super) state: Mutex<RoutingState>,
    pub(super) ready: watch::Sender<usize>,
    pub(super) acquire_timeout: Duration,
}

impl HostUsage {
    pub(super) fn new() -> Arc<Self> {
        let (state, _) = watch::channel(UsageState {
            active: 0,
            idle_since: None,
        });
        Arc::new(Self { state })
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<UsageState> {
        self.state.subscribe()
    }

    pub(super) fn snapshot(&self) -> UsageState {
        *self.state.borrow()
    }

    fn reserve(self: &Arc<Self>, host_id: usize) -> Option<HostReservation> {
        let mut reserved = false;
        self.state.send_modify(|usage| {
            if let Some(active) = usage.active.checked_add(1) {
                usage.active = active;
                usage.idle_since = None;
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
                return;
            }
            usage.active -= 1;
            if usage.active == 0 {
                usage.idle_since = Some(Instant::now());
            }
            tracing::trace!(host_id, active = usage.active, "VPN route released");
        });
    }
}

impl Shared {
    pub(super) fn phase(&self, id: usize, phase: HostPhase) {
        let Ok(mut state) = self.state.lock() else {
            tracing::error!(host_id = id, "VPN routing state lock poisoned");
            return;
        };
        state.hosts[id].phase = phase;
        tracing::debug!(host_id = id, endpoint = %state.hosts[id].endpoint, ?phase, "VPN host state changed");
        let ready = state
            .hosts
            .iter()
            .filter(|host| host.stack.is_some())
            .count();
        self.ready.send_replace(ready);
    }

    pub(super) fn ready(&self, id: usize, endpoint: SocketAddr, stack: &Stack, elapsed: Duration) {
        let Ok(mut state) = self.state.lock() else {
            tracing::error!(host_id = id, "VPN routing state lock poisoned");
            return;
        };
        let host = &mut state.hosts[id];
        host.endpoint = endpoint;
        host.phase = HostPhase::Ready;
        host.generation = host.generation.wrapping_add(1);
        host.stack = Some(stack.clone());
        let endpoint = host.endpoint;
        let generation = host.generation;
        let ready = state
            .hosts
            .iter()
            .filter(|host| host.stack.is_some())
            .count();
        self.ready.send_replace(ready);
        tracing::info!(host_id = id, %endpoint, stack_id = stack.id(), ipv6 = stack.supports_ipv6(), generation, ?elapsed, ready_hosts = ready, "VPN host ready");
    }

    pub(super) fn park_if_idle(&self, id: usize, idle_timeout: Duration) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("VPN routing state lock poisoned during idle shutdown"))?;
        let host = &mut state.hosts[id];
        let usage = host.usage.snapshot();
        if host.phase != HostPhase::Ready
            || usage.active != 0
            || !usage
                .idle_since
                .is_some_and(|since| since.elapsed() >= idle_timeout)
        {
            return Ok(false);
        }
        let endpoint = host.endpoint;
        host.stack = None;
        host.phase = HostPhase::Dormant;
        let ready = state
            .hosts
            .iter()
            .filter(|host| host.stack.is_some())
            .count();
        self.ready.send_replace(ready);
        tracing::info!(host_id = id, %endpoint, ready_hosts = ready, "VPN host closed after idle timeout; sticky assignments retained");
        Ok(true)
    }

    pub(super) fn down(&self, id: usize, shutdown: bool) {
        let Ok(mut state) = self.state.lock() else {
            tracing::error!(host_id = id, "VPN routing state lock poisoned");
            return;
        };
        let host = &mut state.hosts[id];
        let was_ready = host.stack.take().is_some();
        host.phase = if shutdown {
            HostPhase::Stopped
        } else {
            HostPhase::Backoff
        };
        let endpoint = host.endpoint;
        let cleared = state.sticky.len();
        state.sticky.retain(|_, selected| *selected != id);
        let cleared = cleared - state.sticky.len();
        let ready = state
            .hosts
            .iter()
            .filter(|host| host.stack.is_some())
            .count();
        self.ready.send_replace(ready);
        if was_ready || cleared > 0 {
            if shutdown {
                tracing::info!(host_id = id, %endpoint, cleared_groups = cleared, ready_hosts = ready, "VPN host stopped; sticky assignments cleared");
            } else {
                tracing::warn!(host_id = id, %endpoint, cleared_groups = cleared, ready_hosts = ready, "VPN host unavailable; sticky assignments cleared");
            }
        }
    }
}

impl RouteLease for HostLease {
    fn stack(&self) -> &Stack {
        &self.stack
    }
}

impl Drop for HostReservation {
    fn drop(&mut self) {
        self.usage.release(self.host_id);
    }
}

impl RouteProvider for RouterHandle {
    type Lease = HostLease;

    fn select(
        &self,
        destination: DestinationHost,
    ) -> impl Future<Output = Option<Self::Lease>> + Send {
        async move {
            let key = sticky_key(&destination)?;
            let deadline = Instant::now() + self.shared.acquire_timeout;
            let mut updates = self.shared.ready.subscribe();
            let mut excluded = Vec::new();
            let host_count = self.shared.state.lock().ok()?.hosts.len();
            loop {
                let choice = {
                    let Ok(mut state) = self.shared.state.lock() else {
                        tracing::error!("VPN routing state lock poisoned; rejecting SOCKS request");
                        return None;
                    };
                    let sticky = state.sticky.get(&key).copied();
                    let sticky = sticky.filter(|&id| {
                        !excluded.contains(&id) && host_eligible(&state.hosts[id], &destination)
                    });
                    if sticky.is_none() {
                        state.sticky.remove(&key);
                    }
                    let id = if let Some(id) = sticky {
                        Some(id)
                    } else {
                        if state.sticky.len() >= MAX_STICKY_GROUPS {
                            tracing::warn!(
                                limit = MAX_STICKY_GROUPS,
                                "sticky routing table full; rejecting SOCKS request"
                            );
                            return None;
                        }
                        let mut eligible: Vec<_> = state
                            .hosts
                            .iter()
                            .enumerate()
                            .filter_map(|(id, host)| {
                                (!excluded.contains(&id) && host_eligible(host, &destination))
                                    .then_some(id)
                            })
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
                        if eligible.is_empty() {
                            None
                        } else {
                            let start = state.next_choice % eligible.len();
                            state.next_choice = state.next_choice.wrapping_add(1);
                            let id = (0..eligible.len())
                                .map(|offset| eligible[(start + offset) % eligible.len()])
                                .min_by_key(|&id| host_cost(&state.hosts[id]));
                            if let Some(id) = id {
                                state.sticky.insert(key.clone(), id);
                                let host = &state.hosts[id];
                                tracing::info!(group = %key, host_id = id, endpoint = %host.endpoint, ?host.phase, active = host.usage.snapshot().active, "assigned destination group to VPN host");
                            }
                            id
                        }
                    };
                    id.and_then(|id| {
                        let host = &state.hosts[id];
                        let reservation = host.usage.reserve(id)?;
                        tracing::debug!(group = %key, host_id = id, ?host.phase, active = host.usage.snapshot().active, "VPN host requested for SOCKS destination");
                        Some((id, reservation, host.stack.clone()))
                    })
                };
                let no_choice = choice.is_none();
                if let Some((id, reservation, stack)) = choice {
                    if let Some(stack) = stack.filter(|stack| {
                        stack.is_ready() && destination_supported(stack, &destination)
                    }) {
                        return Some(HostLease {
                            stack,
                            _reservation: reservation,
                        });
                    }
                    loop {
                        let status = {
                            let Ok(state) = self.shared.state.lock() else {
                                tracing::error!(
                                    "VPN routing state lock poisoned while waiting for host"
                                );
                                return None;
                            };
                            let host = &state.hosts[id];
                            (host.phase, host.stack.clone())
                        };
                        match status {
                            (HostPhase::Ready, Some(stack))
                                if stack.is_ready()
                                    && destination_supported(&stack, &destination) =>
                            {
                                tracing::debug!(group = %key, host_id = id, stack_id = stack.id(), "VPN host acquired for SOCKS destination");
                                return Some(HostLease {
                                    stack,
                                    _reservation: reservation,
                                });
                            }
                            (
                                phase
                                @ (HostPhase::Ready | HostPhase::Backoff | HostPhase::Stopped),
                                _,
                            ) => {
                                tracing::debug!(group = %key, host_id = id, ?phase, "VPN host unavailable for destination; trying another host");
                                excluded.push(id);
                                let Ok(mut state) = self.shared.state.lock() else {
                                    return None;
                                };
                                if state.sticky.get(&key) == Some(&id) {
                                    state.sticky.remove(&key);
                                }
                                break;
                            }
                            _ => {}
                        }
                        if !wait_for_update(&mut updates, deadline).await {
                            tracing::warn!(group = %key, "timed out waiting for a VPN host");
                            return None;
                        }
                    }
                    drop(reservation);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    tracing::warn!(group = %key, "no VPN host became available before request deadline");
                    return None;
                }
                if excluded.len() >= host_count {
                    tracing::debug!(group = %key, "no VPN host can route the destination");
                    return None;
                }
                if no_choice {
                    let no_future_host = {
                        let Ok(state) = self.shared.state.lock() else {
                            return None;
                        };
                        state
                            .hosts
                            .iter()
                            .all(|host| matches!(host.phase, HostPhase::Ready | HostPhase::Stopped))
                    };
                    if no_future_host {
                        tracing::debug!(group = %key, "no VPN host can route the destination");
                        return None;
                    }
                    if !wait_for_update(&mut updates, deadline).await {
                        tracing::warn!(group = %key, "timed out waiting for an eligible VPN host");
                        return None;
                    }
                }
            }
        }
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

fn host_eligible(host: &Host, destination: &DestinationHost) -> bool {
    match host.phase {
        HostPhase::Dormant | HostPhase::Connecting => true,
        HostPhase::Ready => host
            .stack
            .as_ref()
            .is_some_and(|stack| stack.is_ready() && destination_supported(stack, destination)),
        HostPhase::Backoff | HostPhase::Stopped => false,
    }
}

fn host_cost(host: &Host) -> usize {
    host.usage
        .snapshot()
        .active
        .saturating_add(if host.phase == HostPhase::Ready {
            0
        } else {
            COLD_HOST_COST
        })
}

fn sticky_key(destination: &DestinationHost) -> Option<String> {
    match destination {
        DestinationHost::Ipv4(address) => Some(format!("ip:{address}")),
        DestinationHost::Ipv6(address) => Some(format!("ip6:{address}")),
        DestinationHost::Domain(name) => {
            let normalized = name.trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                return None;
            }
            let group = psl::domain_str(&normalized).unwrap_or(&normalized);
            Some(format!("domain:{group}"))
        }
    }
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
    fn registrable_domains_share_a_sticky_key() {
        let key = sticky_key(&DestinationHost::Domain("ABC.COM".into()));
        assert_eq!(
            key,
            sticky_key(&DestinationHost::Domain("xyz.abc.com".into()))
        );
        assert_eq!(
            sticky_key(&DestinationHost::Domain("shop.example.co.uk".into())),
            sticky_key(&DestinationHost::Domain("example.co.uk".into()))
        );
        assert_ne!(
            key,
            sticky_key(&DestinationHost::Domain("other.com".into()))
        );
    }
}
