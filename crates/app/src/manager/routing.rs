use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ovpn_netstack::Stack;
use ovpn_socks5::{DestinationHost, RouteLease, RouteProvider};
use tokio::sync::watch;

const MAX_STICKY_GROUPS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostPhase {
    Waiting,
    Connecting,
    Ready,
    Backoff,
    Stopped,
}

pub(super) struct Host {
    pub(super) endpoint: SocketAddr,
    pub(super) phase: HostPhase,
    pub(super) stack: Option<Stack>,
    pub(super) active: Arc<AtomicUsize>,
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
}

impl Shared {
    pub(super) fn phase(&self, id: usize, phase: HostPhase) {
        let Ok(mut state) = self.state.lock() else {
            tracing::error!(host_id = id, "VPN routing state lock poisoned");
            return;
        };
        state.hosts[id].phase = phase;
        tracing::debug!(host_id = id, endpoint = %state.hosts[id].endpoint, ?phase, "VPN host state changed");
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
        tracing::info!(host_id = id, %endpoint, generation, ?elapsed, ready_hosts = ready, "VPN host ready");
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

#[derive(Clone)]
pub(crate) struct RouterHandle {
    pub(super) shared: Arc<Shared>,
}

pub(crate) struct HostLease {
    stack: Stack,
    active: Arc<AtomicUsize>,
    host_id: usize,
}

impl RouteLease for HostLease {
    fn stack(&self) -> &Stack {
        &self.stack
    }
}

impl Drop for HostLease {
    fn drop(&mut self) {
        let remaining = self.active.fetch_sub(1, Ordering::Relaxed) - 1;
        tracing::trace!(
            host_id = self.host_id,
            active = remaining,
            "VPN route released"
        );
    }
}

impl RouteProvider for RouterHandle {
    type Lease = HostLease;

    fn select(&self, destination: &DestinationHost) -> Option<Self::Lease> {
        let key = sticky_key(destination)?;
        let Ok(mut state) = self.shared.state.lock() else {
            tracing::error!("VPN routing state lock poisoned; rejecting SOCKS request");
            return None;
        };
        if let Some(&id) = state.sticky.get(&key) {
            if let Some(stack) = state.hosts[id]
                .stack
                .as_ref()
                .filter(|stack| stack.is_ready())
            {
                let stack = stack.clone();
                let active = Arc::clone(&state.hosts[id].active);
                let count = active.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(group = %key, host_id = id, active = count, "reused sticky VPN host");
                return Some(HostLease {
                    stack,
                    active,
                    host_id: id,
                });
            }
            state.sticky.remove(&key);
        }
        if state.sticky.len() >= MAX_STICKY_GROUPS {
            tracing::warn!(
                limit = MAX_STICKY_GROUPS,
                "sticky routing table full; rejecting SOCKS request"
            );
            return None;
        }
        let ready: Vec<usize> = state
            .hosts
            .iter()
            .enumerate()
            .filter_map(|(id, host)| {
                host.stack
                    .as_ref()
                    .is_some_and(Stack::is_ready)
                    .then_some(id)
            })
            .collect();
        if ready.is_empty() {
            tracing::debug!(group = %key, "no ready VPN host for new assignment");
            return None;
        }
        let first = ready[state.next_choice % ready.len()];
        let second = ready[(state.next_choice + 1) % ready.len()];
        state.next_choice = state.next_choice.wrapping_add(1);
        let first_load = state.hosts[first].active.load(Ordering::Relaxed);
        let second_load = state.hosts[second].active.load(Ordering::Relaxed);
        let id = if second_load < first_load {
            second
        } else {
            first
        };
        state.sticky.insert(key.clone(), id);
        let host = &state.hosts[id];
        let stack = host.stack.as_ref()?.clone();
        let active = Arc::clone(&host.active);
        let count = active.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!(group = %key, host_id = id, endpoint = %host.endpoint, generation = host.generation, active = count, ready_hosts = ready.len(), "assigned domain group to VPN host");
        Some(HostLease {
            stack,
            active,
            host_id: id,
        })
    }
}

fn sticky_key(destination: &DestinationHost) -> Option<String> {
    match destination {
        DestinationHost::Ipv4(address) => Some(format!("ip:{address}")),
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
