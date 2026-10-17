//! Domain observations. Producers never wait for dashboard work or depend on UI types.
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

pub(crate) const STICKY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub(crate) const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostPhase {
    Dormant,
    Connecting,
    Ready,
    Backoff,
    Stopped,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct StickyKey {
    pub source: IpAddr,
    pub destination: StickyDestination,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) enum StickyDestination {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone)]
pub(crate) struct HostObservation {
    pub endpoint: SocketAddr,
    pub phase: HostPhase,
    pub selected: bool,
    pub active_routes: usize,
    pub latency_score: Option<Duration>,
    pub score_measured_at: Option<Instant>,
    pub ready: bool,
    pub ipv6: bool,
}

#[derive(Default)]
pub(crate) struct PoolObservation {
    pub awake: bool,
    pub has_requests: bool,
    pub idle_since: Option<Instant>,
}

/// `Initialized` is sent before host workers start. Host IDs are stable vector
/// indices for this manager lifetime. All routing mutations use one sender;
/// traffic updates are absolute totals from each host's single owner.
pub(crate) enum Observation {
    Initialized {
        hosts: Vec<HostObservation>,
        max_active_hosts: usize,
    },
    Host {
        id: usize,
        state: HostObservation,
    },
    Pool(PoolObservation),
    Assignment {
        key: StickyKey,
        host_id: usize,
        active: usize,
        idle_since: Option<Instant>,
    },
    AssignmentRemoved(StickyKey),
    HostAssignmentsCleared(usize),
    AssignmentsCleared,
    Traffic {
        id: usize,
        tx_bytes: u64,
        rx_bytes: u64,
    },
    #[cfg(test)]
    Barrier(tokio::sync::oneshot::Sender<()>),
}

/// Optional, ordered delivery to the single observation consumer. Disabled producers
/// skip constructing payloads. Losing the consumer never affects routing availability.
#[derive(Clone, Default)]
pub(crate) struct Telemetry(Option<mpsc::UnboundedSender<Observation>>);

impl Telemetry {
    pub(crate) fn new(sender: mpsc::UnboundedSender<Observation>) -> Self {
        Self(Some(sender))
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.0.as_ref().is_some_and(|sender| !sender.is_closed())
    }

    pub(crate) fn emit(&self, observation: impl FnOnce() -> Observation) {
        if let Some(sender) = &self.0
            && !sender.is_closed()
        {
            let _ = sender.send(observation());
        }
    }
}

/// Owned by one host worker across reconnects; no shared per-packet counters.
pub(super) struct HostTraffic {
    id: usize,
    tx_bytes: u64,
    rx_bytes: u64,
    telemetry: Telemetry,
}

impl HostTraffic {
    pub(super) fn new(id: usize, telemetry: Telemetry) -> Self {
        Self {
            id,
            tx_bytes: 0,
            rx_bytes: 0,
            telemetry,
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.telemetry.is_enabled()
    }

    pub(super) fn add_tx(&mut self, bytes: usize) {
        self.tx_bytes = self.tx_bytes.saturating_add(bytes as u64);
    }

    pub(super) fn add_rx(&mut self, bytes: usize) {
        self.rx_bytes = self.rx_bytes.saturating_add(bytes as u64);
    }

    pub(super) fn publish(&self) {
        self.telemetry.emit(|| Observation::Traffic {
            id: self.id,
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
        });
    }
}

impl Drop for HostTraffic {
    fn drop(&mut self) {
        self.publish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_or_closed_telemetry_does_not_construct_payloads() {
        Telemetry::default().emit(|| panic!("disabled producer built an event"));
        let (sender, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        Telemetry::new(sender).emit(|| panic!("closed producer built an event"));
    }

    #[test]
    fn traffic_is_absolute_across_publications_and_drop_preserves_last_bytes() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut traffic = HostTraffic::new(3, Telemetry::new(sender));
        traffic.add_tx(10);
        traffic.add_rx(20);
        assert!(
            receiver.try_recv().is_err(),
            "packet accounting sent an event"
        );
        traffic.publish();
        traffic.add_tx(5);
        traffic.add_rx(7);
        drop(traffic);
        assert!(matches!(
            receiver.try_recv().unwrap(),
            Observation::Traffic {
                id: 3,
                tx_bytes: 10,
                rx_bytes: 20
            }
        ));
        assert!(matches!(
            receiver.try_recv().unwrap(),
            Observation::Traffic {
                id: 3,
                tx_bytes: 15,
                rx_bytes: 27
            }
        ));
    }
}
