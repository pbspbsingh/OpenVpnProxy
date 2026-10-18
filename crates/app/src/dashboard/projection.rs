//! Dashboard-owned read model. No routing handles, stacks, or shared counters.
use std::collections::{BTreeMap, HashMap};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ovpn_ui::{
    DashboardSnapshot, GroupPage, GroupSnapshot, HostPhase as UiHostPhase, HostSnapshot, PoolPhase,
    PoolSnapshot,
};

use crate::manager::domain::{
    HostPhase, POOL_IDLE_TIMEOUT, STICKY_IDLE_TIMEOUT, StickyDestination, StickyKey,
};
use crate::manager::telemetry::{HostObservation, Observation, PoolObservation};

pub(super) enum Lifecycle {
    Unconfigured,
    Starting(&'static str),
    Running,
    Failed(String),
}

struct HostView {
    state: HostObservation,
    tx_bytes: u64,
    rx_bytes: u64,
}

struct Assignment {
    host_id: usize,
    active: usize,
    idle_since: Option<Instant>,
    // Display order is computed only when an assignment is first observed.
    display: (String, String),
}

pub(super) struct Projection {
    pub lifecycle: Lifecycle,
    pub configuration: ovpn_ui::ConfigurationStatus,
    hosts: Vec<HostView>,
    pool: PoolObservation,
    max_active_hosts: usize,
    assignments: HashMap<StickyKey, Assignment>,
    groups_by_host: Vec<BTreeMap<(String, String), StickyKey>>,
}

impl Projection {
    pub fn new() -> Self {
        Self {
            lifecycle: Lifecycle::Starting("Starting proxy"),
            configuration: ovpn_ui::ConfigurationStatus::default(),
            hosts: Vec::new(),
            pool: PoolObservation::default(),
            max_active_hosts: 0,
            assignments: HashMap::new(),
            groups_by_host: Vec::new(),
        }
    }

    pub fn observe(&mut self, observation: Observation) {
        match observation {
            Observation::Initialized {
                hosts,
                max_active_hosts,
            } => {
                self.max_active_hosts = max_active_hosts;
                self.groups_by_host = (0..hosts.len()).map(|_| BTreeMap::new()).collect();
                self.hosts = hosts
                    .into_iter()
                    .map(|state| HostView {
                        state,
                        tx_bytes: 0,
                        rx_bytes: 0,
                    })
                    .collect();
                self.assignments.clear();
                self.pool = PoolObservation::default();
            }
            Observation::Host { id, state } => self.hosts[id].state = state,
            Observation::Pool(pool) => self.pool = pool,
            Observation::Traffic {
                id,
                tx_bytes,
                rx_bytes,
            } => {
                self.hosts[id].tx_bytes = tx_bytes;
                self.hosts[id].rx_bytes = rx_bytes;
            }
            Observation::Assignment {
                key,
                host_id,
                active,
                idle_since,
            } => {
                if self
                    .assignments
                    .get(&key)
                    .is_some_and(|entry| entry.host_id != host_id)
                {
                    self.remove(&key);
                }
                let entry = match self.assignments.entry(key) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let key = entry.key();
                        let destination = match &key.destination {
                            StickyDestination::Ip(ip) => ip.to_string(),
                            StickyDestination::Domain(domain) => domain.clone(),
                        };
                        let display = (destination, key.source.to_string());
                        self.groups_by_host[host_id].insert(display.clone(), key.clone());
                        entry.insert(Assignment {
                            host_id,
                            active,
                            idle_since,
                            display,
                        })
                    }
                };
                entry.active = active;
                entry.idle_since = idle_since;
            }
            Observation::AssignmentRemoved(key) => self.remove(&key),
            Observation::HostAssignmentsCleared(id) => {
                for (_, key) in std::mem::take(&mut self.groups_by_host[id]) {
                    self.assignments.remove(&key);
                }
            }
            Observation::AssignmentsCleared => {
                self.assignments.clear();
                for groups in &mut self.groups_by_host {
                    groups.clear();
                }
            }
            Observation::Barrier(reply) => {
                let _ = reply.send(());
            }
        }
    }

    fn remove(&mut self, key: &StickyKey) {
        if let Some(entry) = self.assignments.remove(key) {
            self.groups_by_host[entry.host_id].remove(&entry.display);
        }
    }

    pub fn snapshot(&self, now: Instant) -> DashboardSnapshot {
        let mut tx_bytes = 0_u64;
        let mut rx_bytes = 0_u64;
        let mut ready_hosts = 0;
        let mut selected_hosts = 0;
        let mut active_routes = 0_usize;
        let hosts = self
            .hosts
            .iter()
            .enumerate()
            .map(|(id, view)| {
                let host = &view.state;
                tx_bytes = tx_bytes.saturating_add(view.tx_bytes);
                rx_bytes = rx_bytes.saturating_add(view.rx_bytes);
                ready_hosts += usize::from(host.ready);
                selected_hosts += usize::from(host.selected);
                active_routes = active_routes.saturating_add(host.active_routes);
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
                    active_routes: host.active_routes,
                    sticky_groups: self.groups_by_host[id].len(),
                    latency_ms: host.latency_score.map(|score| score.as_secs_f64() * 1000.0),
                    score_age_seconds: host
                        .score_measured_at
                        .map(|at| now.saturating_duration_since(at).as_secs()),
                    ipv6: host.ipv6,
                    tx_bytes: view.tx_bytes,
                    rx_bytes: view.rx_bytes,
                }
            })
            .collect();
        let phase = if !self.pool.awake {
            PoolPhase::Dormant
        } else if !self.pool.has_requests {
            PoolPhase::Idle
        } else if ready_hosts == 0 {
            PoolPhase::Waking
        } else if ready_hosts < selected_hosts {
            PoolPhase::Degraded
        } else {
            PoolPhase::Ready
        };
        let (phase, message) = match &self.lifecycle {
            Lifecycle::Unconfigured => (
                PoolPhase::Unconfigured,
                Some("No configuration active; add or activate one in Configuration".into()),
            ),
            Lifecycle::Starting(stage) => (PoolPhase::Starting, Some((*stage).to_owned())),
            Lifecycle::Running => (phase, None),
            Lifecycle::Failed(error) => (PoolPhase::Failed, Some(error.clone())),
        };
        DashboardSnapshot {
            version: 1,
            sampled_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or_default(),
            message,
            configuration: self.configuration.clone(),
            pool: PoolSnapshot {
                phase,
                candidate_hosts: self.hosts.len(),
                selected_hosts,
                ready_hosts,
                max_active_hosts: self.max_active_hosts,
                active_routes,
                sticky_groups: self.assignments.len(),
                idle_remaining_seconds: self.pool.idle_since.map(|since| {
                    POOL_IDLE_TIMEOUT
                        .saturating_sub(now.saturating_duration_since(since))
                        .as_secs()
                }),
                tx_bytes,
                rx_bytes,
            },
            hosts,
        }
    }

    pub fn group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
        now: Instant,
    ) -> Option<GroupPage> {
        let groups = self.groups_by_host.get(host_id)?;
        let page = groups
            .iter()
            .skip(offset)
            .take(limit)
            .map(|((destination, source), key)| {
                let entry = &self.assignments[key];
                GroupSnapshot {
                    source: source.clone(),
                    destination: destination.clone(),
                    active_connections: entry.active,
                    idle_remaining_seconds: entry.idle_since.map(|since| {
                        STICKY_IDLE_TIMEOUT
                            .saturating_sub(now.saturating_duration_since(since))
                            .as_secs()
                    }),
                }
            })
            .collect();
        Some(GroupPage {
            total: groups.len(),
            offset,
            groups: page,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn host(now: Instant) -> HostObservation {
        HostObservation {
            endpoint: "127.0.0.1:1194".parse().unwrap(),
            phase: HostPhase::Ready,
            selected: true,
            active_routes: 1,
            latency_score: Some(Duration::from_millis(20)),
            score_measured_at: Some(now),
            ready: true,
            ipv6: true,
        }
    }

    fn model(now: Instant) -> Projection {
        let mut model = Projection::new();
        model.observe(Observation::Initialized {
            hosts: vec![host(now), host(now)],
            max_active_hosts: 2,
        });
        model.lifecycle = Lifecycle::Running;
        model
    }

    fn key(destination: &str) -> StickyKey {
        StickyKey {
            source: "127.0.0.1".parse().unwrap(),
            destination: destination
                .parse()
                .map(StickyDestination::Ip)
                .unwrap_or_else(|_| StickyDestination::Domain(destination.into())),
        }
    }

    fn assign(
        model: &mut Projection,
        destination: &str,
        host_id: usize,
        active: usize,
        idle_since: Option<Instant>,
    ) {
        model.observe(Observation::Assignment {
            key: key(destination),
            host_id,
            active,
            idle_since,
        });
    }

    #[test]
    fn assignment_updates_reassignment_and_bulk_removal_keep_indices_consistent() {
        let now = Instant::now();
        let mut model = model(now);
        assign(&mut model, "example.com", 0, 2, None);
        assign(&mut model, "example.com", 0, 0, Some(now));
        assert_eq!(model.snapshot(now).pool.sticky_groups, 1);
        let page = model
            .group_page(0, 0, 100, now + Duration::from_secs(7))
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.groups[0].active_connections, 0);
        assert_eq!(
            page.groups[0].idle_remaining_seconds,
            Some(STICKY_IDLE_TIMEOUT.as_secs() - 7)
        );
        assign(&mut model, "example.com", 1, 1, None);
        assign(&mut model, "other.com", 0, 1, None);
        assert_eq!(model.snapshot(now).pool.sticky_groups, 2);
        assert_eq!(model.group_page(0, 0, 100, now).unwrap().total, 1);
        model.observe(Observation::HostAssignmentsCleared(0));
        assert_eq!(model.snapshot(now).pool.sticky_groups, 1);
        assert_eq!(
            model.group_page(1, 0, 100, now).unwrap().groups[0].destination,
            "example.com"
        );
        model.observe(Observation::AssignmentRemoved(key("example.com")));
        assert_eq!(model.snapshot(now).pool.sticky_groups, 0);
        assign(&mut model, "new.com", 0, 1, None);
        model.observe(Observation::AssignmentsCleared);
        assert!(model.group_page(0, 0, 100, now).unwrap().groups.is_empty());
        assert!(model.assignments.is_empty());
    }

    #[test]
    fn pagination_preserves_display_order_and_handles_missing_hosts_and_large_offsets() {
        let now = Instant::now();
        let mut model = model(now);
        for destination in ["10.0.0.2", "abc.com", "10.0.0.10"] {
            assign(&mut model, destination, 0, 1, None);
        }
        let page = model.group_page(0, 1, 1, now).unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.groups.len(), 1);
        assert_eq!(page.groups[0].destination, "10.0.0.2");
        assert!(model.group_page(2, 0, 100, now).is_none());
        assert!(
            model
                .group_page(0, usize::MAX, 100, now)
                .unwrap()
                .groups
                .is_empty()
        );
    }

    #[test]
    fn phase_and_time_derived_metrics_follow_local_observations() {
        let now = Instant::now();
        let mut model = model(now);
        assert!(matches!(model.snapshot(now).pool.phase, PoolPhase::Dormant));
        model.observe(Observation::Pool(PoolObservation {
            awake: true,
            has_requests: true,
            idle_since: None,
        }));
        assert!(matches!(model.snapshot(now).pool.phase, PoolPhase::Ready));
        let mut second = host(now);
        second.ready = false;
        second.phase = HostPhase::Connecting;
        model.observe(Observation::Host {
            id: 1,
            state: second,
        });
        model.observe(Observation::Traffic {
            id: 0,
            tx_bytes: 20,
            rx_bytes: 100,
        });
        model.observe(Observation::Traffic {
            id: 1,
            tx_bytes: 30,
            rx_bytes: 200,
        });
        let snapshot = model.snapshot(now + Duration::from_secs(8));
        assert!(matches!(snapshot.pool.phase, PoolPhase::Degraded));
        assert_eq!(snapshot.pool.active_routes, 2);
        assert_eq!(snapshot.pool.tx_bytes, 50);
        assert_eq!(snapshot.pool.rx_bytes, 300);
        assert_eq!(snapshot.hosts[0].score_age_seconds, Some(8));
        assert_eq!(snapshot.hosts[0].latency_ms, Some(20.0));
        assert!(snapshot.hosts[0].ipv6);
        let mut first = host(now);
        first.ready = false;
        model.observe(Observation::Host {
            id: 0,
            state: first,
        });
        assert!(matches!(model.snapshot(now).pool.phase, PoolPhase::Waking));
        model.observe(Observation::Pool(PoolObservation {
            awake: true,
            has_requests: false,
            idle_since: Some(now),
        }));
        let later = model.snapshot(now + Duration::from_secs(10));
        assert!(matches!(later.pool.phase, PoolPhase::Idle));
        assert_eq!(
            later.pool.idle_remaining_seconds,
            Some(POOL_IDLE_TIMEOUT.as_secs() - 10)
        );
        model.lifecycle = Lifecycle::Failed("routing stopped".into());
        let failed = model.snapshot(now);
        assert!(matches!(failed.pool.phase, PoolPhase::Failed));
        assert_eq!(failed.message.as_deref(), Some("routing stopped"));
        assert_eq!(failed.pool.rx_bytes, 300);
    }
}
