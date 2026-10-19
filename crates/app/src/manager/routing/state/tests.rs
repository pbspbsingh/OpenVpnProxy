// Policy and lease integration regressions live here to keep state fields private.
use super::super::{
    RoutingActor, RoutingCommand, RoutingOwner, SelectReply, SelectedRoute, StickyReservation,
};
use super::*;
use crate::manager::domain::StickyDestination;
use std::net::IpAddr;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

async fn test_stack() -> (ovpn_netstack::StackOwner, mpsc::Receiver<Vec<u8>>) {
    test_stack_with_ipv6(None).await
}

async fn test_stack_with_ipv6(
    ipv6: Option<ovpn_netstack::Ipv6Config>,
) -> (ovpn_netstack::StackOwner, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel(1024);
    let owner = ovpn_netstack::StackOwner::start(
        ovpn_netstack::TunnelConfig::new(
            "10.8.0.2".parse().unwrap(),
            "10.8.0.1".parse().unwrap(),
            ovpn_dns::ResolverConfig::default(),
            1400,
            ipv6,
        )
        .unwrap(),
        tx,
    )
    .await
    .unwrap();
    (owner, rx)
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
async fn host_selection_weights_load_and_rotates_equal_scores() {
    let (owner, _output) = test_stack().await;
    let mut hosts = vec![
        Host::new("127.0.0.1:1194".parse().unwrap(), true, Some(score(10))),
        Host::new("127.0.0.2:1194".parse().unwrap(), true, Some(score(5))),
    ];
    for host in &mut hosts {
        host.phase = HostPhase::Ready;
        host.stack = Some(owner.client());
    }
    let mut state = RoutingState::new(hosts, 2, Telemetry::default());
    let destination = DestinationHost::Domain("example.com".into());
    state.hosts[1].active = 16;
    assert_eq!(choose_host(&mut state, &destination), Some(0));
    state.hosts[1].active = 0;
    assert_eq!(choose_host(&mut state, &destination), Some(1));

    state.hosts[0].latency_score = Some(Duration::from_millis(5));
    state.next_choice = 0;
    for expected in [0, 1, 0, 1] {
        assert_eq!(choose_host(&mut state, &destination), Some(expected));
    }
    state.hosts[0].selected = false;
    assert_eq!(choose_host(&mut state, &destination), Some(1));
    state.hosts[1].phase = HostPhase::Dormant;
    assert_eq!(choose_host(&mut state, &destination), None);
    owner.shutdown().await;
}

#[tokio::test]
async fn host_selection_prefers_ipv6_for_domains_and_checks_literal_routes() {
    let (v4, _v4_output) = test_stack().await;
    let (v6, _v6_output) = test_stack_with_ipv6(Some(ovpn_netstack::Ipv6Config {
        local: "fd00::2".parse().unwrap(),
        prefix_len: 64,
        routes: vec![ovpn_netstack::Ipv6Route {
            network: "::".parse().unwrap(),
            prefix_len: 0,
            gateway: "fd00::1".parse().unwrap(),
        }],
    }))
    .await;
    let mut hosts = vec![
        Host::new("127.0.0.1:1194".parse().unwrap(), true, Some(score(1))),
        Host::new("127.0.0.2:1194".parse().unwrap(), true, Some(score(20))),
    ];
    for (host, stack) in hosts.iter_mut().zip([v4.client(), v6.client()]) {
        host.phase = HostPhase::Ready;
        host.stack = Some(stack);
    }
    let mut state = RoutingState::new(hosts, 2, Telemetry::default());
    let domain = DestinationHost::Domain("example.com".into());
    let ipv4 = DestinationHost::Ipv4("192.0.2.1".parse().unwrap());
    let ipv6 = DestinationHost::Ipv6("2001:db8::1".parse().unwrap());
    assert_eq!(choose_host(&mut state, &domain), Some(1));
    assert_eq!(choose_host(&mut state, &ipv4), Some(0));
    assert_eq!(choose_host(&mut state, &ipv6), Some(1));

    state.hosts[1].selected = false;
    assert_eq!(choose_host(&mut state, &domain), Some(0));
    assert_eq!(choose_host(&mut state, &ipv6), None);
    v4.shutdown().await;
    v6.shutdown().await;
}

#[tokio::test]
async fn session_failure_clears_assignments_and_wakes_a_ranked_standby() {
    let (ready, _) = watch::channel(0);
    let (releases, _) = mpsc::unbounded_channel();
    let endpoint = "127.0.0.1:1194".parse().unwrap();
    let mut actor = RoutingActor {
        state: RoutingState::new(
            vec![
                Host::new(endpoint, true, Some(score(10))),
                Host::new("127.0.0.2:1194".parse().unwrap(), false, Some(score(20))),
            ],
            1,
            Telemetry::default(),
        ),
        ready,
        releases,
    };
    let token = actor.state.begin().unwrap();
    let epoch = actor.state.pool_epoch.unwrap();
    let (owner, _output) = test_stack().await;
    actor.update(RoutingUpdate::Ready {
        id: 0,
        epoch,
        endpoint,
        stack: owner.client(),
        elapsed: Duration::ZERO,
        score: score(10),
    });
    let destination = DestinationHost::Domain("example.com".into());
    let key = StickyKey::new("127.0.0.1".parse().unwrap(), &destination).unwrap();
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
fn pool_wake_selects_fastest_scored_hosts_and_keeps_others_dormant() {
    let (ready, _) = watch::channel(0);
    let (releases, _) = mpsc::unbounded_channel();
    let preferred = "127.0.0.2:443".parse().unwrap();
    let mut actor = RoutingActor {
        state: RoutingState::new(
            vec![
                Host::new("127.0.0.1:1194".parse().unwrap(), true, Some(score(20))),
                Host::new(preferred, false, Some(score(10))),
                Host::new("127.0.0.3:1194".parse().unwrap(), false, Some(score(5))),
                Host::new("127.0.0.4:1194".parse().unwrap(), false, None),
            ],
            2,
            Telemetry::default(),
        ),
        ready,
        releases,
    };
    actor.state.begin().unwrap();
    assert!(!actor.state.hosts[0].selected);
    assert!(actor.state.hosts[1].selected);
    assert!(actor.state.hosts[2].selected);
    assert!(!actor.state.hosts[3].selected);
    assert_eq!(
        *actor.state.hosts[0].enabled.borrow(),
        HostActivation::Dormant
    );
    assert_eq!(
        *actor.state.hosts[3].enabled.borrow(),
        HostActivation::Dormant
    );
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

#[tokio::test]
async fn old_readiness_and_probe_cannot_replace_current_session() {
    let (ready, _) = watch::channel(0);
    let (releases, _) = mpsc::unbounded_channel();
    let endpoint = "127.0.0.1:1194".parse().unwrap();
    let mut actor = RoutingActor {
        state: RoutingState::new(
            vec![Host::new(endpoint, true, Some(score(20)))],
            1,
            Telemetry::default(),
        ),
        ready,
        releases,
    };
    actor.state.hosts[0]
        .enabled
        .send_replace(HostActivation::Active {
            epoch: 2,
            preferred_endpoint: endpoint,
        });
    let (old, _old_output) = test_stack().await;
    let (current, _current_output) = test_stack().await;
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
        state: RoutingState::new(
            vec![Host::new("127.0.0.1:1194".parse().unwrap(), true, None)],
            1,
            Telemetry::default(),
        ),
        ready,
        releases,
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
    actor.state.release_sticky(&key, 1, 0);
    assert_eq!(actor.state.hosts[0].active, 1);
    assert_eq!(actor.state.sticky[&key].active, 1);
    actor.state.release_sticky(&key, 2, 0);
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
        state: RoutingState::new(
            vec![Host::new("127.0.0.1:1194".parse().unwrap(), true, None)],
            1,
            Telemetry::default(),
        ),
        ready,
        releases: releases.clone(),
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
    let (stack_owner, _output) = test_stack().await;
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
        state: RoutingState::new(
            vec![Host::new(endpoint, true, Some(score(20)))],
            1,
            Telemetry::default(),
        ),
        ready,
        releases,
    };
    actor.state.telemetry = telemetry.clone();
    telemetry.emit(|| Observation::Initialized {
        hosts: vec![actor.state.host_observation(0)],
        max_active_hosts: 1,
    });
    let token = actor.state.begin().unwrap();
    let (stack, _output) = test_stack().await;
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
    let key = StickyKey::new("127.0.0.1".parse().unwrap(), &destination).unwrap();
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
    actor.state.release_pool(token);
    view.flush_observations().await;
    let snapshot = view.snapshot().await;
    assert_eq!(snapshot.pool.active_routes, 0);
    assert!(matches!(snapshot.pool.phase, ovpn_ui::PoolPhase::Idle));
    actor.state.pool_idle_since = Some(Instant::now() - POOL_IDLE_TIMEOUT);
    actor.park_pool();
    view.flush_observations().await;
    let snapshot = view.snapshot().await;
    assert!(matches!(snapshot.pool.phase, ovpn_ui::PoolPhase::Dormant));
    assert_eq!(snapshot.pool.sticky_groups, 0);
    drop(actor);
    stack.shutdown().await;
    dashboard.shutdown().await;
}
