mod projection;

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use ovpn_profile::Profile;
use ovpn_ui::{
    DashboardHistory, DashboardSource, GroupError, GroupPage, ProfileRemote, ProfileSummary,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time;

use crate::manager::telemetry::{Observation, Telemetry};
use projection::{Lifecycle, Projection};

const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);

/// Owns the aggregation task. Request handles do not extend its lifetime.
pub(crate) struct Dashboard {
    handle: DashboardHandle,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub(crate) struct DashboardHandle {
    requests: mpsc::UnboundedSender<Request>,
    telemetry: Telemetry,
    frames: watch::Receiver<String>,
    profile: watch::Receiver<ProfileSummary>,
}

enum Request {
    Lifecycle(Lifecycle),
    Profile(ProfileSummary),
    Groups {
        host_id: usize,
        offset: usize,
        limit: usize,
        reply: oneshot::Sender<Option<GroupPage>>,
    },
    #[cfg(test)]
    Snapshot(oneshot::Sender<ovpn_ui::DashboardSnapshot>),
}

struct DashboardActor {
    projection: Projection,
    history: DashboardHistory,
    frames: watch::Sender<String>,
    profile: watch::Sender<ProfileSummary>,
}

impl Dashboard {
    pub(crate) fn start() -> Result<Self, ovpn_ui::UiError> {
        let projection = Projection::new();
        let mut history = DashboardHistory::new();
        let initial = history.serialize(projection.snapshot(Instant::now()))?;
        let (frames, feed) = watch::channel(initial);
        let (profile, current_profile) = watch::channel(ProfileSummary::default());
        let (events, observations) = mpsc::unbounded_channel();
        let (requests, inbox) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let actor = DashboardActor {
            projection,
            history,
            frames,
            profile,
        };
        Ok(Self {
            handle: DashboardHandle {
                requests,
                telemetry: Telemetry::new(events),
                frames: feed,
                profile: current_profile,
            },
            stop: Some(stop),
            worker: Some(tokio::spawn(actor.run(observations, inbox, stopped))),
        })
    }

    pub(crate) fn handle(&self) -> DashboardHandle {
        self.handle.clone()
    }

    pub(crate) async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.as_mut() {
            let result = worker.await;
            self.worker.take();
            if let Err(error) = result {
                tracing::error!(%error, "dashboard actor failed during shutdown");
            }
        }
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

impl DashboardHandle {
    pub(crate) fn telemetry(&self) -> Telemetry {
        self.telemetry.clone()
    }
    pub(crate) fn starting(&self, stage: &'static str) {
        self.lifecycle(Lifecycle::Starting(stage));
    }
    pub(crate) fn running(&self) {
        self.lifecycle(Lifecycle::Running);
    }
    pub(crate) fn failed(&self, error: String) {
        self.lifecycle(Lifecycle::Failed(error));
    }
    fn lifecycle(&self, state: Lifecycle) {
        let _ = self.requests.send(Request::Lifecycle(state));
    }
    pub(crate) fn profile_loaded(&self, profile: ProfileSummary) {
        let _ = self.requests.send(Request::Profile(profile));
    }
}

impl DashboardActor {
    async fn run(
        mut self,
        mut observations: mpsc::UnboundedReceiver<Observation>,
        mut requests: mpsc::UnboundedReceiver<Request>,
        mut stop: oneshot::Receiver<()>,
    ) {
        let mut tick =
            time::interval_at(time::Instant::now() + SNAPSHOT_INTERVAL, SNAPSHOT_INTERVAL);
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                Some(event) = observations.recv() => self.projection.observe(event),
                Some(request) = requests.recv() => match request {
                    Request::Lifecycle(state) => { self.projection.lifecycle = state; self.publish(); }
                    Request::Profile(profile) => { self.profile.send_replace(profile); }
                    Request::Groups { host_id, offset, limit, reply } => {
                        let _ = reply.send(self.projection.group_page(host_id, offset, limit, Instant::now()));
                    }
                    #[cfg(test)]
                    Request::Snapshot(reply) => { let _ = reply.send(self.projection.snapshot(Instant::now())); }
                },
                _ = tick.tick() => self.publish(),
            }
        }
        // Core producers are stopped first. Preserve their final counters in the last frame.
        observations.close();
        while let Some(event) = observations.recv().await {
            self.projection.observe(event);
        }
        self.publish();
    }

    fn publish(&mut self) {
        match self
            .history
            .serialize(self.projection.snapshot(Instant::now()))
        {
            Ok(frame) => {
                self.frames.send_replace(frame);
            }
            Err(error) => tracing::error!(%error, "dashboard snapshot serialization failed"),
        }
    }
}

impl DashboardSource for DashboardHandle {
    fn subscribe(&self) -> watch::Receiver<String> {
        self.frames.clone()
    }

    fn group_page(
        &self,
        host_id: usize,
        offset: usize,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Option<GroupPage>, GroupError>> + Send + '_>> {
        Box::pin(async move {
            let (reply, received) = oneshot::channel();
            self.requests
                .send(Request::Groups {
                    host_id,
                    offset,
                    limit,
                    reply,
                })
                .map_err(|_| GroupError::Unavailable)?;
            received.await.map_err(|_| GroupError::Unavailable)
        })
    }

    fn profile(&self) -> ProfileSummary {
        self.profile.borrow().clone()
    }
}

pub(crate) fn summarize_profile(profile: &Profile) -> ProfileSummary {
    ProfileSummary {
        remotes: profile
            .remotes
            .iter()
            .map(|(host, port)| ProfileRemote {
                host: host.clone(),
                port: *port,
            })
            .collect(),
        credentials_required: profile.needs_credentials,
        ipv6_blocked: profile.block_ipv6,
        server_certificate_purpose_required: profile.require_server_certificate_purpose,
        renegotiate_after_seconds: profile.renegotiate_after.map(|duration| duration.as_secs()),
        handshake_window_seconds: profile.handshake_window.as_secs(),
        transition_window_seconds: profile.transition_window.as_secs(),
    }
}

#[cfg(test)]
impl DashboardHandle {
    pub(crate) async fn flush_observations(&self) {
        let (reply, received) = oneshot::channel();
        self.telemetry.emit(|| Observation::Barrier(reply));
        received.await.unwrap();
    }

    pub(crate) async fn snapshot(&self) -> ovpn_ui::DashboardSnapshot {
        let (reply, received) = oneshot::channel();
        self.requests.send(Request::Snapshot(reply)).unwrap();
        received.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::telemetry::{HostObservation, HostPhase, StickyDestination, StickyKey};

    fn initialize(telemetry: &Telemetry) {
        telemetry.emit(|| Observation::Initialized {
            hosts: vec![HostObservation {
                endpoint: "127.0.0.1:1194".parse().unwrap(),
                phase: HostPhase::Dormant,
                selected: true,
                active_routes: 0,
                latency_score: None,
                score_measured_at: None,
                ready: false,
                ipv6: false,
            }],
            max_active_hosts: 1,
        });
    }

    #[tokio::test]
    async fn dashboard_serves_its_own_state_after_producers_stop_and_shuts_down_with_live_handles()
    {
        let dashboard = Dashboard::start().unwrap();
        let handle = dashboard.handle();
        let telemetry = handle.telemetry();
        initialize(&telemetry);
        telemetry.emit(|| Observation::Assignment {
            key: StickyKey {
                source: "127.0.0.1".parse().unwrap(),
                destination: StickyDestination::Domain("example.com".into()),
            },
            host_id: 0,
            active: 1,
            idle_since: None,
        });
        telemetry.emit(|| Observation::Traffic {
            id: 0,
            tx_bytes: 25,
            rx_bytes: 100,
        });
        handle.flush_observations().await;
        drop(telemetry);
        handle.running();
        handle.profile_loaded(ProfileSummary {
            credentials_required: true,
            ..ProfileSummary::default()
        });
        handle.failed("core stopped".into());
        let snapshot = handle.snapshot().await;
        assert!(matches!(snapshot.pool.phase, ovpn_ui::PoolPhase::Failed));
        assert_eq!(snapshot.pool.rx_bytes, 100);
        assert_eq!(snapshot.pool.sticky_groups, 1);
        assert!(handle.profile().credentials_required);
        assert_eq!(
            handle.group_page(0, 0, 100).await.unwrap().unwrap().total,
            1
        );
        tokio::time::timeout(Duration::from_secs(1), dashboard.shutdown())
            .await
            .unwrap();
        assert!(matches!(
            handle.group_page(0, 0, 100).await,
            Err(GroupError::Unavailable)
        ));
        assert!(!handle.telemetry().is_enabled());
    }

    #[tokio::test]
    async fn periodic_feed_publishes_observations_without_requests_from_the_ui() {
        let dashboard = Dashboard::start().unwrap();
        let handle = dashboard.handle();
        let mut frames = handle.subscribe();
        initialize(&handle.telemetry());
        handle.flush_observations().await;
        frames.borrow_and_update();
        tokio::time::timeout(SNAPSHOT_INTERVAL + Duration::from_secs(2), frames.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(frames.borrow().contains("127.0.0.1:1194"));
        dashboard.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_drains_pending_observations_into_final_frame() {
        let dashboard = Dashboard::start().unwrap();
        let handle = dashboard.handle();
        let mut frames = handle.subscribe();
        let telemetry = handle.telemetry();
        initialize(&telemetry);
        telemetry.emit(|| Observation::Traffic {
            id: 0,
            tx_bytes: 12,
            rx_bytes: 345,
        });
        dashboard.shutdown().await;
        let final_frame = frames.borrow_and_update();
        assert!(final_frame.contains("\"rx_bytes\":345"));
    }
}
