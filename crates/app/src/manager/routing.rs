//! Routing task ownership, request delivery and cancellation-safe leases.
mod state;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ovpn_netstack::Stack;
use ovpn_socks5::DestinationHost;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time;

use super::domain::{HostPhase, StickyKey};
use super::probe::LatencyScore;
use super::telemetry::Telemetry;
pub(super) use state::Host;
use state::{RoutingState, RoutingUpdate};

const STICKY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const ROUTING_COMMAND_QUEUE: usize = 2048;

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
        let state = RoutingState::new(hosts, max_active_vpn_hosts, telemetry);
        let actor = RoutingActor {
            state,
            ready,
            releases,
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
                && !self.state.has_requests()
                && releases.is_empty()
            {
                break;
            }
            let deadline = self.state.idle_deadline();
            tokio::select! {
                _ = &mut stop => break,
                Some(release) = releases.recv() => self.release(release),
                Some(command) = commands.recv() => match command {
                    RoutingCommand::Begin(reply) => {
                        let reservation = accepting.then(|| self.state.begin()).flatten().map(|token| {
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
                            if let Some(token) = reservation.token.take() { self.state.release_pool(token); }
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
                        let _ = reply.send(self.state.request_count());
                    }
                    RoutingCommand::StopAccepting(reply) => {
                        accepting = false;
                        let _ = reply.send(());
                    }
                },
                _ = sweep.tick() => self.state.sweep_sticky(),
                _ = wait_until(deadline) => self.park_pool(),
                else => break,
            }
        }
    }

    fn release(&mut self, release: Release) {
        match release {
            Release::Pool { token, sticky } => {
                if let Some((key, generation, host_id)) = sticky {
                    self.state.release_sticky(&key, generation, host_id);
                }
                self.state.release_pool(token);
            }
            Release::Sticky(key, generation, host_id) => {
                self.state.release_sticky(&key, generation, host_id);
            }
        }
    }

    fn update(&mut self, update: RoutingUpdate) {
        if self.state.update(update) {
            self.notify_ready();
        }
    }

    fn park_pool(&mut self) {
        if self.state.park_pool() {
            self.notify_ready();
        }
    }

    fn notify_ready(&self) {
        self.ready.send_replace(self.state.ready_count());
    }

    fn select(
        &mut self,
        token: u64,
        key: &StickyKey,
        destination: &DestinationHost,
    ) -> SelectReply {
        Ok(self
            .state
            .select(token, key, destination)?
            .map(|route| SelectedRoute {
                stack: route.stack,
                reservation: StickyReservation {
                    releases: self.releases.clone(),
                    sticky: Some((key.clone(), route.generation, route.host_id)),
                },
            }))
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
        let key = StickyKey::new(source, &destination)?;
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
