use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time;

use crate::engine::Worker;
use crate::error::{Result, StackError};
use crate::stream::{StreamEvents, TunnelStream};
use crate::types::{IpVersion, Ipv6Route, StackPhase, StreamEvent, TunnelConfig};

const COMMAND_QUEUE_CAPACITY: usize = 2048;
const CONNECTION_EVENT_QUEUE_CAPACITY: usize = 32;
pub(crate) const STREAM_WRITE_CHUNK_BYTES: usize = 8192;
const STREAM_WRITE_QUEUE_CAPACITY: usize = 256 * 1024 / STREAM_WRITE_CHUNK_BYTES;
const DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(16);
static NEXT_STACK_ID: AtomicU64 = AtomicU64::new(1);

/// Exclusive owner of one tunnel's packet worker.
///
/// Clients receive a restricted [`Stack`] handle. Dropping the owner cancels its
/// worker; normal teardown should call [`Self::shutdown`] and await completion.
pub struct StackOwner {
    client: Stack,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl StackOwner {
    /// Starts and configures a new worker for exactly one VPN session.
    pub async fn start(config: TunnelConfig, io: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let id = NEXT_STACK_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, commands) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let phase = Arc::new(AtomicU8::new(StackPhase::Offline as u8));
        let wake = Arc::new(Notify::new());
        let ipv6_routes = config
            .ipv6
            .as_ref()
            .map_or_else(Vec::new, |ipv6| ipv6.routes.clone());
        let (stop, stopped) = oneshot::channel();
        let (ready, started) = oneshot::channel();
        let worker = Worker {
            id,
            config,
            io,
            commands,
            phase: Arc::clone(&phase),
            wake: Arc::clone(&wake),
            stop: stopped,
            ready,
        };
        let owner = Self {
            client: Stack {
                id,
                tx,
                phase,
                next_id: Arc::new(AtomicU64::new(1)),
                wake,
                ipv6_routes: ipv6_routes.into(),
            },
            stop: Some(stop),
            worker: Some(tokio::spawn(worker.run())),
        };
        if let Err(error) = started.await.unwrap_or(Err(StackError::WorkerStopped)) {
            owner.shutdown().await;
            return Err(error);
        }
        Ok(owner)
    }

    /// Grants connection access without granting lifecycle or packet ingress access.
    pub fn client(&self) -> Stack {
        self.client.clone()
    }

    /// Delivers an IP packet decrypted by the owning VPN session.
    pub fn packet(&self, packet: Vec<u8>) -> Result<()> {
        if !self.client.is_ready() {
            return Err(StackError::VpnDown);
        }
        self.client
            .tx
            .try_send(Command::Packet(packet))
            .map_err(|_| StackError::CommandQueueFull)
    }

    /// Stops the worker even if clients still hold handles, and awaits its exit.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.as_mut() {
            let result = worker.await;
            self.worker.take();
            if let Err(error) = result {
                tracing::error!(%error, "packet stack worker failed");
            }
        }
    }
}

impl Drop for StackOwner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

/// Cloneable connection capability for one immutable VPN session.
#[derive(Clone)]
pub struct Stack {
    id: u64,
    pub(crate) tx: mpsc::Sender<Command>,
    phase: Arc<AtomicU8>,
    next_id: Arc<AtomicU64>,
    wake: Arc<Notify>,
    ipv6_routes: Arc<[Ipv6Route]>,
}

impl Stack {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn is_ready(&self) -> bool {
        self.phase() == StackPhase::Ready
    }
    pub fn supports_ipv6(&self) -> bool {
        self.is_ready() && !self.ipv6_routes.is_empty()
    }

    pub fn can_route_ipv6(&self, address: Ipv6Addr) -> bool {
        !address.is_unspecified()
            && !address.is_multicast()
            && self.is_ready()
            && self.ipv6_routes.iter().any(|route| route.contains(address))
    }

    pub fn phase(&self) -> StackPhase {
        StackPhase::from_raw(self.phase.load(Ordering::Acquire))
    }

    /// Resolves through this session's DNS servers, including mailbox wait in the deadline.
    pub async fn resolve(&self, host: &str, version: IpVersion) -> Result<IpAddr> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        if version == IpVersion::V6 && !self.supports_ipv6() {
            return Err(StackError::NoIpv6Route);
        }
        time::timeout(DNS_RESPONSE_TIMEOUT, async {
            let (reply, received) = oneshot::channel();
            self.tx
                .send(Command::Resolve(host.to_owned(), version, reply))
                .await
                .map_err(|_| StackError::WorkerStopped)?;
            received.await.map_err(|_| StackError::WorkerStopped)?
        })
        .await
        .map_err(|_| StackError::DnsTimeout)?
    }

    /// Connects and returns an independently owned, bidirectional TCP stream.
    /// Dropping a pending connect or its resulting stream releases the socket.
    pub async fn connect(&self, address: SocketAddr) -> Result<TunnelStream> {
        time::timeout(TCP_CONNECT_TIMEOUT, async {
            let (id, mut events) = self.open(address).await?;
            match events.recv().await {
                Some(StreamEvent::Connected) => Ok(TunnelStream::new(id, events)),
                _ => Err(StackError::Disconnected),
            }
        })
        .await
        .map_err(|_| StackError::ConnectTimeout)?
    }

    pub(crate) async fn open(&self, address: SocketAddr) -> Result<(u64, StreamEvents)> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        if let IpAddr::V6(ipv6) = address.ip()
            && !self.can_route_ipv6(ipv6)
        {
            return Err(StackError::NoIpv6Route);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(CONNECTION_EVENT_QUEUE_CAPACITY);
        let (write_tx, write_rx) = mpsc::channel(STREAM_WRITE_QUEUE_CAPACITY);
        let (write_finished, finished) = oneshot::channel();
        let wake_needed = Arc::new(AtomicBool::new(false));
        let events = StreamEvents::new(
            rx,
            Arc::clone(&self.wake),
            Arc::clone(&wake_needed),
            write_tx,
            finished,
        );
        self.tx
            .send(Command::Connect(ConnectRequest {
                id,
                address,
                events: tx,
                wake_needed,
                writes: write_rx,
                write_finished,
            }))
            .await
            .map_err(|_| StackError::WorkerStopped)?;
        Ok((id, events))
    }
}

pub(crate) enum Command {
    Packet(Vec<u8>),
    Resolve(String, IpVersion, oneshot::Sender<Result<IpAddr>>),
    Connect(ConnectRequest),
    #[cfg(test)]
    Close(u64),
}

pub(crate) struct ConnectRequest {
    pub id: u64,
    pub address: SocketAddr,
    pub events: mpsc::Sender<StreamEvent>,
    pub wake_needed: Arc<AtomicBool>,
    pub writes: mpsc::Receiver<Bytes>,
    pub write_finished: oneshot::Sender<()>,
}
