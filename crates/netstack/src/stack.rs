use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time;

use crate::engine::run;
use crate::error::{Result, StackError};
use crate::types::{StackPhase, StreamEvent, TunnelConfig};

const COMMAND_QUEUE_CAPACITY: usize = 2048;
const CONNECTION_EVENT_QUEUE_CAPACITY: usize = 32;
const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);
static NEXT_STACK_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) enum Command {
    Configure(
        TunnelConfig,
        mpsc::Sender<Vec<u8>>,
        oneshot::Sender<Result<()>>,
    ),
    Packet(Vec<u8>),
    Reset,
    Resolve(String, oneshot::Sender<Result<Ipv4Addr>>),
    Connect(
        u64,
        SocketAddrV4,
        mpsc::Sender<StreamEvent>,
        Arc<AtomicBool>,
    ),
    Data(u64, Vec<u8>),
    Close(u64),
}

pub struct StreamEvents {
    rx: mpsc::Receiver<StreamEvent>,
    wake: Arc<Notify>,
    wake_needed: Arc<AtomicBool>,
}

impl StreamEvents {
    pub async fn recv(&mut self) -> Option<StreamEvent> {
        let event = self.rx.recv().await;
        if event.is_some() && self.wake_needed.swap(false, Ordering::AcqRel) {
            self.wake.notify_one();
        }
        event
    }
}

impl Drop for StreamEvents {
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

#[derive(Clone)]
pub struct Stack {
    id: u64,
    tx: mpsc::Sender<Command>,
    phase: Arc<AtomicU8>,
    next_id: Arc<AtomicU64>,
    wake: Arc<Notify>,
}

impl Stack {
    pub fn start() -> Self {
        let id = NEXT_STACK_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let phase = Arc::new(AtomicU8::new(StackPhase::Offline as u8));
        let worker_phase = phase.clone();
        let wake = Arc::new(Notify::new());
        tokio::spawn(run(id, rx, worker_phase, Arc::clone(&wake)));
        Self {
            id,
            tx,
            phase,
            next_id: Arc::new(AtomicU64::new(1)),
            wake,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_ready(&self) -> bool {
        self.phase() == StackPhase::Ready
    }

    pub fn phase(&self) -> StackPhase {
        StackPhase::from_raw(self.phase.load(Ordering::Acquire))
    }

    pub fn activate(&self) -> Result<()> {
        self.phase
            .compare_exchange(
                StackPhase::Configured as u8,
                StackPhase::Ready as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| StackError::InvalidState)
    }

    pub async fn configure(&self, config: TunnelConfig, io: mpsc::Sender<Vec<u8>>) -> Result<()> {
        self.phase
            .store(StackPhase::Offline as u8, Ordering::Release);
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Configure(config, io, tx))
            .await
            .map_err(|_| StackError::WorkerStopped)?;
        time::timeout(CONFIGURATION_TIMEOUT, rx)
            .await
            .map_err(|_| StackError::ConfigurationTimeout)?
            .map_err(|_| StackError::WorkerStopped)?
    }

    pub fn packet(&self, packet: &[u8]) -> Result<()> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        if self.tx.try_send(Command::Packet(packet.to_vec())).is_err() {
            self.phase
                .store(StackPhase::Failed as u8, Ordering::Release);
            tracing::error!(
                "packet stack command queue rejected a VPN packet; tunnel marked failed"
            );
            return Err(StackError::CommandQueueFull);
        }
        Ok(())
    }

    pub async fn reset(&self) -> Result<()> {
        self.phase
            .store(StackPhase::Offline as u8, Ordering::Release);
        self.tx
            .send(Command::Reset)
            .await
            .map_err(|_| StackError::WorkerStopped)
    }

    pub async fn resolve(&self, host: &str) -> Result<Ipv4Addr> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::Resolve(host.to_owned(), tx))
            .await
            .map_err(|_| StackError::WorkerStopped)?;
        time::timeout(DNS_RESPONSE_TIMEOUT, rx)
            .await
            .map_err(|_| StackError::DnsTimeout)?
            .map_err(|_| StackError::WorkerStopped)?
    }

    pub async fn connect(&self, address: SocketAddrV4) -> Result<(u64, StreamEvents)> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(CONNECTION_EVENT_QUEUE_CAPACITY);
        let wake_needed = Arc::new(AtomicBool::new(false));
        self.tx
            .send(Command::Connect(id, address, tx, Arc::clone(&wake_needed)))
            .await
            .map_err(|_| StackError::WorkerStopped)?;
        Ok((
            id,
            StreamEvents {
                rx,
                wake: Arc::clone(&self.wake),
                wake_needed,
            },
        ))
    }

    pub fn data(&self, id: u64, data: Vec<u8>) -> Result<()> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        self.tx.try_send(Command::Data(id, data)).map_err(|_| {
            self.phase
                .store(StackPhase::Failed as u8, Ordering::Release);
            tracing::error!(
                id,
                "packet stack command queue rejected TCP data; tunnel marked failed"
            );
            StackError::CommandQueueFull
        })
    }

    pub fn close(&self, id: u64) -> Result<()> {
        self.tx.try_send(Command::Close(id)).map_err(|_| {
            self.phase
                .store(StackPhase::Failed as u8, Ordering::Release);
            tracing::error!(
                id,
                "packet stack command queue rejected TCP close; tunnel marked failed"
            );
            StackError::CommandQueueFull
        })
    }
}
