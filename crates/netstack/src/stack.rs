use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time;

use crate::engine::run;
use crate::error::{Result, StackError};
use crate::types::{StackPhase, StreamEvent, TunnelConfig};

pub(crate) enum Command {
    Configure(
        TunnelConfig,
        mpsc::Sender<Vec<u8>>,
        oneshot::Sender<Result<()>>,
    ),
    Packet(Vec<u8>),
    Reset,
    Resolve(String, oneshot::Sender<Result<Ipv4Addr>>),
    Connect(u64, SocketAddrV4, mpsc::Sender<StreamEvent>),
    Data(u64, Vec<u8>),
    Close(u64),
}

#[derive(Clone)]
pub struct Stack {
    tx: mpsc::Sender<Command>,
    phase: Arc<AtomicU8>,
    next_id: Arc<AtomicU64>,
}

impl Stack {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel(2048);
        let phase = Arc::new(AtomicU8::new(StackPhase::Offline as u8));
        let worker_phase = phase.clone();
        tokio::spawn(run(rx, worker_phase));
        Self {
            tx,
            phase,
            next_id: Arc::new(AtomicU64::new(1)),
        }
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
        time::timeout(Duration::from_secs(5), rx)
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
        time::timeout(Duration::from_secs(12), rx)
            .await
            .map_err(|_| StackError::DnsTimeout)?
            .map_err(|_| StackError::WorkerStopped)?
    }

    pub async fn connect(
        &self,
        address: SocketAddrV4,
    ) -> Result<(u64, mpsc::Receiver<StreamEvent>)> {
        if !self.is_ready() {
            return Err(StackError::VpnDown);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(32);
        self.tx
            .send(Command::Connect(id, address, tx))
            .await
            .map_err(|_| StackError::WorkerStopped)?;
        Ok((id, rx))
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
