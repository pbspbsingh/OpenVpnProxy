use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::time::{Duration, Instant};

use rustls::ClientConnection;
use tokio::net::UdpSocket;
use tokio::time;

use crate::error::{Error, Result};
use crate::tlscrypt::TlsCrypt;

macro_rules! ensure {
    ($condition:expr, $message:literal) => {
        crate::error::require($condition, $message)?
    };
}

const HARD_RESET_CLIENT: u8 = 7;
const HARD_RESET_SERVER: u8 = 8;
const CONTROL: u8 = 4;
const ACK: u8 = 5;
const DATA: u8 = 9;
const TLS_CHUNK: usize = 1200;

struct Pending {
    opcode: u8,
    body: Vec<u8>,
    last_sent: Instant,
    attempts: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlPhase {
    AwaitingServerReset,
    TlsHandshake,
    ApplicationData,
}

pub struct Link {
    socket: UdpSocket,
    crypt: TlsCrypt,
    local_sid: u64,
    remote_sid: Option<u64>,
    phase: ControlPhase,
    next_tx: u32,
    next_rx: u32,
    pending: BTreeMap<u32, Pending>,
    reordered: BTreeMap<u32, Vec<u8>>,
    acks: VecDeque<u32>,
    unsent_tls: VecDeque<Vec<u8>>,
    tls: ClientConnection,
    app: Vec<u8>,
    last_received: Instant,
}

impl Link {
    pub async fn new(socket: UdpSocket, key: &[u8; 256], tls: ClientConnection) -> Result<Self> {
        let mut sid = [0; 8];
        getrandom::fill(&mut sid).map_err(Error::Randomness)?;
        let mut link = Self {
            socket,
            crypt: TlsCrypt::client(key),
            local_sid: u64::from_be_bytes(sid),
            remote_sid: None,
            phase: ControlPhase::AwaitingServerReset,
            next_tx: 0,
            next_rx: 0,
            pending: BTreeMap::new(),
            reordered: BTreeMap::new(),
            acks: VecDeque::new(),
            unsent_tls: VecDeque::new(),
            tls,
            app: Vec::new(),
            last_received: Instant::now(),
        };
        link.queue(HARD_RESET_CLIENT, &[]).await?;
        Ok(link)
    }

    async fn queue(&mut self, opcode: u8, body: &[u8]) -> Result<()> {
        ensure!(self.pending.len() < 12, "control transmit window full");
        let pid = self.next_tx;
        self.next_tx = self
            .next_tx
            .checked_add(1)
            .ok_or(Error::PacketIdExhausted)?;
        self.pending.insert(
            pid,
            Pending {
                opcode,
                body: body.to_vec(),
                last_sent: Instant::now(),
                attempts: 1,
            },
        );
        self.send_control(opcode, pid, body).await
    }

    async fn send_control(&mut self, opcode: u8, pid: u32, body: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(22 + body.len());
        let count = self.acks.len().min(8);
        payload.push(count as u8);
        for _ in 0..count {
            if let Some(ack) = self.acks.pop_front() {
                payload.extend_from_slice(&ack.to_be_bytes());
            }
        }
        if count > 0 {
            payload.extend_from_slice(
                &self
                    .remote_sid
                    .ok_or(Error::Protocol("ACK without server session"))?
                    .to_be_bytes(),
            );
        }
        payload.extend_from_slice(&pid.to_be_bytes());
        payload.extend_from_slice(body);
        self.send_wrapped(opcode, &payload).await
    }

    async fn send_wrapped(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let wire = self.crypt.wrap(opcode << 3, self.local_sid, payload)?;
        let sent = self.socket.send(&wire).await?;
        ensure!(sent == wire.len(), "short VPN UDP send");
        Ok(())
    }

    async fn flush_tls(&mut self) -> Result<()> {
        if self.phase == ControlPhase::AwaitingServerReset {
            return Ok(());
        }
        while self.tls.wants_write() {
            let mut wire = Vec::new();
            self.tls.write_tls(&mut wire)?;
            for chunk in wire.chunks(TLS_CHUNK) {
                ensure!(self.unsent_tls.len() < 128, "TLS transmit buffer full");
                self.unsent_tls.push_back(chunk.to_vec());
            }
        }
        while self.pending.len() < 12 {
            let Some(chunk) = self.unsent_tls.pop_front() else {
                break;
            };
            self.queue(CONTROL, &chunk).await?;
        }
        Ok(())
    }

    fn process_body(&mut self, body: &[u8]) -> Result<()> {
        if body.is_empty() {
            return Ok(());
        }
        self.tls.read_tls(&mut Cursor::new(body))?;
        self.tls.process_new_packets()?;
        let mut buffer = [0; 4096];
        loop {
            match self.tls.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    ensure!(
                        self.app.len() + n <= 65536,
                        "control application data too large"
                    );
                    self.app.extend_from_slice(&buffer[..n]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(Error::Io(error)),
            }
        }
        Ok(())
    }

    fn receive_control(&mut self, packet: &[u8]) -> Result<()> {
        let (op, sid, payload) = match self.crypt.unwrap(packet) {
            Ok(value) => value,
            Err(Error::Replay | Error::ControlAuthenticationFailed | Error::Protocol(_)) => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let opcode = op >> 3;
        ensure!(op & 7 == 0, "unsupported OpenVPN key ID");
        if let Some(expected) = self.remote_sid {
            ensure!(sid == expected, "server session ID changed");
        } else {
            ensure!(
                self.phase == ControlPhase::AwaitingServerReset && opcode == HARD_RESET_SERVER,
                "server skipped hard reset"
            );
            self.remote_sid = Some(sid);
            self.phase = ControlPhase::TlsHandshake;
            tracing::debug!("OpenVPN server reset accepted");
        }
        ensure!(!payload.is_empty(), "short control payload");
        let count = payload[0] as usize;
        let ack_end = 1 + count * 4;
        let sid_end = ack_end + if count > 0 { 8 } else { 0 };
        ensure!(payload.len() >= sid_end, "short control ACKs");
        if count > 0 {
            ensure!(
                payload[ack_end..sid_end] == self.local_sid.to_be_bytes(),
                "wrong ACK session"
            );
        }
        for ack in payload[1..ack_end].as_chunks::<4>().0 {
            self.pending.remove(&u32::from_be_bytes(*ack));
        }
        self.last_received = Instant::now();
        if opcode == ACK {
            return Ok(());
        }
        ensure!(
            opcode == CONTROL || opcode == HARD_RESET_SERVER,
            "unexpected control opcode"
        );
        ensure!(payload.len() >= sid_end + 4, "short control message");
        let pid = u32::from_be_bytes(
            payload[sid_end..sid_end + 4]
                .try_into()
                .map_err(|_| Error::Protocol("short control message ID"))?,
        );
        self.acks.push_back(pid);
        if pid < self.next_rx {
            return Ok(());
        }
        ensure!(pid - self.next_rx < 64, "control receive window exceeded");
        self.reordered
            .entry(pid)
            .or_insert_with(|| payload[sid_end + 4..].to_vec());
        while let Some(body) = self.reordered.remove(&self.next_rx) {
            self.next_rx += 1;
            self.process_body(&body)?;
        }
        Ok(())
    }

    pub async fn step(&mut self) -> Result<Option<Vec<u8>>> {
        self.flush_tls().await?;
        let now = Instant::now();
        let retry: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&pid, pending)| {
                (now.duration_since(pending.last_sent)
                    >= Duration::from_secs(1 << pending.attempts.min(4)))
                .then_some(pid)
            })
            .collect();
        for pid in retry {
            let (opcode, body) = {
                let pending = self
                    .pending
                    .get_mut(&pid)
                    .ok_or(Error::Protocol("missing retransmit packet"))?;
                if pending.attempts >= 8 {
                    return Err(Error::Timeout("control retransmission"));
                }
                pending.attempts += 1;
                pending.last_sent = now;
                (pending.opcode, pending.body.clone())
            };
            self.send_control(opcode, pid, &body).await?;
        }
        if !self.acks.is_empty() {
            let count = self.acks.len().min(8);
            let mut payload = Vec::with_capacity(1 + count * 4 + 8);
            payload.push(count as u8);
            for _ in 0..count {
                if let Some(ack) = self.acks.pop_front() {
                    payload.extend_from_slice(&ack.to_be_bytes());
                }
            }
            payload.extend_from_slice(
                &self
                    .remote_sid
                    .ok_or(Error::Protocol("ACK without remote SID"))?
                    .to_be_bytes(),
            );
            self.send_wrapped(ACK, &payload).await?;
        }
        let mut buffer = [0; 2048];
        match time::timeout(Duration::from_millis(50), self.socket.recv(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                if buffer[0] >> 3 == DATA {
                    return Ok(Some(buffer[..n].to_vec()));
                }
                self.receive_control(&buffer[..n])?;
            }
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(error)) => return Err(Error::Io(error)),
        }
        Ok(None)
    }

    pub async fn handshake(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.tls.is_handshaking() {
            if Instant::now() >= deadline {
                return Err(Error::Timeout("TLS handshake"));
            }
            self.step().await?;
        }
        ensure!(
            self.phase == ControlPhase::TlsHandshake,
            "TLS completed before server reset"
        );
        self.phase = ControlPhase::ApplicationData;
        tracing::debug!("OpenVPN TLS handshake completed");
        Ok(())
    }

    pub async fn write_app(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.phase == ControlPhase::ApplicationData,
            "TLS application data before handshake"
        );
        self.tls.writer().write_all(bytes)?;
        self.flush_tls().await
    }

    pub fn application_data(&mut self) -> &mut Vec<u8> {
        &mut self.app
    }
    pub fn tls(&self) -> &ClientConnection {
        &self.tls
    }
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
    pub fn last_received(&self) -> Instant {
        self.last_received
    }
}
