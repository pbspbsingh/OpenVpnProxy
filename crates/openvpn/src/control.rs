use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection};
use tokio::net::UdpSocket;
use tokio::time;

use crate::client::new_tls_connection;
use crate::error::{Error, Result};
use crate::protocol::{
    DATA_V2_OPCODE, KEY_ID_MASK, MAX_KEY_ID, OPCODE_SHIFT, REPLAY_WINDOW_BITS, STATIC_KEY_BYTES,
};
use crate::tlscrypt::TlsCrypt;

macro_rules! ensure {
    ($condition:expr, $message:literal) => {
        crate::error::require($condition, $message)?
    };
}

const HARD_RESET_CLIENT: u8 = 7;
const HARD_RESET_SERVER: u8 = 8;
const SOFT_RESET: u8 = 3;
const CONTROL: u8 = 4;
const ACK: u8 = 5;
const TLS_CHUNK: usize = 1200;
const SESSION_ID_BYTES: usize = 8;
const CONTROL_PACKET_ID_BYTES: usize = 4;
const MAX_PENDING_CONTROL_PACKETS: usize = 12;
const MAX_ACKS_PER_PACKET: usize = 8;
const MAX_QUEUED_TLS_CHUNKS: usize = 128;
const TLS_READ_BUFFER_BYTES: usize = 4096;
const MAX_CONTROL_APP_BYTES: usize = 65_536;
const MAX_CONTROL_SEND_ATTEMPTS: u8 = 8;
const MAX_RETRY_EXPONENT: u8 = 4;
const BASE_RETRY_SECONDS: u64 = 1;
const UDP_RECEIVE_BUFFER_BYTES: usize = 2048;
const UDP_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct Link {
    socket: Arc<UdpSocket>,
    tls_config: Arc<ClientConfig>,
    static_key: [u8; STATIC_KEY_BYTES],
    key_id: u8,
    next: Option<Box<Link>>,
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

impl Link {
    pub(crate) async fn new(
        socket: UdpSocket,
        key: &[u8; STATIC_KEY_BYTES],
        tls: ClientConnection,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Self> {
        let mut sid = [0; SESSION_ID_BYTES];
        getrandom::fill(&mut sid).map_err(Error::Randomness)?;
        let mut link = Self {
            socket: Arc::new(socket),
            tls_config,
            static_key: *key,
            key_id: 0,
            next: None,
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
        tracing::debug!("starting OpenVPN control handshake");
        link.queue(HARD_RESET_CLIENT, &[]).await?;
        Ok(link)
    }

    pub(crate) async fn step(&mut self) -> Result<Option<Vec<u8>>> {
        self.advance_outbound().await?;
        if let Some(next) = &mut self.next {
            next.advance_outbound().await?;
        }
        let mut buffer = [0; UDP_RECEIVE_BUFFER_BYTES];
        match time::timeout(UDP_POLL_INTERVAL, self.socket.recv(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                if buffer[0] >> OPCODE_SHIFT == DATA_V2_OPCODE {
                    tracing::trace!(bytes = n, "received OpenVPN data datagram");
                    return Ok(Some(buffer[..n].to_vec()));
                }
                let key_id = buffer[0] & KEY_ID_MASK;
                if key_id == self.key_id {
                    self.receive_control(&buffer[..n])?;
                } else if self.next.as_ref().is_some_and(|next| next.key_id == key_id) {
                    if let Some(next) = &mut self.next {
                        next.receive_control(&buffer[..n])?;
                    }
                } else if buffer[0] >> OPCODE_SHIFT == SOFT_RESET
                    && key_id == next_key_id(self.key_id)
                    && self.next.is_none()
                {
                    let mut next = self.renegotiated(key_id)?;
                    next.receive_control(&buffer[..n])?;
                    next.queue(SOFT_RESET, &[]).await?;
                    self.next = Some(Box::new(next));
                    tracing::info!(key_id, "OpenVPN key renegotiation started");
                } else {
                    tracing::debug!(key_id, "discarded control packet for inactive key");
                }
            }
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(error)) => return Err(Error::Io(error)),
        }
        Ok(None)
    }

    pub(crate) fn next(&mut self) -> Option<&mut Link> {
        self.next.as_deref_mut()
    }

    pub(crate) async fn begin_renegotiation(&mut self) -> Result<()> {
        ensure!(
            self.next.is_none(),
            "OpenVPN key renegotiation already in progress"
        );
        let key_id = next_key_id(self.key_id);
        let mut next = self.renegotiated(key_id)?;
        next.queue(SOFT_RESET, &[]).await?;
        self.next = Some(Box::new(next));
        tracing::info!(key_id, "OpenVPN key renegotiation requested");
        Ok(())
    }

    pub(crate) fn promote_next(&mut self) -> Result<()> {
        let next = self
            .next
            .take()
            .ok_or(Error::Protocol("no negotiated key to promote"))?;
        *self = *next;
        Ok(())
    }

    pub(crate) fn key_id(&self) -> u8 {
        self.key_id
    }

    pub(crate) fn control_synchronized(&self) -> bool {
        self.pending.is_empty() && self.acks.is_empty() && self.unsent_tls.is_empty()
    }

    pub(crate) fn activate_tls(&mut self) -> Result<()> {
        ensure!(
            self.phase == ControlPhase::TlsHandshake && !self.tls.is_handshaking(),
            "OpenVPN TLS is not ready"
        );
        self.phase = ControlPhase::ApplicationData;
        Ok(())
    }

    pub(crate) async fn handshake(&mut self, window: Duration) -> Result<()> {
        tracing::debug!("waiting for OpenVPN TLS handshake");
        let deadline = Instant::now()
            .checked_add(window)
            .ok_or(Error::Protocol("invalid OpenVPN handshake window"))?;
        while self.tls.is_handshaking() {
            if Instant::now() >= deadline {
                return Err(Error::Timeout("TLS handshake"));
            }
            self.step().await?;
        }
        self.activate_tls()?;
        tracing::debug!("OpenVPN TLS handshake completed");
        Ok(())
    }

    pub(crate) async fn write_app(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.phase == ControlPhase::ApplicationData,
            "TLS application data before handshake"
        );
        self.tls.writer().write_all(bytes)?;
        self.flush_tls().await
    }

    pub(crate) fn application_data(&mut self) -> &mut Vec<u8> {
        &mut self.app
    }
    pub(crate) fn tls(&self) -> &ClientConnection {
        &self.tls
    }
    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }
    pub(crate) fn last_received(&self) -> Instant {
        self.next.as_ref().map_or(self.last_received, |next| {
            self.last_received.max(next.last_received)
        })
    }
}

impl Link {
    fn renegotiated(&self, key_id: u8) -> Result<Self> {
        let tls = new_tls_connection(&self.tls_config)?;
        Ok(Self {
            socket: Arc::clone(&self.socket),
            tls_config: Arc::clone(&self.tls_config),
            static_key: self.static_key,
            key_id,
            next: None,
            crypt: TlsCrypt::client(&self.static_key),
            local_sid: self.local_sid,
            remote_sid: self.remote_sid,
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
        })
    }

    async fn queue(&mut self, opcode: u8, body: &[u8]) -> Result<()> {
        ensure!(
            self.pending.len() < MAX_PENDING_CONTROL_PACKETS,
            "control transmit window full"
        );
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
        tracing::trace!(
            opcode,
            pid,
            bytes = body.len(),
            "queued OpenVPN control packet"
        );
        self.send_control(opcode, pid, body).await
    }

    async fn send_control(&mut self, opcode: u8, pid: u32, body: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(
            1 + MAX_ACKS_PER_PACKET * CONTROL_PACKET_ID_BYTES
                + SESSION_ID_BYTES
                + CONTROL_PACKET_ID_BYTES
                + body.len(),
        );
        let count = self.acks.len().min(MAX_ACKS_PER_PACKET);
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
        let wire = self.crypt.wrap(
            (opcode << OPCODE_SHIFT) | self.key_id,
            self.local_sid,
            payload,
        )?;
        tracing::trace!(
            opcode,
            bytes = wire.len(),
            "sending OpenVPN control datagram"
        );
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
                ensure!(
                    self.unsent_tls.len() < MAX_QUEUED_TLS_CHUNKS,
                    "TLS transmit buffer full"
                );
                self.unsent_tls.push_back(chunk.to_vec());
            }
        }
        while self.pending.len() < MAX_PENDING_CONTROL_PACKETS {
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
        let mut buffer = [0; TLS_READ_BUFFER_BYTES];
        loop {
            match self.tls.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    ensure!(
                        self.app.len() + n <= MAX_CONTROL_APP_BYTES,
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
            Err(
                error @ (Error::Replay | Error::ControlAuthenticationFailed | Error::Protocol(_)),
            ) => {
                tracing::debug!(%error, "discarded invalid OpenVPN control packet");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let opcode = op >> OPCODE_SHIFT;
        ensure!(
            op & KEY_ID_MASK == self.key_id,
            "wrong OpenVPN control key ID"
        );
        if let Some(expected) = self.remote_sid {
            ensure!(sid == expected, "server session ID changed");
            if self.phase == ControlPhase::AwaitingServerReset {
                match opcode {
                    SOFT_RESET => {
                        self.phase = ControlPhase::TlsHandshake;
                        tracing::info!(key_id = self.key_id, "OpenVPN soft reset accepted");
                    }
                    ACK => {}
                    _ => return Err(Error::Protocol("server skipped soft reset")),
                }
            }
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
        let ack_end = 1 + count * CONTROL_PACKET_ID_BYTES;
        let sid_end = ack_end + if count > 0 { SESSION_ID_BYTES } else { 0 };
        ensure!(payload.len() >= sid_end, "short control ACKs");
        if count > 0 {
            ensure!(
                payload[ack_end..sid_end] == self.local_sid.to_be_bytes(),
                "wrong ACK session"
            );
        }
        for ack in payload[1..ack_end].as_chunks::<CONTROL_PACKET_ID_BYTES>().0 {
            self.pending.remove(&u32::from_be_bytes(*ack));
        }
        tracing::trace!(opcode, acks = count, "received OpenVPN control datagram");
        self.last_received = Instant::now();
        if opcode == ACK {
            return Ok(());
        }
        ensure!(
            opcode == CONTROL || opcode == HARD_RESET_SERVER || opcode == SOFT_RESET,
            "unexpected control opcode"
        );
        ensure!(
            payload.len() >= sid_end + CONTROL_PACKET_ID_BYTES,
            "short control message"
        );
        let pid = u32::from_be_bytes(
            payload[sid_end..sid_end + CONTROL_PACKET_ID_BYTES]
                .try_into()
                .map_err(|_| Error::Protocol("short control message ID"))?,
        );
        tracing::trace!(pid, opcode, "received OpenVPN control packet");
        self.acks.push_back(pid);
        if pid < self.next_rx {
            return Ok(());
        }
        ensure!(
            pid - self.next_rx < REPLAY_WINDOW_BITS,
            "control receive window exceeded"
        );
        self.reordered
            .entry(pid)
            .or_insert_with(|| payload[sid_end + CONTROL_PACKET_ID_BYTES..].to_vec());
        while let Some(body) = self.reordered.remove(&self.next_rx) {
            self.next_rx += 1;
            self.process_body(&body)?;
        }
        Ok(())
    }

    async fn advance_outbound(&mut self) -> Result<()> {
        self.flush_tls().await?;
        let now = Instant::now();
        let retry: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&pid, pending)| {
                (now.duration_since(pending.last_sent)
                    >= Duration::from_secs(
                        BASE_RETRY_SECONDS << pending.attempts.min(MAX_RETRY_EXPONENT),
                    ))
                .then_some(pid)
            })
            .collect();
        for pid in retry {
            let (opcode, body) = {
                let pending = self
                    .pending
                    .get_mut(&pid)
                    .ok_or(Error::Protocol("missing retransmit packet"))?;
                if pending.attempts >= MAX_CONTROL_SEND_ATTEMPTS {
                    tracing::warn!(
                        pid,
                        opcode = pending.opcode,
                        "OpenVPN control retransmission limit reached"
                    );
                    return Err(Error::Timeout("control retransmission"));
                }
                pending.attempts += 1;
                pending.last_sent = now;
                tracing::debug!(
                    pid,
                    opcode = pending.opcode,
                    attempts = pending.attempts,
                    "retransmitting OpenVPN control packet"
                );
                (pending.opcode, pending.body.clone())
            };
            self.send_control(opcode, pid, &body).await?;
        }
        if !self.acks.is_empty() {
            let count = self.acks.len().min(MAX_ACKS_PER_PACKET);
            let mut payload =
                Vec::with_capacity(1 + count * CONTROL_PACKET_ID_BYTES + SESSION_ID_BYTES);
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
        Ok(())
    }
}

fn next_key_id(current: u8) -> u8 {
    if current == MAX_KEY_ID {
        1
    } else {
        current + 1
    }
}
