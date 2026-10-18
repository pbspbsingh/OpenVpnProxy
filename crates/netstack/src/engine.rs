use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant as Clock};

use bytes::{Buf, Bytes};
use smoltcp::iface::{Config, Interface, Route, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time;

use crate::device::PacketDevice;
use crate::error::{Result, StackError};
use crate::stack::{Command, ConnectRequest};
use crate::types::{IpVersion, Ipv6Route, StackPhase, StreamEvent, TunnelConfig, matches_route};

const TCP_RECEIVE_BUFFER_BYTES: usize = 256 * 1024;
const TCP_SEND_BUFFER_BYTES: usize = 32 * 1024;
const IPV4_HOST_PREFIX_BITS: u8 = 32;
const EPHEMERAL_PORT_START: u16 = 40_000;
const EPHEMERAL_PORT_END: u16 = 60_000;
const MAX_CONNECTIONS: usize = 256;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
// Linux's default tcp_retries2 reference budget, rather than a short app timeout.
// https://docs.kernel.org/networking/ip-sysctl.html#tcp-retries2-integer
const TCP_PROGRESS_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_millis(924_600);
const TCP_READ_BUFFER_BYTES: usize = 4096;
const STACK_STATUS_INTERVAL: Duration = Duration::from_secs(10);

/// The host owns this worker; handles only submit connection commands.
pub(crate) struct Worker {
    pub id: u64,
    pub config: TunnelConfig,
    pub io: mpsc::Sender<Vec<u8>>,
    pub commands: mpsc::Receiver<Command>,
    pub phase: Arc<AtomicU8>,
    pub wake: Arc<Notify>,
    pub stop: oneshot::Receiver<()>,
    pub ready: oneshot::Sender<Result<()>>,
}

// Also runs on task cancellation, so surviving handles cannot report ready.
struct WorkerPhase(Arc<AtomicU8>);

impl Drop for WorkerPhase {
    fn drop(&mut self) {
        let _ = self.0.compare_exchange(
            StackPhase::Ready as u8,
            StackPhase::Offline as u8,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}

impl Worker {
    pub(crate) async fn run(self) {
        let Self {
            id,
            config,
            io,
            mut commands,
            phase,
            wake,
            mut stop,
            ready,
        } = self;
        let _lifecycle = WorkerPhase(Arc::clone(&phase));
        let mut engine = match Engine::new(id, config, io) {
            Ok(engine) => engine,
            Err(error) => {
                let _ = ready.send(Err(error));
                return;
            }
        };
        phase.store(StackPhase::Ready as u8, Ordering::Release);
        if ready.send(Ok(())).is_err() {
            return;
        }
        let started = Clock::now();
        let mut status = time::interval(STACK_STATUS_INTERVAL);
        status.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            let now =
                Instant::from_millis(started.elapsed().as_millis().min(i64::MAX as u128) as i64);
            let output_blocked = engine.device.output_blocked || engine.io.capacity() == 0;
            let delay = engine.next_delay(now);
            let timer_started = Clock::now();
            let event = tokio::select! {
                _ = &mut stop => break,
                command = commands.recv() => Wake::Command(command),
                _ = wait_for_timer(delay) => Wake::Timer,
                _ = wake.notified() => Wake::Consumer,
                permit = engine.io.reserve(), if output_blocked => {
                    drop(permit);
                    Wake::Output
                }
                _ = engine.io.closed() => Wake::Output,
                _ = status.tick() => Wake::Status,
            };
            match &event {
                Wake::Command(_) => engine.stats.command_wakeups += 1,
                Wake::Timer => {
                    engine.stats.timer_wakeups += 1;
                    if let Some(delay) = delay {
                        engine.stats.max_timer_lateness = engine
                            .stats
                            .max_timer_lateness
                            .max(timer_started.elapsed().saturating_sub(delay));
                    }
                }
                Wake::Consumer => engine.stats.consumer_wakeups += 1,
                Wake::Output | Wake::Status => {}
            }
            match event {
                Wake::Command(Some(command)) => engine.handle(command),
                Wake::Command(None) => break,
                Wake::Status => {
                    engine.log_status();
                    continue;
                }
                Wake::Timer | Wake::Consumer | Wake::Output => {}
            }
            let now =
                Instant::from_millis(started.elapsed().as_millis().min(i64::MAX as u128) as i64);
            if let Err(error) = engine.tick(now) {
                tracing::error!(%error, "packet stack stopped");
                phase.store(StackPhase::Failed as u8, Ordering::Release);
                break;
            }
        }
        // Close admission before releasing sockets and waking their clients.
        if phase.load(Ordering::Relaxed) != StackPhase::Failed as u8 {
            phase.store(StackPhase::Offline as u8, Ordering::Release);
        }
        commands.close();
        engine.shutdown();
    }
}

#[derive(Default)]
struct StackStats {
    polls: u64,
    inbound_packets: u64,
    inbound_bytes: u64,
    inbound_dropped: u64,
    tcp_read_bytes: u64,
    tcp_write_bytes: u64,
    full_tcp_reads: u64,
    event_queue_blocked: u64,
    max_write_queue_bytes: usize,
    command_wakeups: u64,
    timer_wakeups: u64,
    consumer_wakeups: u64,
    max_timer_lateness: Duration,
    max_tick_time: Duration,
}

/// A received FIN starts draining; EOF is published only after buffered data.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ReadState {
    Open,
    Draining,
    Closed,
}

struct Connection {
    socket: SocketHandle,
    events: mpsc::Sender<StreamEvent>,
    wake_needed: Arc<AtomicBool>,
    writes: mpsc::Receiver<Bytes>,
    write_queue: Bytes,
    established: bool,
    read_state: ReadState,
    write_closed: bool,
    write_finished: Option<oneshot::Sender<()>>,
    deadline: Clock,
}

struct PendingDns {
    host: String,
    version: IpVersion,
    query: dns::QueryHandle,
    reply: oneshot::Sender<Result<Vec<IpAddr>>>,
    deadline: Clock,
}

struct Engine {
    id: u64,
    iface: Interface,
    device: PacketDevice,
    sockets: SocketSet<'static>,
    dns_socket: SocketHandle,
    dns_available: bool,
    ipv6_routes: Vec<Ipv6Route>,
    pending_dns: Vec<PendingDns>,
    connections: HashMap<u64, Connection>,
    next_port: u16,
    io: mpsc::Sender<Vec<u8>>,
    stats: StackStats,
    last_status: Clock,
}

impl Engine {
    fn new(id: u64, config: TunnelConfig, io: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let mut device = PacketDevice::new(config.mtu, io.clone());
        let mut iface =
            Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::ZERO);
        let mut inserted = false;
        iface.update_ip_addrs(|addresses| {
            inserted = addresses
                .push(IpCidr::new(ip(config.local).into(), IPV4_HOST_PREFIX_BITS))
                .is_ok();
            if let Some(ipv6) = &config.ipv6 {
                inserted &= addresses
                    .push(IpCidr::new(ipv6.local.into(), ipv6.prefix_len))
                    .is_ok();
            }
        });
        if !inserted {
            return Err(StackError::AddressTableFull);
        }
        iface
            .routes_mut()
            .add_default_ipv4_route(ip(config.gateway))
            .map_err(|_| StackError::RouteTableFull)?;
        if let Some(ipv6) = &config.ipv6 {
            let mut inserted = true;
            iface.routes_mut().update(|routes| {
                for route in &ipv6.routes {
                    inserted &= routes
                        .push(Route {
                            cidr: IpCidr::new(route.network.into(), route.prefix_len),
                            via_router: route.gateway.into(),
                            preferred_until: None,
                            expires_at: None,
                        })
                        .is_ok();
                }
            });
            if !inserted {
                return Err(StackError::RouteTableFull);
            }
        }
        let servers: Vec<IpAddress> = config.dns.iter().copied().map(smol_ip).collect();
        let mut sockets = SocketSet::new(vec![]);
        let dns_socket = sockets.add(dns::Socket::new(&servers, vec![]));
        tracing::debug!(local = %config.local, gateway = %config.gateway, mtu = config.mtu, dns_servers = servers.len(), ipv6_routes = config.ipv6.as_ref().map_or(0, |ipv6| ipv6.routes.len()), "userspace packet stack initialized");
        let ipv6_routes = config.ipv6.map_or_else(Vec::new, |ipv6| ipv6.routes);
        Ok(Self {
            id,
            iface,
            device,
            sockets,
            dns_socket,
            dns_available: !servers.is_empty(),
            ipv6_routes,
            pending_dns: Vec::new(),
            connections: HashMap::new(),
            next_port: EPHEMERAL_PORT_START,
            io,
            stats: StackStats::default(),
            last_status: Clock::now(),
        })
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Packet(packet) => {
                self.stats.inbound_packets += 1;
                self.stats.inbound_bytes += packet.len() as u64;
                tracing::trace!(bytes = packet.len(), "packet delivered to userspace stack");
                if !self.device.receive_packet(packet) {
                    self.stats.inbound_dropped += 1;
                }
            }
            Command::Resolve(host, version, reply) => {
                if !self.dns_available {
                    tracing::warn!(%host, "tunneled DNS requested without a DNS server");
                    let _ = reply.send(Err(StackError::NoDnsServer));
                    return;
                }
                tracing::debug!(%host, ?version, "starting tunneled DNS query");
                let socket = self.sockets.get_mut::<dns::Socket>(self.dns_socket);
                let query_type = match version {
                    IpVersion::V4 => DnsQueryType::A,
                    IpVersion::V6 => DnsQueryType::Aaaa,
                };
                match socket.start_query(self.iface.context(), &host, query_type) {
                    Ok(query) => self.pending_dns.push(PendingDns {
                        host,
                        version,
                        query,
                        reply,
                        deadline: Clock::now() + DNS_QUERY_TIMEOUT,
                    }),
                    Err(error) => {
                        tracing::warn!(%host, ?error, "could not start tunneled DNS query");
                        let _ = reply.send(Err(StackError::DnsQuery(format!("{error:?}"))));
                    }
                }
            }
            Command::Connect(ConnectRequest {
                id,
                address,
                events,
                wake_needed,
                writes,
                write_finished,
            }) => {
                if !matches_route(&self.ipv6_routes, address.ip()) {
                    tracing::warn!(id, %address, "VPN has no IPv6 route for SOCKS destination");
                    let _ = events.try_send(StreamEvent::Closed);
                    return;
                }
                if self.connections.len() >= MAX_CONNECTIONS {
                    tracing::warn!(id, %address, "userspace TCP connection limit reached");
                    let _ =
                        events.try_send(StreamEvent::ConnectFailed(StackError::ConnectionLimit));
                    return;
                }
                tracing::debug!(id, %address, receive_buffer_bytes = TCP_RECEIVE_BUFFER_BYTES, send_buffer_bytes = TCP_SEND_BUFFER_BYTES, "opening userspace TCP connection");
                let socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER_BYTES]),
                    tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER_BYTES]),
                );
                let handle = self.sockets.add(socket);
                let port = self.next_port;
                self.next_port = if port >= EPHEMERAL_PORT_END {
                    EPHEMERAL_PORT_START
                } else {
                    port + 1
                };
                let result = self.sockets.get_mut::<tcp::Socket>(handle).connect(
                    self.iface.context(),
                    (smol_ip(address.ip()), address.port()),
                    port,
                );
                match result {
                    Ok(()) => {
                        self.connections.insert(
                            id,
                            Connection {
                                socket: handle,
                                events,
                                wake_needed,
                                writes,
                                write_queue: Bytes::new(),
                                established: false,
                                read_state: ReadState::Open,
                                write_closed: false,
                                write_finished: Some(write_finished),
                                deadline: Clock::now() + TCP_CONNECT_TIMEOUT,
                            },
                        );
                    }
                    Err(error) => {
                        tracing::warn!(id, %address, ?error, "userspace TCP connect failed");
                        self.sockets.remove(handle);
                        let _ = events.try_send(StreamEvent::Closed);
                    }
                }
            }
            #[cfg(test)]
            Command::Close(id) => self.close(id),
        }
    }

    fn close(&mut self, id: u64) {
        if let Some(connection) = self.connections.remove(&id) {
            tracing::debug!(id, "closing userspace TCP connection");
            let _ = connection.events.try_send(StreamEvent::Closed);
            self.sockets.remove(connection.socket);
        }
    }

    fn tick(&mut self, now: Instant) -> Result<()> {
        if self.io.is_closed() {
            return Err(StackError::PacketDelivery);
        }
        let started = Clock::now();
        self.stats.polls += 1;
        // smoltcp also checks its timeout on idle sockets. Enable it only while
        // a handshake or outstanding data needs progress. The connect deadline
        // remains independently enforced below.
        for connection in self.connections.values() {
            let socket = self.sockets.get_mut::<tcp::Socket>(connection.socket);
            let needs_progress = !connection.established || socket.send_queue() > 0;
            socket.set_timeout(needs_progress.then_some(TCP_PROGRESS_TIMEOUT));
        }
        self.device.output_blocked = false;
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        let mut pending = Vec::new();
        for request in self.pending_dns.drain(..) {
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns_socket);
            if request.reply.is_closed() {
                socket.cancel_query(request.query);
                continue;
            }
            if Clock::now() >= request.deadline {
                tracing::warn!(host = %request.host, "tunneled DNS query timed out");
                socket.cancel_query(request.query);
                let _ = request.reply.send(Err(StackError::DnsTimeout));
                continue;
            }
            match socket.get_query_result(request.query) {
                Ok(addresses) => {
                    let addresses: Vec<_> = addresses
                        .iter()
                        .filter_map(|address| match (request.version, address) {
                            (IpVersion::V4, IpAddress::Ipv4(value)) => Some(IpAddr::V4(*value)),
                            (IpVersion::V6, IpAddress::Ipv6(value)) => Some(IpAddr::V6(*value)),
                            _ => None,
                        })
                        .collect();
                    tracing::debug!(host = %request.host, ?addresses, "tunneled DNS query completed");
                    let _ = request.reply.send(if addresses.is_empty() {
                        Err(StackError::NoDnsAddress)
                    } else {
                        Ok(addresses)
                    });
                }
                Err(dns::GetQueryResultError::Pending) => pending.push(request),
                Err(_) => {
                    tracing::warn!(host = %request.host, "tunneled DNS query failed");
                    let _ = request.reply.send(Err(StackError::DnsFailed));
                }
            }
        }
        self.pending_dns = pending;

        let mut close = Vec::new();
        for (&id, connection) in &mut self.connections {
            let socket = self.sockets.get_mut::<tcp::Socket>(connection.socket);
            if connection.events.is_closed() {
                close.push(id);
                continue;
            }
            if !connection.established
                && matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                )
            {
                connection.established = true;
                tracing::debug!(id, "userspace TCP connection established");
                if connection.events.try_send(StreamEvent::Connected).is_err() {
                    tracing::debug!(id, "TCP client disappeared before connection completed");
                    close.push(id);
                    continue;
                }
            }
            if connection.read_state == ReadState::Open
                && matches!(
                    socket.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                )
            {
                connection.read_state = ReadState::Draining;
            }
            // CLOSED also results from a reset, which leaves unacknowledged
            // data in smoltcp's send queue. Never report that as a drained write.
            if socket.state() == tcp::State::Closed && socket.send_queue() > 0 {
                tracing::debug!(
                    id,
                    unacknowledged_bytes = socket.send_queue(),
                    "TCP closed before upload was acknowledged"
                );
                close.push(id);
                continue;
            }
            if connection.write_closed
                && (matches!(socket.state(), tcp::State::FinWait2 | tcp::State::TimeWait)
                    || (socket.state() == tcp::State::Closed
                        && connection.read_state != ReadState::Open))
                && let Some(finished) = connection.write_finished.take()
            {
                let _ = finished.send(());
            }
            if !socket.is_active()
                && (connection.read_state != ReadState::Draining
                    || (socket.state() == tcp::State::Closed && !connection.write_closed))
            {
                tracing::debug!(id, state = ?socket.state(), "userspace TCP socket became inactive");
                close.push(id);
                continue;
            }
            if !connection.established && Clock::now() >= connection.deadline {
                tracing::warn!(id, "userspace TCP connection timed out");
                close.push(id);
                continue;
            }
            if connection.established {
                if socket.can_send()
                    && connection.write_queue.is_empty()
                    && let Ok(data) = connection.writes.try_recv()
                {
                    connection.write_queue = data;
                    self.stats.max_write_queue_bytes = self
                        .stats
                        .max_write_queue_bytes
                        .max(connection.write_queue.len());
                }
                if socket.can_send() && !connection.write_queue.is_empty() {
                    match socket.send_slice(&connection.write_queue) {
                        Ok(written) => {
                            self.stats.tcp_write_bytes += written as u64;
                            tracing::trace!(id, bytes = written, "userspace TCP data queued");
                            connection.write_queue.advance(written);
                            if connection.write_queue.is_empty() {
                                connection.write_queue = Bytes::new();
                            }
                        }
                        Err(error) => {
                            tracing::warn!(id, ?error, "userspace TCP send failed");
                            close.push(id);
                            continue;
                        }
                    }
                }
                // Dropping the write half queues FIN only after all accepted data
                // has entered smoltcp, which drains its own send buffer before FIN.
                if !connection.write_closed
                    && connection.writes.is_closed()
                    && connection.writes.is_empty()
                    && connection.write_queue.is_empty()
                {
                    socket.close();
                    connection.write_closed = true;
                }
                if connection.read_state == ReadState::Draining && !socket.may_recv() {
                    if connection.events.capacity() > 0 {
                        let _ = connection.events.try_send(StreamEvent::ReadClosed);
                        connection.read_state = ReadState::Closed;
                    } else {
                        connection.wake_needed.store(true, Ordering::Release);
                    }
                }
                if socket.can_recv() && connection.events.capacity() == 0 {
                    self.stats.event_queue_blocked += 1;
                    connection.wake_needed.store(true, Ordering::Release);
                }
                if socket.can_recv() && connection.events.capacity() > 0 {
                    match socket.recv(|data| {
                        let count = data.len().min(TCP_READ_BUFFER_BYTES);
                        (count, data[..count].to_vec())
                    }) {
                        Ok(buffer) => {
                            let read = buffer.len();
                            self.stats.tcp_read_bytes += read as u64;
                            if read == TCP_READ_BUFFER_BYTES {
                                self.stats.full_tcp_reads += 1;
                            }
                            tracing::trace!(id, bytes = read, "userspace TCP data received");
                            if read > 0
                                && connection
                                    .events
                                    .try_send(StreamEvent::Data(buffer))
                                    .is_err()
                            {
                                tracing::debug!(id, "TCP client disappeared during receive");
                                close.push(id);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(id, ?error, "userspace TCP receive failed");
                            close.push(id);
                        }
                    }
                }
            }
        }
        for id in close {
            self.close(id);
        }
        self.stats.max_tick_time = self.stats.max_tick_time.max(started.elapsed());
        Ok(())
    }

    fn next_delay(&mut self, now: Instant) -> Option<Duration> {
        if self.connections.values().any(|connection| {
            let socket = self.sockets.get::<tcp::Socket>(connection.socket);
            connection.events.is_closed()
                || (!connection.write_closed
                    && connection.writes.is_closed()
                    && connection.writes.is_empty()
                    && connection.write_queue.is_empty())
                || (connection.established
                    && connection.read_state == ReadState::Draining
                    && !socket.may_recv()
                    && connection.events.capacity() > 0)
                || (socket.can_recv() && connection.events.capacity() > 0)
                || (socket.can_send()
                    && (!connection.write_queue.is_empty() || !connection.writes.is_empty()))
        }) {
            return Some(Duration::ZERO);
        }

        let current = Clock::now();
        let application_delay = self
            .pending_dns
            .iter()
            .map(|request| request.deadline.saturating_duration_since(current))
            .chain(
                self.connections
                    .values()
                    .filter(|connection| !connection.established)
                    .map(|connection| connection.deadline.saturating_duration_since(current)),
            )
            .min();
        // A full device remains immediately pollable inside smoltcp. Wait for
        // channel capacity instead of spinning on protocol work it cannot send.
        // Application deadlines still run, so stalled connects/DNS can expire.
        let protocol_delay = if self.io.capacity() == 0 {
            None
        } else {
            self.iface
                .poll_delay(now, &self.sockets)
                .map(|delay| Duration::from_millis(delay.total_millis()))
        };
        protocol_delay.into_iter().chain(application_delay).min()
    }

    fn log_status(&mut self) {
        let window = self.last_status.elapsed();
        self.last_status = Clock::now();
        let stats = std::mem::take(&mut self.stats);
        let outbound_packets = std::mem::take(&mut self.device.transmitted_packets);
        let outbound_bytes = std::mem::take(&mut self.device.transmitted_bytes);
        if stats.inbound_packets == 0 && outbound_packets == 0 && self.connections.is_empty() {
            return;
        }
        tracing::debug!(
            stack_id = self.id,
            ?window,
            connections = self.connections.len(),
            pending_dns = self.pending_dns.len(),
            polls = stats.polls,
            inbound_packets = stats.inbound_packets,
            inbound_bytes = stats.inbound_bytes,
            inbound_dropped = stats.inbound_dropped,
            outbound_packets,
            outbound_bytes,
            tcp_read_bytes = stats.tcp_read_bytes,
            tcp_write_bytes = stats.tcp_write_bytes,
            full_tcp_reads = stats.full_tcp_reads,
            event_queue_blocked = stats.event_queue_blocked,
            max_write_queue_bytes = stats.max_write_queue_bytes,
            command_wakeups = stats.command_wakeups,
            timer_wakeups = stats.timer_wakeups,
            consumer_wakeups = stats.consumer_wakeups,
            max_timer_lateness = ?stats.max_timer_lateness,
            max_tick_time = ?stats.max_tick_time,
            "packet stack activity"
        );
    }

    fn shutdown(mut self) {
        self.log_status();
        tracing::info!(
            connections = self.connections.len(),
            pending_dns = self.pending_dns.len(),
            "userspace packet stack shutting down"
        );
        for (_, connection) in self.connections.drain() {
            let _ = connection.events.try_send(StreamEvent::Closed);
        }
        for request in self.pending_dns.drain(..) {
            let _ = request.reply.send(Err(StackError::Disconnected));
        }
    }
}

enum Wake {
    Command(Option<Command>),
    Timer,
    Consumer,
    Output,
    Status,
}

async fn wait_for_timer(delay: Option<Duration>) {
    match delay {
        // Ready work must yield to other tasks without waiting for the timer wheel.
        Some(delay) if delay.is_zero() => tokio::task::yield_now().await,
        Some(delay) => time::sleep(delay).await,
        None => std::future::pending().await,
    }
}

fn ip(address: Ipv4Addr) -> Ipv4Address {
    address
}

fn smol_ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(address),
        IpAddr::V6(address) => IpAddress::Ipv6(address),
    }
}

#[cfg(test)]
mod tests;
