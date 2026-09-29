use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant as Clock};

use smoltcp::iface::{Config, Interface, Route, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time;

use crate::device::PacketDevice;
use crate::error::{Result, StackError};
use crate::stack::Command;
use crate::types::{IpVersion, Ipv6Route, StackPhase, StreamEvent, TunnelConfig, matches_route};

const MAX_QUEUED_WRITE: usize = 256 * 1024;
const TCP_RECEIVE_BUFFER_BYTES: usize = 256 * 1024;
const TCP_SEND_BUFFER_BYTES: usize = 32 * 1024;
const IPV4_HOST_PREFIX_BITS: u8 = 32;
const EPHEMERAL_PORT_START: u16 = 40_000;
const EPHEMERAL_PORT_END: u16 = 60_000;
const MAX_CONNECTIONS: usize = 256;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_READ_BUFFER_BYTES: usize = 4096;
const STACK_STATUS_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) async fn run(
    id: u64,
    mut rx: mpsc::Receiver<Command>,
    phase: Arc<AtomicU8>,
    wake: Arc<Notify>,
) {
    let started = Clock::now();
    let mut engine: Option<Engine> = None;
    let mut status = time::interval(STACK_STATUS_INTERVAL);
    status.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        let delay = engine.as_mut().and_then(|active| {
            let elapsed = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
            active.next_delay(Instant::from_millis(elapsed))
        });
        let timer_started = Clock::now();
        let event = tokio::select! {
            command = rx.recv() => Wake::Command(command),
            _ = wait_for_timer(delay) => Wake::Timer,
            _ = wake.notified() => Wake::Consumer,
            _ = status.tick() => {
                if let Some(active) = &mut engine {
                    active.log_status();
                }
                continue;
            }
        };
        if let Some(active) = &mut engine {
            match &event {
                Wake::Command(_) => active.stats.command_wakeups += 1,
                Wake::Timer => {
                    active.stats.timer_wakeups += 1;
                    if let Some(delay) = delay {
                        active.stats.max_timer_lateness = active
                            .stats
                            .max_timer_lateness
                            .max(timer_started.elapsed().saturating_sub(delay));
                    }
                }
                Wake::Consumer => active.stats.consumer_wakeups += 1,
            }
        }
        match event {
            Wake::Command(Some(Command::Configure(config, io, reply))) => {
                phase.store(StackPhase::Offline as u8, Ordering::Release);
                if let Some(old) = engine.take() {
                    old.shutdown();
                }
                match Engine::new(id, config, io) {
                    Ok(new) => {
                        engine = Some(new);
                        phase.store(StackPhase::Configured as u8, Ordering::Release);
                        tracing::debug!("userspace packet stack configured");
                        let _ = reply.send(Ok(()));
                    }
                    Err(error) => {
                        tracing::error!(%error, "userspace packet stack configuration failed");
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Wake::Command(Some(Command::Reset)) => {
                tracing::debug!("resetting userspace packet stack");
                phase.store(StackPhase::Offline as u8, Ordering::Release);
                if let Some(old) = engine.take() {
                    old.shutdown();
                }
            }
            Wake::Command(Some(command)) => {
                if let Some(engine) = &mut engine {
                    engine.handle(command);
                } else {
                    reject_without_tunnel(command);
                }
            }
            Wake::Command(None) => break,
            Wake::Timer | Wake::Consumer => {}
        }
        if phase.load(Ordering::Acquire) == StackPhase::Failed as u8
            && let Some(old) = engine.take()
        {
            old.shutdown();
        }
        if let Some(active) = &mut engine {
            let elapsed = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
            if let Err(error) = active.tick(Instant::from_millis(elapsed)) {
                tracing::error!(%error, "packet stack stopped");
                phase.store(StackPhase::Failed as u8, Ordering::Release);
                if let Some(old) = engine.take() {
                    old.shutdown();
                }
            }
        }
    }
    phase.store(StackPhase::Offline as u8, Ordering::Release);
    if let Some(old) = engine {
        old.shutdown();
    }
}

#[derive(Default)]
struct StackStats {
    polls: u64,
    inbound_packets: u64,
    inbound_bytes: u64,
    outbound_packets: u64,
    outbound_bytes: u64,
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

struct Connection {
    socket: SocketHandle,
    events: mpsc::Sender<StreamEvent>,
    wake_needed: Arc<AtomicBool>,
    write_queue: VecDeque<u8>,
    established: bool,
    deadline: Clock,
}

struct PendingDns {
    host: String,
    version: IpVersion,
    query: dns::QueryHandle,
    reply: oneshot::Sender<Result<IpAddr>>,
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
        let mut device = PacketDevice::new(config.mtu);
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
                self.device.inbound.push_back(packet);
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
            Command::Connect(id, address, events, wake_needed) => {
                if !matches_route(&self.ipv6_routes, address.ip()) {
                    tracing::warn!(id, %address, "VPN has no IPv6 route for SOCKS destination");
                    let _ = events.try_send(StreamEvent::Closed);
                    return;
                }
                if self.connections.len() >= MAX_CONNECTIONS {
                    tracing::warn!(id, %address, "userspace TCP connection limit reached");
                    let _ = events.try_send(StreamEvent::Closed);
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
                                write_queue: VecDeque::new(),
                                established: false,
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
            Command::Data(id, data) => {
                if let Some(connection) = self.connections.get_mut(&id) {
                    if connection.write_queue.len() + data.len() > MAX_QUEUED_WRITE {
                        tracing::warn!(
                            id,
                            queued = connection.write_queue.len(),
                            incoming = data.len(),
                            "userspace TCP write queue limit reached"
                        );
                        self.close(id);
                    } else {
                        connection.write_queue.extend(data);
                        self.stats.max_write_queue_bytes = self
                            .stats
                            .max_write_queue_bytes
                            .max(connection.write_queue.len());
                    }
                }
            }
            Command::Close(id) => self.close(id),
            Command::Configure(_, _, _) | Command::Reset => unreachable!(),
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
        let started = Clock::now();
        self.stats.polls += 1;
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.outbound.pop_front() {
            self.stats.outbound_packets += 1;
            self.stats.outbound_bytes += packet.len() as u64;
            tracing::trace!(bytes = packet.len(), "userspace stack produced VPN packet");
            self.io
                .try_send(packet)
                .map_err(|_| StackError::PacketDelivery)?;
        }
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
                    let address =
                        addresses
                            .iter()
                            .find_map(|address| match (request.version, address) {
                                (IpVersion::V4, IpAddress::Ipv4(value)) => Some(IpAddr::V4(*value)),
                                (IpVersion::V6, IpAddress::Ipv6(value)) => Some(IpAddr::V6(*value)),
                                _ => None,
                            });
                    tracing::debug!(host = %request.host, ?address, "tunneled DNS query completed");
                    let _ = request.reply.send(address.ok_or(StackError::NoDnsAddress));
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
            if !connection.established && socket.state() == tcp::State::Established {
                connection.established = true;
                tracing::debug!(id, "userspace TCP connection established");
                if connection.events.try_send(StreamEvent::Connected).is_err() {
                    tracing::debug!(id, "TCP client disappeared before connection completed");
                    close.push(id);
                    continue;
                }
            }
            if !socket.is_active() {
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
                if socket.can_send() && !connection.write_queue.is_empty() {
                    let data = connection.write_queue.make_contiguous();
                    match socket.send_slice(data) {
                        Ok(written) => {
                            self.stats.tcp_write_bytes += written as u64;
                            tracing::trace!(id, bytes = written, "userspace TCP data queued");
                            connection.write_queue.drain(..written);
                        }
                        Err(error) => {
                            tracing::warn!(id, ?error, "userspace TCP send failed");
                            close.push(id);
                            continue;
                        }
                    }
                }
                if socket.can_recv() && connection.events.capacity() == 0 {
                    self.stats.event_queue_blocked += 1;
                    connection.wake_needed.store(true, Ordering::Release);
                }
                if socket.can_recv() && connection.events.capacity() > 0 {
                    let mut buffer = vec![0; TCP_READ_BUFFER_BYTES];
                    match socket.recv_slice(&mut buffer) {
                        Ok(read) => {
                            self.stats.tcp_read_bytes += read as u64;
                            if read == TCP_READ_BUFFER_BYTES {
                                self.stats.full_tcp_reads += 1;
                            }
                            tracing::trace!(id, bytes = read, "userspace TCP data received");
                            buffer.truncate(read);
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
                || (socket.can_recv() && connection.events.capacity() > 0)
                || (!connection.write_queue.is_empty() && socket.can_send())
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
        let protocol_delay = self
            .iface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()));
        protocol_delay.into_iter().chain(application_delay).min()
    }

    fn log_status(&mut self) {
        let window = self.last_status.elapsed();
        self.last_status = Clock::now();
        let stats = std::mem::take(&mut self.stats);
        if stats.inbound_packets == 0 && stats.outbound_packets == 0 && self.connections.is_empty()
        {
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
            outbound_packets = stats.outbound_packets,
            outbound_bytes = stats.outbound_bytes,
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
}

async fn wait_for_timer(delay: Option<Duration>) {
    match delay {
        Some(delay) => time::sleep(delay).await,
        None => std::future::pending().await,
    }
}

fn reject_without_tunnel(command: Command) {
    match command {
        Command::Resolve(_, _, reply) => {
            let _ = reply.send(Err(StackError::VpnDown));
        }
        Command::Connect(_, _, events, _) => {
            let _ = events.try_send(StreamEvent::Closed);
        }
        _ => {}
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
