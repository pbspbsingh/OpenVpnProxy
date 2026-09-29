use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant as Clock};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::sync::{mpsc, oneshot};
use tokio::time;

use crate::device::PacketDevice;
use crate::error::{Result, StackError};
use crate::stack::Command;
use crate::types::{StackPhase, StreamEvent, TunnelConfig};

const MAX_QUEUED_WRITE: usize = 256 * 1024;
const TCP_BUFFER: usize = 32 * 1024;

struct Connection {
    socket: SocketHandle,
    events: mpsc::Sender<StreamEvent>,
    write_queue: VecDeque<u8>,
    established: bool,
    deadline: Clock,
}

struct PendingDns {
    host: String,
    query: dns::QueryHandle,
    reply: oneshot::Sender<Result<Ipv4Addr>>,
    deadline: Clock,
}

struct Engine {
    iface: Interface,
    device: PacketDevice,
    sockets: SocketSet<'static>,
    dns_socket: SocketHandle,
    dns_available: bool,
    pending_dns: Vec<PendingDns>,
    connections: HashMap<u64, Connection>,
    next_port: u16,
    io: mpsc::Sender<Vec<u8>>,
}

impl Engine {
    fn new(config: TunnelConfig, io: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let mut device = PacketDevice::new(config.mtu);
        let mut iface =
            Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::ZERO);
        let mut inserted = false;
        iface.update_ip_addrs(|addresses| {
            inserted = addresses
                .push(IpCidr::new(ip(config.local).into(), 32))
                .is_ok();
        });
        if !inserted {
            return Err(StackError::AddressTableFull);
        }
        iface
            .routes_mut()
            .add_default_ipv4_route(ip(config.gateway))
            .map_err(|_| StackError::RouteTableFull)?;
        let servers: Vec<IpAddress> = config
            .dns
            .iter()
            .copied()
            .map(|addr| ip(addr).into())
            .collect();
        let mut sockets = SocketSet::new(vec![]);
        let dns_socket = sockets.add(dns::Socket::new(&servers, vec![]));
        tracing::debug!(local = %config.local, gateway = %config.gateway, mtu = config.mtu, dns_servers = servers.len(), "userspace packet stack initialized");
        Ok(Self {
            iface,
            device,
            sockets,
            dns_socket,
            dns_available: !servers.is_empty(),
            pending_dns: Vec::new(),
            connections: HashMap::new(),
            next_port: 40000,
            io,
        })
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Packet(packet) => {
                tracing::trace!(bytes = packet.len(), "packet delivered to userspace stack");
                self.device.inbound.push_back(packet);
            }
            Command::Resolve(host, reply) => {
                if !self.dns_available {
                    tracing::warn!(%host, "tunneled DNS requested without a DNS server");
                    let _ = reply.send(Err(StackError::NoDnsServer));
                    return;
                }
                tracing::debug!(%host, "starting tunneled DNS query");
                let socket = self.sockets.get_mut::<dns::Socket>(self.dns_socket);
                match socket.start_query(self.iface.context(), &host, DnsQueryType::A) {
                    Ok(query) => self.pending_dns.push(PendingDns {
                        host,
                        query,
                        reply,
                        deadline: Clock::now() + Duration::from_secs(10),
                    }),
                    Err(error) => {
                        tracing::warn!(%host, ?error, "could not start tunneled DNS query");
                        let _ = reply.send(Err(StackError::DnsQuery(format!("{error:?}"))));
                    }
                }
            }
            Command::Connect(id, address, events) => {
                if self.connections.len() >= 256 {
                    tracing::warn!(id, %address, "userspace TCP connection limit reached");
                    let _ = events.try_send(StreamEvent::Closed);
                    return;
                }
                tracing::debug!(id, %address, "opening userspace TCP connection");
                let socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                    tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                );
                let handle = self.sockets.add(socket);
                let port = self.next_port;
                self.next_port = if port >= 60000 { 40000 } else { port + 1 };
                let result = self.sockets.get_mut::<tcp::Socket>(handle).connect(
                    self.iface.context(),
                    (ip(*address.ip()), address.port()),
                    port,
                );
                match result {
                    Ok(()) => {
                        self.connections.insert(
                            id,
                            Connection {
                                socket: handle,
                                events,
                                write_queue: VecDeque::new(),
                                established: false,
                                deadline: Clock::now() + Duration::from_secs(15),
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
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.outbound.pop_front() {
            tracing::trace!(bytes = packet.len(), "userspace stack produced VPN packet");
            self.io
                .try_send(packet)
                .map_err(|_| StackError::PacketDelivery)?;
        }
        let mut pending = Vec::new();
        for request in self.pending_dns.drain(..) {
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns_socket);
            if Clock::now() >= request.deadline {
                tracing::warn!(host = %request.host, "tunneled DNS query timed out");
                socket.cancel_query(request.query);
                let _ = request.reply.send(Err(StackError::DnsTimeout));
                continue;
            }
            match socket.get_query_result(request.query) {
                Ok(addresses) => {
                    let address = addresses.iter().next().map(|address| match address {
                        IpAddress::Ipv4(value) => *value,
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
                if socket.can_recv() && connection.events.capacity() > 0 {
                    let mut buffer = vec![0; 4096];
                    match socket.recv_slice(&mut buffer) {
                        Ok(read) => {
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
        Ok(())
    }

    fn shutdown(mut self) {
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

pub(crate) async fn run(mut rx: mpsc::Receiver<Command>, phase: Arc<AtomicU8>) {
    let started = Clock::now();
    let mut engine: Option<Engine> = None;
    let mut ticker = time::interval(Duration::from_millis(10));
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        let command = tokio::select! {
            command = rx.recv() => Some(command),
            _ = ticker.tick() => None,
        };
        match command {
            Some(Some(Command::Configure(config, io, reply))) => {
                phase.store(StackPhase::Offline as u8, Ordering::Release);
                if let Some(old) = engine.take() {
                    old.shutdown();
                }
                match Engine::new(config, io) {
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
            Some(Some(Command::Reset)) => {
                tracing::debug!("resetting userspace packet stack");
                phase.store(StackPhase::Offline as u8, Ordering::Release);
                if let Some(old) = engine.take() {
                    old.shutdown();
                }
            }
            Some(Some(command)) => {
                if let Some(engine) = &mut engine {
                    engine.handle(command);
                } else {
                    reject_without_tunnel(command);
                }
            }
            Some(None) => break,
            None => {}
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

fn reject_without_tunnel(command: Command) {
    match command {
        Command::Resolve(_, reply) => {
            let _ = reply.send(Err(StackError::VpnDown));
        }
        Command::Connect(_, _, events) => {
            let _ = events.try_send(StreamEvent::Closed);
        }
        _ => {}
    }
}

fn ip(address: Ipv4Addr) -> Ipv4Address {
    address
}
