use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use ovpn_netstack::{IpVersion, Stack, StackError, StreamEvent};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

const REPLY_OK: u8 = 0x00;
const REPLY_FAILURE: u8 = 0x01;
const REPLY_NETWORK: u8 = 0x03;
const REPLY_HOST: u8 = 0x04;
const REPLY_COMMAND: u8 = 0x07;
const REPLY_ADDRESS: u8 = 0x08;
const SOCKS_VERSION: u8 = 5;
const NO_AUTH_METHOD: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT_COMMAND: u8 = 1;
const IPV4_ADDRESS_TYPE: u8 = 1;
const DOMAIN_ADDRESS_TYPE: u8 = 3;
const IPV6_ADDRESS_TYPE: u8 = 4;
const GREETING_BYTES: usize = 2;
const REQUEST_HEADER_BYTES: usize = 4;
const IPV4_ADDRESS_BYTES: usize = 4;
const IPV6_ADDRESS_BYTES: usize = 16;
const PORT_BYTES: usize = 2;
const SOCKS_REPLY_BYTES: usize = 10;
const VERSION_INDEX: usize = 0;
const GREETING_METHOD_COUNT_INDEX: usize = 1;
const REQUEST_COMMAND_INDEX: usize = 1;
const REPLY_CODE_INDEX: usize = 1;
const REQUEST_RESERVED_INDEX: usize = 2;
const ADDRESS_TYPE_INDEX: usize = 3;
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(16);
const IPV6_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_FALLBACK_WINDOW: Duration = Duration::from_millis(75);
const READY_CHECK_INTERVAL: Duration = Duration::from_millis(250);
const TRANSFER_STATUS_INTERVAL: Duration = Duration::from_secs(10);
const TRANSFER_BUFFER_BYTES: usize = 8192;

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("SOCKS socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("SOCKS socket operation timed out")]
    SocketTimeout,
    #[error("tunnel stack failed: {0}")]
    Stack(#[from] StackError),
}

type Result<T> = std::result::Result<T, SocksError>;

#[derive(Clone, Debug)]
pub enum DestinationHost {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

pub trait RouteLease: Send {
    fn stack(&self) -> &Stack;
}

pub trait RouteProvider: Clone + Send + Sync + 'static {
    type Lease: RouteLease;

    fn select(&self, destination: &DestinationHost) -> Option<Self::Lease>;
}

async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    let mut response = [0; SOCKS_REPLY_BYTES];
    response[VERSION_INDEX] = SOCKS_VERSION;
    response[REPLY_CODE_INDEX] = code;
    response[ADDRESS_TYPE_INDEX] = IPV4_ADDRESS_TYPE;
    stream.write_all(&response).await?;
    Ok(())
}

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    time::timeout(SOCKET_IO_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| SocksError::SocketTimeout)??;
    Ok(())
}

pub async fn handle<R: RouteProvider>(mut stream: TcpStream, router: R) -> Result<()> {
    let started = Instant::now();
    tracing::debug!("SOCKS5 handshake started");
    let mut greeting = [0; GREETING_BYTES];
    read_exact(&mut stream, &mut greeting).await?;
    if greeting[VERSION_INDEX] != SOCKS_VERSION || greeting[GREETING_METHOD_COUNT_INDEX] == 0 {
        tracing::debug!("SOCKS5 client sent an invalid greeting");
        return Ok(());
    }
    let mut methods = vec![0; greeting[GREETING_METHOD_COUNT_INDEX] as usize];
    read_exact(&mut stream, &mut methods).await?;
    if !methods.contains(&NO_AUTH_METHOD) {
        tracing::debug!("SOCKS5 client does not support no-authentication method");
        stream
            .write_all(&[SOCKS_VERSION, NO_ACCEPTABLE_METHOD])
            .await?;
        return Ok(());
    }
    stream.write_all(&[SOCKS_VERSION, NO_AUTH_METHOD]).await?;

    let mut request = [0; REQUEST_HEADER_BYTES];
    read_exact(&mut stream, &mut request).await?;
    if request[VERSION_INDEX] != SOCKS_VERSION || request[REQUEST_RESERVED_INDEX] != 0 {
        tracing::debug!("SOCKS5 client sent an invalid request");
        reply(&mut stream, REPLY_FAILURE).await?;
        return Ok(());
    }
    if request[REQUEST_COMMAND_INDEX] != CONNECT_COMMAND {
        tracing::debug!(
            command = request[REQUEST_COMMAND_INDEX],
            "SOCKS5 command is unsupported"
        );
        reply(&mut stream, REPLY_COMMAND).await?;
        return Ok(());
    }
    let destination = match request[ADDRESS_TYPE_INDEX] {
        IPV4_ADDRESS_TYPE => {
            let mut raw = [0; IPV4_ADDRESS_BYTES];
            read_exact(&mut stream, &mut raw).await?;
            DestinationHost::Ipv4(Ipv4Addr::from(raw))
        }
        DOMAIN_ADDRESS_TYPE => {
            let mut length = [0; 1];
            read_exact(&mut stream, &mut length).await?;
            if length[0] == 0 {
                tracing::debug!("SOCKS5 client sent an empty domain");
                reply(&mut stream, REPLY_ADDRESS).await?;
                return Ok(());
            }
            let mut raw = vec![0; length[0] as usize];
            read_exact(&mut stream, &mut raw).await?;
            let host = match String::from_utf8(raw)
                .ok()
                .and_then(|host| idna::domain_to_ascii(&host).ok())
                .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty())
            {
                Some(host) => host,
                None => {
                    tracing::debug!("SOCKS5 client sent an invalid domain");
                    reply(&mut stream, REPLY_ADDRESS).await?;
                    return Ok(());
                }
            };
            DestinationHost::Domain(host)
        }
        IPV6_ADDRESS_TYPE => {
            let mut raw = [0; IPV6_ADDRESS_BYTES];
            read_exact(&mut stream, &mut raw).await?;
            let address = Ipv6Addr::from(raw);
            if address.is_unspecified() || address.is_multicast() {
                tracing::debug!(%address, "SOCKS5 client requested an invalid IPv6 destination");
                reply(&mut stream, REPLY_ADDRESS).await?;
                return Ok(());
            }
            DestinationHost::Ipv6(address)
        }
        _ => {
            tracing::debug!(
                address_type = request[ADDRESS_TYPE_INDEX],
                "SOCKS5 address type is unsupported"
            );
            reply(&mut stream, REPLY_ADDRESS).await?;
            return Ok(());
        }
    };
    let mut port = [0; PORT_BYTES];
    read_exact(&mut stream, &mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        tracing::debug!("SOCKS5 client requested port zero");
        reply(&mut stream, REPLY_ADDRESS).await?;
        return Ok(());
    }
    let route_started = Instant::now();
    let Some(route) = router.select(&destination) else {
        tracing::warn!(
            ?destination,
            "SOCKS5 request rejected: no VPN host with a route to the destination"
        );
        reply(&mut stream, REPLY_NETWORK).await?;
        return Ok(());
    };
    let route_elapsed = route_started.elapsed();
    let stack = route.stack();
    let stack_id = stack.id();
    if !stack.is_ready() {
        tracing::warn!("SOCKS5 request rejected because VPN went down");
        reply(&mut stream, REPLY_NETWORK).await?;
        return Ok(());
    }
    let mut dns_elapsed = None;
    let mut delayed_ipv4 = None;
    let addresses = match destination {
        DestinationHost::Ipv4(address) => vec![IpAddr::V4(address)],
        DestinationHost::Ipv6(address) => vec![IpAddr::V6(address)],
        DestinationHost::Domain(host) => {
            tracing::debug!(%host, "resolving SOCKS5 destination through assigned VPN");
            let dns_started = Instant::now();
            let mut addresses = Vec::new();
            if stack.supports_ipv6() {
                let ipv4 = stack.resolve(&host, IpVersion::V4);
                let ipv6 = stack.resolve(&host, IpVersion::V6);
                tokio::pin!(ipv4, ipv6);
                tokio::select! {
                    result = &mut ipv4 => {
                        if let Ok(IpAddr::V4(address)) = result {
                            addresses.push(IpAddr::V4(address));
                        } else if let Ok(IpAddr::V6(address)) = ipv6.await
                            && stack.can_route_ipv6(address)
                        {
                            addresses.push(IpAddr::V6(address));
                        }
                    }
                    result = &mut ipv6 => {
                        if let Ok(IpAddr::V6(address)) = result
                            && stack.can_route_ipv6(address)
                        {
                            addresses.push(IpAddr::V6(address));
                            match time::timeout(DNS_FALLBACK_WINDOW, &mut ipv4).await {
                                Ok(Ok(IpAddr::V4(address))) => addresses.push(IpAddr::V4(address)),
                                Err(_) => delayed_ipv4 = Some(host.clone()),
                                _ => {}
                            }
                        } else if let Ok(IpAddr::V4(address)) = ipv4.await {
                            addresses.push(IpAddr::V4(address));
                        }
                    }
                }
            } else if let Ok(IpAddr::V4(address)) = stack.resolve(&host, IpVersion::V4).await {
                addresses.push(IpAddr::V4(address));
            }
            dns_elapsed = Some(dns_started.elapsed());
            if addresses.is_empty() {
                tracing::warn!(%host, ?dns_elapsed, "SOCKS5 destination lookup returned no routable address");
                reply(&mut stream, REPLY_HOST).await?;
                return Ok(());
            }
            tracing::debug!(%host, ?addresses, ?dns_elapsed, "SOCKS5 destination resolved");
            addresses
        }
    };
    let mut connected = None;
    let connect_phase_started = Instant::now();
    let mut addresses: VecDeque<_> = addresses.into();
    loop {
        let address = if let Some(address) = addresses.pop_front() {
            address
        } else if let Some(host) = delayed_ipv4.take() {
            match stack.resolve(&host, IpVersion::V4).await {
                Ok(IpAddr::V4(address)) => IpAddr::V4(address),
                Err(error) => {
                    tracing::warn!(%host, %error, "IPv4 fallback lookup failed");
                    break;
                }
                Ok(_) => break,
            }
        } else {
            break;
        };
        let destination = SocketAddr::new(address, port);
        tracing::debug!(%destination, "connecting SOCKS5 destination through VPN");
        let connect_started = Instant::now();
        let (id, mut events) = match stack.connect(destination).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%destination, %error, elapsed = ?connect_started.elapsed(), "SOCKS5 tunnel connection failed");
                continue;
            }
        };
        let timeout = if address.is_ipv6() && (!addresses.is_empty() || delayed_ipv4.is_some()) {
            IPV6_CONNECT_TIMEOUT
        } else {
            TUNNEL_CONNECT_TIMEOUT
        };
        match time::timeout(timeout, events.recv()).await {
            Ok(Some(StreamEvent::Connected)) => {
                connected = Some((destination, id, events, connect_phase_started.elapsed()));
                break;
            }
            Ok(Some(StreamEvent::Closed) | None) => {
                tracing::warn!(id, %destination, elapsed = ?connect_started.elapsed(), "SOCKS5 tunnel closed before connecting");
            }
            Ok(Some(StreamEvent::Data(_))) => {
                tracing::warn!(id, %destination, elapsed = ?connect_started.elapsed(), "SOCKS5 tunnel sent data before connecting");
            }
            Err(_) => {
                tracing::warn!(id, %destination, elapsed = ?connect_started.elapsed(), "SOCKS5 tunnel connect timed out");
            }
        }
        if let Err(error) = stack.close(id) {
            tracing::debug!(id, %error, "SOCKS tunnel cleanup failed");
        }
    }
    let Some((destination, id, mut events, connect_elapsed)) = connected else {
        reply(&mut stream, REPLY_HOST).await?;
        return Ok(());
    };
    tracing::debug!(id, %destination, stack_id, ?route_elapsed, ?dns_elapsed, ?connect_elapsed, "SOCKS5 tunnel connected");
    reply(&mut stream, REPLY_OK).await?;

    let (mut reader, mut writer) = stream.into_split();
    let transfer_started = Instant::now();
    let mut client_bytes = 0_u64;
    let mut server_bytes = 0_u64;
    let mut last_client_bytes = 0_u64;
    let mut last_server_bytes = 0_u64;
    let mut last_status = Instant::now();
    let mut first_client_data: Option<Instant> = None;
    let mut first_response: Option<Duration> = None;
    let mut request_to_first_response: Option<Duration> = None;
    let mut end_reason = "error";
    let mut buffer = [0; TRANSFER_BUFFER_BYTES];
    let mut ready_check = time::interval(READY_CHECK_INTERVAL);
    ready_check.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut status = time::interval(TRANSFER_STATUS_INTERVAL);
    status.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let transfer = async {
        loop {
            tokio::select! {
                read = reader.read(&mut buffer) => {
                    match read {
                        Ok(0) => {
                            tracing::debug!(id, "SOCKS5 client closed its connection");
                            end_reason = "client_closed";
                            break;
                        }
                        Ok(count) => {
                            tracing::trace!(id, bytes = count, "forwarding SOCKS5 client data into VPN");
                            stack.data(id, buffer[..count].to_vec())?;
                            first_client_data.get_or_insert_with(Instant::now);
                            client_bytes += count as u64;
                        }
                        Err(error) => return Err(SocksError::Io(error)),
                    }
                }
                event = events.recv() => match event {
                    Some(StreamEvent::Data(data)) => {
                        tracing::trace!(id, bytes = data.len(), "forwarding VPN data to SOCKS5 client");
                        time::timeout(SOCKET_IO_TIMEOUT, writer.write_all(&data))
                            .await.map_err(|_| SocksError::SocketTimeout)??;
                        if first_response.is_none() {
                            first_response = Some(transfer_started.elapsed());
                            request_to_first_response = first_client_data.map(|when| when.elapsed());
                        }
                        server_bytes += data.len() as u64;
                    }
                    Some(StreamEvent::Connected) => {}
                    Some(StreamEvent::Closed) | None => {
                        tracing::debug!(id, "VPN destination closed SOCKS5 connection");
                        end_reason = "destination_closed";
                        break;
                    }
                },
                _ = ready_check.tick() => if !stack.is_ready() {
                    tracing::warn!(id, "VPN went down during SOCKS5 transfer");
                    end_reason = "vpn_down";
                    break;
                },
                _ = status.tick() => {
                    if client_bytes != last_client_bytes || server_bytes != last_server_bytes {
                        tracing::debug!(id, %destination, stack_id, window = ?last_status.elapsed(), client_bytes, server_bytes, window_client_bytes = client_bytes - last_client_bytes, window_server_bytes = server_bytes - last_server_bytes, "SOCKS5 transfer activity");
                    }
                    last_client_bytes = client_bytes;
                    last_server_bytes = server_bytes;
                    last_status = Instant::now();
                }
            }
        }
        Ok(())
    }
    .await;
    tracing::debug!(id, %destination, stack_id, outcome = if transfer.is_ok() { end_reason } else { "error" }, elapsed = ?started.elapsed(), transfer_elapsed = ?transfer_started.elapsed(), ?route_elapsed, ?dns_elapsed, ?connect_elapsed, ?first_response, ?request_to_first_response, client_bytes, server_bytes, "SOCKS5 transfer summary");
    let close_result = stack.close(id);
    let shutdown_result = writer.shutdown().await;
    if let Err(error) = &close_result {
        tracing::debug!(%error, "SOCKS tunnel close failed");
    }
    if let Err(error) = &shutdown_result {
        tracing::debug!(%error, "SOCKS socket shutdown failed");
    }
    transfer?;
    close_result?;
    shutdown_result?;
    Ok(())
}
