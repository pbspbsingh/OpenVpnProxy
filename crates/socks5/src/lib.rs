use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use ovpn_netstack::{Stack, StackError, StreamEvent};
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
const GREETING_BYTES: usize = 2;
const REQUEST_HEADER_BYTES: usize = 4;
const IPV4_ADDRESS_BYTES: usize = 4;
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
const READY_CHECK_INTERVAL: Duration = Duration::from_millis(250);
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
    let Some(route) = router.select(&destination) else {
        tracing::warn!(?destination, "SOCKS5 request rejected: no healthy VPN host");
        reply(&mut stream, REPLY_NETWORK).await?;
        return Ok(());
    };
    let stack = route.stack();
    if !stack.is_ready() {
        tracing::warn!("SOCKS5 request rejected because VPN went down");
        reply(&mut stream, REPLY_NETWORK).await?;
        return Ok(());
    }
    let address = match destination {
        DestinationHost::Ipv4(address) => address,
        DestinationHost::Domain(host) => {
            tracing::debug!(%host, "resolving SOCKS5 destination through assigned VPN");
            match stack.resolve(&host).await {
                Ok(address) => {
                    tracing::debug!(%host, %address, "SOCKS5 destination resolved");
                    address
                }
                Err(error) => {
                    tracing::warn!(%host, %error, "SOCKS5 destination lookup failed");
                    reply(&mut stream, REPLY_HOST).await?;
                    return Ok(());
                }
            }
        }
    };
    let destination = SocketAddrV4::new(address, port);
    tracing::debug!(%destination, "connecting SOCKS5 destination through VPN");
    let (id, mut events) = match stack.connect(destination).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%destination, %error, "SOCKS5 tunnel connection failed");
            reply(&mut stream, REPLY_NETWORK).await?;
            return Ok(());
        }
    };
    let connected = match time::timeout(TUNNEL_CONNECT_TIMEOUT, events.recv()).await {
        Ok(Some(StreamEvent::Connected)) => true,
        Ok(Some(StreamEvent::Closed) | None) => {
            tracing::warn!(id, %destination, "SOCKS5 tunnel closed before connecting");
            false
        }
        Ok(Some(StreamEvent::Data(_))) => {
            tracing::warn!(id, %destination, "SOCKS5 tunnel sent data before connecting");
            false
        }
        Err(_) => {
            tracing::warn!(id, %destination, "SOCKS5 tunnel connect timed out");
            false
        }
    };
    if !connected {
        let close_result = stack.close(id);
        reply(&mut stream, REPLY_HOST).await?;
        close_result?;
        return Ok(());
    }
    tracing::debug!(id, %destination, "SOCKS5 tunnel connected");
    reply(&mut stream, REPLY_OK).await?;

    let (mut reader, mut writer) = stream.into_split();
    let mut buffer = [0; TRANSFER_BUFFER_BYTES];
    let mut ready_check = time::interval(READY_CHECK_INTERVAL);
    ready_check.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let transfer = async {
        loop {
            tokio::select! {
                read = reader.read(&mut buffer) => {
                    match read {
                        Ok(0) => {
                            tracing::debug!(id, "SOCKS5 client closed its connection");
                            break;
                        }
                        Ok(count) => {
                            tracing::trace!(id, bytes = count, "forwarding SOCKS5 client data into VPN");
                            stack.data(id, buffer[..count].to_vec())?;
                        }
                        Err(error) => return Err(SocksError::Io(error)),
                    }
                }
                event = events.recv() => match event {
                    Some(StreamEvent::Data(data)) => {
                        tracing::trace!(id, bytes = data.len(), "forwarding VPN data to SOCKS5 client");
                        time::timeout(SOCKET_IO_TIMEOUT, writer.write_all(&data))
                            .await.map_err(|_| SocksError::SocketTimeout)??;
                    }
                    Some(StreamEvent::Connected) => {}
                    Some(StreamEvent::Closed) | None => {
                        tracing::debug!(id, "VPN destination closed SOCKS5 connection");
                        break;
                    }
                },
                _ = ready_check.tick() => if !stack.is_ready() {
                    tracing::warn!(id, "VPN went down during SOCKS5 transfer");
                    break;
                },
            }
        }
        Ok(())
    }
    .await;
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
