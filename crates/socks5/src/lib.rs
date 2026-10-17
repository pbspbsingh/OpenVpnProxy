//! SOCKS5 TCP CONNECT handling over an assigned userspace VPN stack.

#[cfg(test)]
mod tests;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
/// Errors while serving a SOCKS5 connection.
#[derive(Debug, Error)]
pub enum SocksError {
    #[error("SOCKS socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("SOCKS socket operation timed out")]
    SocketTimeout,
}

/// Result returned by the SOCKS5 handler.
pub type Result<T> = std::result::Result<T, SocksError>;

/// Destination supplied by a SOCKS5 client.
#[derive(Clone, Debug)]
pub enum DestinationHost {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

/// Connects a SOCKS destination using the application's routing policy.
/// The returned stream owns all resources needed for its entire lifetime.
pub trait Connector: Clone + Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    fn connect(
        &self,
        source: IpAddr,
        destination: DestinationHost,
        port: u16,
    ) -> impl Future<Output = std::result::Result<Self::Stream, ConnectError>> + Send;
}

/// SOCKS reply categories supplied by the egress connector.
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("no VPN route available")]
    NetworkUnavailable,
    #[error("destination could not be reached")]
    HostUnreachable,
}

/// Negotiates SOCKS5 and forwards both directions, preserving TCP half-close.
pub async fn handle<C: Connector>(mut stream: TcpStream, connector: C) -> Result<()> {
    let source = stream.peer_addr()?.ip();
    serve(&mut stream, source, connector).await
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin, C: Connector>(
    stream: &mut S,
    source: IpAddr,
    connector: C,
) -> Result<()> {
    let started = Instant::now();
    let Some((destination, port)) = read_request(stream).await? else {
        return Ok(());
    };
    let mut tunnel = match connector.connect(source, destination, port).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            tracing::debug!(%error, "SOCKS5 destination unavailable");
            let code = match error {
                ConnectError::NetworkUnavailable => REPLY_NETWORK,
                ConnectError::HostUnreachable => REPLY_HOST,
            };
            reply(stream, code).await?;
            return Ok(());
        }
    };
    reply(stream, REPLY_OK).await?;
    let (uploaded, downloaded) = tokio::io::copy_bidirectional(stream, &mut tunnel).await?;
    tracing::debug!(uploaded, downloaded, elapsed = ?started.elapsed(), "SOCKS5 connection finished");
    Ok(())
}

async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<Option<(DestinationHost, u16)>> {
    tracing::debug!("SOCKS5 handshake started");
    let mut greeting = [0; GREETING_BYTES];
    read_exact(stream, &mut greeting).await?;
    if greeting[VERSION_INDEX] != SOCKS_VERSION || greeting[GREETING_METHOD_COUNT_INDEX] == 0 {
        tracing::debug!("SOCKS5 client sent an invalid greeting");
        return Ok(None);
    }
    let mut methods = vec![0; greeting[GREETING_METHOD_COUNT_INDEX] as usize];
    read_exact(stream, &mut methods).await?;
    if !methods.contains(&NO_AUTH_METHOD) {
        tracing::debug!("SOCKS5 client does not support no-authentication method");
        stream
            .write_all(&[SOCKS_VERSION, NO_ACCEPTABLE_METHOD])
            .await?;
        return Ok(None);
    }
    stream.write_all(&[SOCKS_VERSION, NO_AUTH_METHOD]).await?;

    let mut request = [0; REQUEST_HEADER_BYTES];
    read_exact(stream, &mut request).await?;
    if request[VERSION_INDEX] != SOCKS_VERSION || request[REQUEST_RESERVED_INDEX] != 0 {
        tracing::debug!("SOCKS5 client sent an invalid request");
        reply(stream, REPLY_FAILURE).await?;
        return Ok(None);
    }
    if request[REQUEST_COMMAND_INDEX] != CONNECT_COMMAND {
        tracing::debug!(
            command = request[REQUEST_COMMAND_INDEX],
            "SOCKS5 command is unsupported"
        );
        reply(stream, REPLY_COMMAND).await?;
        return Ok(None);
    }
    let destination = match request[ADDRESS_TYPE_INDEX] {
        IPV4_ADDRESS_TYPE => {
            let mut raw = [0; IPV4_ADDRESS_BYTES];
            read_exact(stream, &mut raw).await?;
            DestinationHost::Ipv4(Ipv4Addr::from(raw))
        }
        DOMAIN_ADDRESS_TYPE => {
            let mut length = [0; 1];
            read_exact(stream, &mut length).await?;
            if length[0] == 0 {
                tracing::debug!("SOCKS5 client sent an empty domain");
                reply(stream, REPLY_ADDRESS).await?;
                return Ok(None);
            }
            let mut raw = vec![0; length[0] as usize];
            read_exact(stream, &mut raw).await?;
            let host = match String::from_utf8(raw)
                .ok()
                .and_then(|host| idna::domain_to_ascii(&host).ok())
                .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty())
            {
                Some(host) => host,
                None => {
                    tracing::debug!("SOCKS5 client sent an invalid domain");
                    reply(stream, REPLY_ADDRESS).await?;
                    return Ok(None);
                }
            };
            DestinationHost::Domain(host)
        }
        IPV6_ADDRESS_TYPE => {
            let mut raw = [0; IPV6_ADDRESS_BYTES];
            read_exact(stream, &mut raw).await?;
            let address = Ipv6Addr::from(raw);
            if address.is_unspecified() || address.is_multicast() {
                tracing::debug!(%address, "SOCKS5 client requested an invalid IPv6 destination");
                reply(stream, REPLY_ADDRESS).await?;
                return Ok(None);
            }
            DestinationHost::Ipv6(address)
        }
        _ => {
            tracing::debug!(
                address_type = request[ADDRESS_TYPE_INDEX],
                "SOCKS5 address type is unsupported"
            );
            reply(stream, REPLY_ADDRESS).await?;
            return Ok(None);
        }
    };
    let mut port = [0; PORT_BYTES];
    read_exact(stream, &mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        tracing::debug!("SOCKS5 client requested port zero");
        reply(stream, REPLY_ADDRESS).await?;
        return Ok(None);
    }
    Ok(Some((destination, port)))
}

async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> Result<()> {
    let mut response = [0; SOCKS_REPLY_BYTES];
    response[VERSION_INDEX] = SOCKS_VERSION;
    response[REPLY_CODE_INDEX] = code;
    response[ADDRESS_TYPE_INDEX] = IPV4_ADDRESS_TYPE;
    stream.write_all(&response).await?;
    Ok(())
}

async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<()> {
    time::timeout(SOCKET_IO_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| SocksError::SocketTimeout)??;
    Ok(())
}
