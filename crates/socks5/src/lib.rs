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

async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    time::timeout(Duration::from_secs(10), stream.read_exact(buf))
        .await
        .map_err(|_| SocksError::SocketTimeout)??;
    Ok(())
}

pub async fn handle(mut stream: TcpStream, stack: Stack) -> Result<()> {
    tracing::debug!("SOCKS5 handshake started");
    let mut greeting = [0; 2];
    read_exact(&mut stream, &mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        tracing::debug!("SOCKS5 client sent an invalid greeting");
        return Ok(());
    }
    let mut methods = vec![0; greeting[1] as usize];
    read_exact(&mut stream, &mut methods).await?;
    if !methods.contains(&0) {
        tracing::debug!("SOCKS5 client does not support no-authentication method");
        stream.write_all(&[5, 0xff]).await?;
        return Ok(());
    }
    stream.write_all(&[5, 0]).await?;

    let mut request = [0; 4];
    read_exact(&mut stream, &mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        tracing::debug!("SOCKS5 client sent an invalid request");
        reply(&mut stream, REPLY_FAILURE).await?;
        return Ok(());
    }
    if request[1] != 1 {
        tracing::debug!(command = request[1], "SOCKS5 command is unsupported");
        reply(&mut stream, REPLY_COMMAND).await?;
        return Ok(());
    }
    if !stack.is_ready() {
        tracing::warn!("SOCKS5 request rejected because VPN is down");
        reply(&mut stream, REPLY_NETWORK).await?;
        return Ok(());
    }

    let address = match request[3] {
        1 => {
            let mut raw = [0; 4];
            read_exact(&mut stream, &mut raw).await?;
            Ipv4Addr::from(raw)
        }
        3 => {
            let mut length = [0; 1];
            read_exact(&mut stream, &mut length).await?;
            if length[0] == 0 {
                tracing::debug!("SOCKS5 client sent an empty domain");
                reply(&mut stream, REPLY_ADDRESS).await?;
                return Ok(());
            }
            let mut raw = vec![0; length[0] as usize];
            read_exact(&mut stream, &mut raw).await?;
            let host = match String::from_utf8(raw) {
                Ok(host) => host,
                Err(_) => {
                    tracing::debug!("SOCKS5 client sent a non-UTF-8 domain");
                    reply(&mut stream, REPLY_ADDRESS).await?;
                    return Ok(());
                }
            };
            tracing::debug!(%host, "resolving SOCKS5 destination through VPN");
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
        _ => {
            tracing::debug!(
                address_type = request[3],
                "SOCKS5 address type is unsupported"
            );
            reply(&mut stream, REPLY_ADDRESS).await?;
            return Ok(());
        }
    };
    let mut port = [0; 2];
    read_exact(&mut stream, &mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        tracing::debug!("SOCKS5 client requested port zero");
        reply(&mut stream, REPLY_ADDRESS).await?;
        return Ok(());
    }
    if !stack.is_ready() {
        tracing::warn!("SOCKS5 request rejected because VPN went down");
        reply(&mut stream, REPLY_NETWORK).await?;
        return Ok(());
    }
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
    let connected = match time::timeout(Duration::from_secs(16), events.recv()).await {
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
    let mut buffer = [0; 8192];
    let mut ready_check = time::interval(Duration::from_millis(250));
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
                        time::timeout(Duration::from_secs(10), writer.write_all(&data))
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
