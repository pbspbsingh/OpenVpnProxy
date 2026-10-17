//! Application egress policy, independent of SOCKS negotiation and forwarding.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ovpn_netstack::{IpVersion, Stack, StackError, TunnelStream};
use ovpn_socks5::{ConnectError, Connector, DestinationHost};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time;

use crate::manager::{HostLease, RouterHandle};

const ADDRESS_FAMILY_DELAY: Duration = Duration::from_millis(250);

/// Keeps the routing reservation alive until forwarding and both half-closes finish.
pub(crate) struct LeasedStream {
    stream: TunnelStream,
    _lease: HostLease,
}

impl Connector for RouterHandle {
    type Stream = LeasedStream;

    async fn connect(
        &self,
        source: IpAddr,
        destination: DestinationHost,
        port: u16,
    ) -> Result<LeasedStream, ConnectError> {
        let started = Instant::now();
        let lease = self
            .select(source, destination.clone())
            .await
            .ok_or(ConnectError::NetworkUnavailable)?;
        let stack = lease.stack();
        let route_elapsed = started.elapsed();
        tracing::debug!(%source, ?destination, port, stack_id = stack.id(), ?route_elapsed, "VPN route acquired");
        let result = match destination {
            DestinationHost::Ipv4(address) => {
                stack.connect(SocketAddr::new(address.into(), port)).await
            }
            DestinationHost::Ipv6(address) => {
                stack.connect(SocketAddr::new(address.into(), port)).await
            }
            DestinationHost::Domain(host) => connect_domain(stack, &host, port).await,
        };
        let stream = result.map_err(|error| {
            tracing::debug!(%error, stack_id = stack.id(), "VPN destination connection failed");
            ConnectError::HostUnreachable
        })?;
        tracing::debug!(id = stream.id(), stack_id = stack.id(), ?route_elapsed, elapsed = ?started.elapsed(), "VPN destination connected");
        Ok(LeasedStream {
            stream,
            _lease: lease,
        })
    }
}

async fn connect_domain(
    stack: &Stack,
    host: &str,
    port: u16,
) -> ovpn_netstack::Result<TunnelStream> {
    let connect = |version| async move {
        let address = stack.resolve(host, version).await?;
        stack.connect(SocketAddr::new(address, port)).await
    };
    if !stack.supports_ipv6() {
        return connect(IpVersion::V4).await;
    }
    // Keep each lookup alive through its connection attempt. Losing attempts are
    // cancelled by dropping their futures, releasing DNS queries and sockets.
    connect_with_fallback(connect(IpVersion::V4), connect(IpVersion::V6)).await
}

async fn connect_with_fallback<T>(
    primary: impl Future<Output = Result<T, StackError>>,
    fallback: impl Future<Output = Result<T, StackError>>,
) -> Result<T, StackError> {
    tokio::pin!(primary, fallback);
    tokio::select! {
        result = &mut primary => match result {
            Ok(stream) => return Ok(stream),
            Err(_) => return fallback.await,
        },
        _ = time::sleep(ADDRESS_FAMILY_DELAY) => {}
    }
    tokio::select! {
        result = &mut primary => match result { Ok(stream) => Ok(stream), Err(_) => fallback.await },
        result = &mut fallback => match result { Ok(stream) => Ok(stream), Err(_) => primary.await },
    }
}

impl AsyncRead for LeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for LeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_primary_uses_fallback_without_waiting_for_stagger() {
        let result = time::timeout(
            Duration::from_millis(100),
            connect_with_fallback(async { Err(StackError::NoDnsAddress) }, async { Ok(42) }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn fallback_succeeds_while_primary_stays_pending() {
        let result = time::timeout(
            Duration::from_secs(1),
            connect_with_fallback(std::future::pending(), async { Ok(42) }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, 42);
    }
}
