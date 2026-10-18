//! Application egress policy, independent of SOCKS negotiation and forwarding.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream::FuturesUnordered};
use ovpn_netstack::{IpVersion, Stack, StackError, TunnelStream};
use ovpn_socks5::{ConnectError, Connector, DestinationHost};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time;

use crate::manager::{HostLease, RouterHandle};

const ADDRESS_FAMILY_DELAY: Duration = Duration::from_millis(250);
const DOMAIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
        let addresses = stack.resolve(host, version).await?;
        connect_addresses(addresses, port, |address| stack.connect(address)).await
    };
    time::timeout(DOMAIN_CONNECT_TIMEOUT, async {
        if !stack.supports_ipv6() {
            return connect(IpVersion::V4).await;
        }
        // Losing lookups and connection attempts release their queries/sockets.
        connect_with_fallback(connect(IpVersion::V4), connect(IpVersion::V6)).await
    })
    .await
    .map_err(|_| StackError::ConnectTimeout)?
}

async fn connect_addresses<T, F, Fut>(
    addresses: Vec<IpAddr>,
    port: u16,
    connect: F,
) -> Result<T, StackError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, StackError>>,
{
    let mut addresses = addresses.into_iter().peekable();
    // These futures belong to the requesting task. Dropping the race releases
    // every losing socket immediately, without spawning or cancelling tasks.
    let mut attempts = FuturesUnordered::new();
    let mut next_attempt = time::Instant::now();
    let mut last_error = StackError::NoDnsAddress;
    loop {
        if (attempts.is_empty() || time::Instant::now() >= next_attempt)
            && let Some(address) = addresses.next()
        {
            attempts.push(connect(SocketAddr::new(address, port)));
            next_attempt = time::Instant::now() + ADDRESS_FAMILY_DELAY;
        }
        if attempts.is_empty() {
            return Err(last_error);
        }
        tokio::select! {
            result = attempts.next() => match result {
                Some(Ok(stream)) => return Ok(stream),
                Some(Err(error)) => last_error = error,
                None => return Err(last_error),
            },
            _ = time::sleep_until(next_attempt), if addresses.peek().is_some() => {}
        }
    }
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
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn later_dns_answer_wins_when_the_first_address_never_connects() {
        let addresses = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let dropped = Arc::new(AtomicBool::new(false));
        struct PendingAttempt(Arc<AtomicBool>);
        impl Drop for PendingAttempt {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let result = time::timeout(
            Duration::from_secs(2),
            connect_addresses(addresses, 443, |address| {
                let dropped = Arc::clone(&dropped);
                async move {
                    if address.ip() == "192.0.2.1".parse::<IpAddr>().unwrap() {
                        let _guard = PendingAttempt(dropped);
                        std::future::pending().await
                    } else {
                        Ok(address)
                    }
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, "192.0.2.2:443".parse().unwrap());
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn refused_dns_answer_tries_next_immediately_and_all_failures_return() {
        let addresses = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let result = time::timeout(
            Duration::from_millis(100),
            connect_addresses(addresses, 443, |address| async move {
                if address.ip() == "192.0.2.1".parse::<IpAddr>().unwrap() {
                    Err(StackError::Disconnected)
                } else {
                    Ok(address)
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, "192.0.2.2:443".parse().unwrap());
        assert!(matches!(
            connect_addresses(vec![result.ip()], 443, |_| async {
                Err::<(), _>(StackError::Disconnected)
            })
            .await,
            Err(StackError::Disconnected)
        ));
    }

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
