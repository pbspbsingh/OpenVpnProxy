//! Observe forwarding boundaries without inspecting or retaining application data.

#[cfg(test)]
mod tests;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) async fn copy<C, D>(client: &mut C, destination: &mut D) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = ObservedIo::new(client, "client");
    let mut destination = ObservedIo::new(destination, "destination");
    let result = tokio::io::copy_bidirectional(&mut client, &mut destination).await;
    let outcome = if result.is_ok() { "complete" } else { "failed" };
    client.outcome = outcome;
    destination.outcome = outcome;
    result
}

struct ObservedIo<S> {
    inner: S,
    side: &'static str,
    started: Instant,
    read_bytes: u64,
    written_bytes: u64,
    read_eof: bool,
    shutdown_requested: bool,
    shutdown_complete: bool,
    outcome: &'static str,
}

impl<S> ObservedIo<S> {
    fn new(inner: S, side: &'static str) -> Self {
        Self {
            inner,
            side,
            started: Instant::now(),
            read_bytes: 0,
            written_bytes: 0,
            read_eof: false,
            shutdown_requested: false,
            shutdown_complete: false,
            outcome: "cancelled",
        }
    }

    fn error(&self, operation: &'static str, error: &io::Error) {
        tracing::warn!(side = self.side, operation, %error, kind = ?error.kind(),
            read_bytes = self.read_bytes, written_bytes = self.written_bytes,
            read_eof = self.read_eof, shutdown_requested = self.shutdown_requested,
            elapsed = ?self.started.elapsed(), "SOCKS5 forwarding I/O error");
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let before = buf.filled().len();
        let requested = buf.remaining();
        let result = ready!(Pin::new(&mut this.inner).poll_read(cx, buf));
        match &result {
            Ok(()) => {
                let read = buf.filled().len() - before;
                if read > 0 && this.read_bytes == 0 {
                    tracing::info!(side = this.side, bytes = read, elapsed = ?this.started.elapsed(), "SOCKS5 first forwarding read");
                }
                this.read_bytes += read as u64;
                if requested > 0 && read == 0 && !this.read_eof {
                    this.read_eof = true;
                    tracing::info!(side = this.side, read_bytes = this.read_bytes, written_bytes = this.written_bytes,
                        elapsed = ?this.started.elapsed(), "SOCKS5 forwarding EOF received");
                }
            }
            Err(error) => this.error("read", error),
        }
        Poll::Ready(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_write(cx, data));
        match &result {
            Ok(written) => {
                if *written > 0 && this.written_bytes == 0 {
                    tracing::info!(side = this.side, bytes = written, elapsed = ?this.started.elapsed(), "SOCKS5 first forwarding write");
                }
                this.written_bytes += *written as u64;
            }
            Err(error) => this.error("write", error),
        }
        Poll::Ready(result)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        if let Err(error) = &result {
            this.error("flush", error);
        }
        Poll::Ready(result)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.shutdown_requested {
            this.shutdown_requested = true;
            tracing::info!(side = this.side, read_bytes = this.read_bytes, written_bytes = this.written_bytes,
                elapsed = ?this.started.elapsed(), "SOCKS5 forwarding write shutdown requested");
        }
        let result = ready!(Pin::new(&mut this.inner).poll_shutdown(cx));
        match &result {
            Ok(()) if !this.shutdown_complete => {
                this.shutdown_complete = true;
                tracing::info!(side = this.side, elapsed = ?this.started.elapsed(), "SOCKS5 forwarding write shutdown completed");
            }
            Err(error) => this.error("shutdown", error),
            _ => {}
        }
        Poll::Ready(result)
    }
}

impl<S> Drop for ObservedIo<S> {
    fn drop(&mut self) {
        tracing::info!(side = self.side, outcome = self.outcome,
            read_bytes = self.read_bytes, written_bytes = self.written_bytes,
            read_eof = self.read_eof, shutdown_requested = self.shutdown_requested,
            shutdown_complete = self.shutdown_complete, elapsed = ?self.started.elapsed(),
            "SOCKS5 forwarding side released");
    }
}
