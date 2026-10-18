use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::stack::STREAM_WRITE_CHUNK_BYTES;
use crate::types::StreamEvent;

type ReserveWrite = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Bytes>, mpsc::error::SendError<()>>> + Send>,
>;

pub(crate) struct StreamEvents {
    rx: mpsc::Receiver<StreamEvent>,
    wake: Arc<Notify>,
    wake_needed: Arc<AtomicBool>,
    writes: Option<mpsc::Sender<Bytes>>,
    write_finished: oneshot::Receiver<()>,
}

impl StreamEvents {
    pub(crate) fn new(
        rx: mpsc::Receiver<StreamEvent>,
        wake: Arc<Notify>,
        wake_needed: Arc<AtomicBool>,
        writes: mpsc::Sender<Bytes>,
        write_finished: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            rx,
            wake,
            wake_needed,
            writes: Some(writes),
            write_finished,
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<StreamEvent> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<StreamEvent>> {
        let event = ready!(self.rx.poll_recv(cx));
        if event.is_some() && self.wake_needed.swap(false, Ordering::AcqRel) {
            self.wake.notify_one();
        }
        Poll::Ready(event)
    }

    #[cfg(test)]
    pub(crate) fn writer(&self) -> TestWriter {
        TestWriter {
            tx: self.writes.as_ref().unwrap().clone(),
            wake: Arc::clone(&self.wake),
        }
    }
}

impl Drop for StreamEvents {
    fn drop(&mut self) {
        self.rx.close();
        self.wake.notify_one();
    }
}

/// A virtual TCP stream whose read and write halves close independently.
///
/// Writes commit bytes to the stack's bounded send queue. Flush has the same
/// meaning as for a TCP socket: it does not wait for a peer acknowledgement.
/// Write shutdown keeps the virtual socket alive until queued bytes are
/// acknowledged and the TCP write half closes. Reads can continue meanwhile.
pub struct TunnelStream {
    id: u64,
    events: StreamEvents,
    buffered: Bytes,
    read_closed: bool,
    reserve: Option<ReserveWrite>,
    shutdown: WriteShutdown,
}

enum WriteShutdown {
    Pending,
    Complete,
    Failed,
}

impl TunnelStream {
    pub(crate) fn new(id: u64, events: StreamEvents) -> Self {
        Self {
            id,
            events,
            buffered: Bytes::new(),
            read_closed: false,
            reserve: None,
            shutdown: WriteShutdown::Pending,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let count = self.buffered.len().min(buffer.remaining());
                buffer.put_slice(&self.buffered[..count]);
                self.buffered.advance(count);
                if self.buffered.is_empty() {
                    self.buffered = Bytes::new();
                }
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.events.poll_recv(cx)) {
                Some(StreamEvent::Data(data)) => self.buffered = Bytes::from(data),
                Some(StreamEvent::ReadClosed) => self.read_closed = true,
                Some(StreamEvent::Connected) => continue,
                Some(StreamEvent::ConnectFailed(_)) | Some(StreamEvent::Closed) | None => {
                    return Poll::Ready(Err(disconnected()));
                }
            }
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(sender) = this.events.writes.as_ref() else {
            return Poll::Ready(Err(disconnected()));
        };
        let count = data.len().min(STREAM_WRITE_CHUNK_BYTES);
        if this.reserve.is_none() {
            match sender.try_reserve() {
                Ok(permit) => {
                    permit.send(Bytes::copy_from_slice(&data[..count]));
                    this.events.wake.notify_one();
                    return Poll::Ready(Ok(count));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(disconnected()));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        let reserve = this
            .reserve
            .get_or_insert_with(|| Box::pin(sender.clone().reserve_owned()));
        let result = ready!(reserve.as_mut().poll(cx));
        this.reserve = None;
        match result {
            Ok(permit) => {
                permit.send(Bytes::copy_from_slice(&data[..count]));
                this.events.wake.notify_one();
                Poll::Ready(Ok(count))
            }
            Err(_) => Poll::Ready(Err(disconnected())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.shutdown {
            WriteShutdown::Complete => return Poll::Ready(Ok(())),
            WriteShutdown::Failed => return Poll::Ready(Err(disconnected())),
            WriteShutdown::Pending => {}
        }
        self.reserve = None;
        self.events.writes.take();
        self.events.wake.notify_one();
        // Keep the socket owned until TCP drains accepted bytes and closes its write half.
        // Otherwise copy_bidirectional could drop it with an upload still queued.
        match ready!(Pin::new(&mut self.events.write_finished).poll(cx)) {
            Ok(()) => {
                self.shutdown = WriteShutdown::Complete;
                Poll::Ready(Ok(()))
            }
            Err(_) => {
                self.shutdown = WriteShutdown::Failed;
                Poll::Ready(Err(disconnected()))
            }
        }
    }
}

fn disconnected() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "VPN connection closed")
}

#[cfg(test)]
pub(crate) struct TestWriter {
    tx: mpsc::Sender<Bytes>,
    wake: Arc<Notify>,
}

#[cfg(test)]
impl TestWriter {
    pub(crate) async fn write(&self, data: Vec<u8>) -> crate::Result<()> {
        let mut data = Bytes::from(data);
        while !data.is_empty() {
            let count = data.len().min(STREAM_WRITE_CHUNK_BYTES);
            self.tx
                .send(data.split_to(count))
                .await
                .map_err(|_| crate::StackError::Disconnected)?;
            self.wake.notify_one();
        }
        Ok(())
    }
}
