use super::*;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Capture {
    fn logs(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + use<> {
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(self.clone())
            .finish()
    }
}

#[tokio::test]
async fn empty_client_eof_is_logged_before_destination_shutdown() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());
    let (mut client, mut client_io) = duplex(64);
    let (mut destination_io, mut destination) = duplex(64);
    client.shutdown().await.unwrap();
    let peer = async {
        let mut request = Vec::new();
        destination.read_to_end(&mut request).await.unwrap();
        assert!(request.is_empty());
        destination.shutdown().await.unwrap();
    };
    let (result, ()) = tokio::join!(copy(&mut client_io, &mut destination_io), peer);
    assert_eq!(result.unwrap(), (0, 0));
    let logs = capture.logs();
    let eof = logs
        .find("SOCKS5 forwarding EOF received side=\"client\"")
        .unwrap();
    let shutdown = logs
        .find("SOCKS5 forwarding write shutdown requested side=\"destination\"")
        .unwrap();
    assert!(eof < shutdown, "{logs}");
    assert!(
        logs.contains("outcome=\"complete\" read_bytes=0 written_bytes=0 read_eof=true"),
        "{logs}"
    );
}

struct FailWrites<S>(S);
impl<S: AsyncRead + Unpin> AsyncRead for FailWrites<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl<S: Unpin> AsyncWrite for FailWrites<S> {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn forwarding_error_identifies_client_write_and_retains_counts_without_payload() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());
    let (_client, client_io) = duplex(64);
    let (mut destination_io, mut destination) = duplex(64);
    let payload = b"private application data";
    destination.write_all(payload).await.unwrap();
    let error = copy(&mut FailWrites(client_io), &mut destination_io)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    let logs = capture.logs();
    assert!(
        logs.contains("SOCKS5 forwarding I/O error side=\"client\" operation=\"write\""),
        "{logs}"
    );
    assert!(
        logs.contains(&format!(
            "side=\"destination\" outcome=\"failed\" read_bytes={} written_bytes=0",
            payload.len()
        )),
        "{logs}"
    );
    assert!(!logs.contains(std::str::from_utf8(payload).unwrap()));
}

#[tokio::test]
async fn cancellation_preserves_forwarding_summary_for_both_sides() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());
    let (_client, mut client_io) = duplex(64);
    let (mut destination_io, _destination) = duplex(64);
    let mut forwarding = Box::pin(copy(&mut client_io, &mut destination_io));
    std::future::poll_fn(|cx| {
        assert!(forwarding.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(forwarding);
    let logs = capture.logs();
    for side in ["client", "destination"] {
        assert!(
            logs.contains(&format!(
                "side=\"{side}\" outcome=\"cancelled\" read_bytes=0 written_bytes=0"
            )),
            "{logs}"
        );
    }
}
