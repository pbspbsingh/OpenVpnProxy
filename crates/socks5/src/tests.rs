use std::sync::{Arc, Mutex};

use tokio::io::{DuplexStream, duplex};

use super::*;

#[derive(Clone)]
struct TestConnector(Arc<Mutex<Option<DuplexStream>>>);

impl Connector for TestConnector {
    type Stream = DuplexStream;

    async fn connect(
        &self,
        _source: IpAddr,
        destination: DestinationHost,
        port: u16,
    ) -> std::result::Result<DuplexStream, ConnectError> {
        assert!(
            matches!(destination, DestinationHost::Ipv4(address) if address == Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_eq!(port, 443);
        Ok(self.0.lock().unwrap().take().unwrap())
    }
}

fn connection() -> (DuplexStream, DuplexStream, DuplexStream, TestConnector) {
    let (client, server) = duplex(1024);
    let (tunnel, peer) = duplex(1024);
    (
        client,
        server,
        peer,
        TestConnector(Arc::new(Mutex::new(Some(tunnel)))),
    )
}

async fn negotiate(client: &mut DuplexStream) {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    client
        .write_all(&[5, 1, 0, 1, 203, 0, 113, 7, 1, 187])
        .await
        .unwrap();
    let mut reply = [0; SOCKS_REPLY_BYTES];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[REPLY_CODE_INDEX], REPLY_OK);
}

#[tokio::test]
async fn client_half_close_preserves_the_final_response() {
    let (mut client, mut server, mut peer, connector) = connection();
    let relay = serve(&mut server, Ipv4Addr::LOCALHOST.into(), connector);
    let request = async {
        negotiate(&mut client).await;
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after request EOF");
    };
    let response = async {
        let mut request = Vec::new();
        peer.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        peer.write_all(b"response after request EOF").await.unwrap();
        peer.shutdown().await.unwrap();
    };
    time::timeout(Duration::from_secs(2), async {
        let (result, (), ()) = tokio::join!(relay, request, response);
        result.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn blocked_download_does_not_block_upload() {
    let (mut client, mut server, peer, connector) = connection();
    let (mut peer_reader, mut peer_writer) = tokio::io::split(peer);
    let upload = vec![1; 128 * 1024];
    let download = vec![2; 128 * 1024];
    let relay = serve(&mut server, Ipv4Addr::LOCALHOST.into(), connector);
    let client = async {
        negotiate(&mut client).await;
        // Do not read the response until the full upload has passed the relay.
        client.write_all(&upload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, download);
    };
    let receive = async {
        let mut received = Vec::new();
        peer_reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, upload);
    };
    let respond = async {
        peer_writer.write_all(&download).await.unwrap();
        peer_writer.shutdown().await.unwrap();
    };
    time::timeout(Duration::from_secs(2), async {
        let (result, (), (), ()) = tokio::join!(relay, client, receive, respond);
        result.unwrap();
    })
    .await
    .unwrap();
}
