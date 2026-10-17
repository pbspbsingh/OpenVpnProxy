use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

use super::*;
use crate::stack::{Stack, StackOwner};
use crate::stream::{StreamEvents, TunnelStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MSS: usize = 1360;
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

fn test_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index ^ (index >> 8) ^ (index >> 16)) as u8)
        .collect()
}

struct Peer {
    stack: Stack,
    outbound: mpsc::Receiver<Vec<u8>>,
    port: u16,
    next_seq: i32,
    initial_ack: i32,
    uploaded: Vec<u8>,
}

impl Peer {
    fn packet(&self, ack: i32, syn: bool, payload: &[u8]) -> Vec<u8> {
        self.control_packet(
            ack,
            if syn {
                TcpControl::Syn
            } else {
                TcpControl::None
            },
            payload,
        )
    }

    fn control_packet(&self, ack: i32, control: TcpControl, payload: &[u8]) -> Vec<u8> {
        let src = Ipv4Addr::new(1, 1, 1, 1);
        let dst = Ipv4Addr::new(10, 8, 0, 2);
        let tcp = TcpRepr {
            src_port: 443,
            dst_port: self.port,
            control,
            seq_number: TcpSeqNumber(self.next_seq),
            ack_number: Some(TcpSeqNumber(ack)),
            window_len: u16::MAX,
            window_scale: None,
            max_seg_size: (control == TcpControl::Syn).then_some(MSS as u16),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let caps = ChecksumCapabilities::default();
        let mut packet = vec![0; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut packet[..]), &caps);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut packet[ip.buffer_len()..]),
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            &caps,
        );
        packet
    }

    fn send(&mut self, ack: i32, payload: &[u8]) {
        self.stack
            .tx
            .try_send(Command::Packet(self.packet(ack, false, payload)))
            .ok()
            .unwrap();
        self.next_seq = self.next_seq.wrapping_add(payload.len() as i32);
    }

    async fn next_packet(&mut self) -> Vec<u8> {
        time::timeout(TEST_TIMEOUT, self.outbound.recv())
            .await
            .expect("stack stopped producing packets")
            .expect("stack output closed")
    }

    async fn receive_upload(&mut self) -> i32 {
        loop {
            let raw = self.next_packet().await;
            let ip = Ipv4Packet::new_checked(&raw[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.payload().is_empty() {
                continue;
            }
            assert_eq!(
                tcp.seq_number().0,
                self.initial_ack.wrapping_add(self.uploaded.len() as i32)
            );
            self.uploaded.extend_from_slice(tcp.payload());
            return self.initial_ack.wrapping_add(self.uploaded.len() as i32);
        }
    }

    async fn fill_send_buffer(&mut self) -> i32 {
        let mut ack = self.initial_ack;
        // Nagle can retain the final partial segment until an ACK arrives.
        while self.uploaded.len() < TCP_SEND_BUFFER_BYTES - MSS {
            ack = self.receive_upload().await;
        }
        ack
    }

    fn finish(&mut self, ack: i32, payload: &[u8]) {
        self.stack
            .tx
            .try_send(Command::Packet(self.control_packet(
                ack,
                TcpControl::Fin,
                payload,
            )))
            .ok()
            .unwrap();
        self.next_seq = self.next_seq.wrapping_add(payload.len() as i32 + 1);
    }

    async fn receive_until_fin(&mut self) {
        loop {
            let raw = self.next_packet().await;
            let ip = Ipv4Packet::new_checked(&raw[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.payload().is_empty() && !tcp.fin() {
                continue;
            }
            assert_eq!(
                tcp.seq_number().0,
                self.initial_ack.wrapping_add(self.uploaded.len() as i32)
            );
            self.uploaded.extend_from_slice(tcp.payload());
            let ack = self
                .initial_ack
                .wrapping_add(self.uploaded.len() as i32 + i32::from(tcp.fin()));
            self.send(ack, &[]);
            if tcp.fin() {
                return;
            }
        }
    }
}

async fn connected() -> (StackOwner, u64, StreamEvents, Peer) {
    let (tx, outbound) = mpsc::channel(1024);
    let owner = StackOwner::start(
        TunnelConfig::new(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 1),
            vec![],
            1400,
            None,
        )
        .unwrap(),
        tx,
    )
    .await
    .unwrap();
    let stack = owner.client();
    let (id, mut events) = stack.open("1.1.1.1:443".parse().unwrap()).await.unwrap();
    let mut peer = Peer {
        stack: stack.clone(),
        outbound,
        port: 0,
        next_seq: 1000,
        initial_ack: 0,
        uploaded: Vec::new(),
    };
    let syn = peer.next_packet().await;
    let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn());
    peer.port = tcp.src_port();
    peer.initial_ack = tcp.seq_number().0.wrapping_add(1);
    owner
        .packet(peer.packet(peer.initial_ack, true, &[]))
        .unwrap();
    peer.next_seq += 1;
    assert!(matches!(
        time::timeout(TEST_TIMEOUT, events.recv()).await.unwrap(),
        Some(StreamEvent::Connected)
    ));
    (owner, id, events, peer)
}

#[test]
fn ready_work_yields_without_a_timer() {
    let mut wait = pin!(wait_for_timer(Some(Duration::ZERO)));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    // No runtime or clock advancement is needed to resume ready work.
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
}

#[test]
fn pending_connect_waits_for_protocol_progress_instead_of_spinning() {
    let config = TunnelConfig::new(
        "10.8.0.2".parse().unwrap(),
        "10.8.0.1".parse().unwrap(),
        vec![],
        1400,
        None,
    )
    .unwrap();
    let (io, _outbound) = mpsc::channel(1024);
    let mut engine = Engine::new(0, config, io).unwrap();
    let (events, _received) = mpsc::channel(32);
    let (_writer, writes) = mpsc::channel(32);
    let (write_finished, _finished) = oneshot::channel();
    engine.handle(Command::Connect(ConnectRequest {
        id: 0,
        address: "1.1.1.1:443".parse().unwrap(),
        events,
        wake_needed: Arc::new(AtomicBool::new(false)),
        writes,
        write_finished,
    }));
    engine.tick(Instant::ZERO).unwrap();
    assert!(
        engine
            .next_delay(Instant::ZERO)
            .is_some_and(|delay| !delay.is_zero())
    );
}

#[tokio::test]
async fn blocked_upload_receives_responses_and_resumes_after_ack() {
    let (stack, id, events, mut peer) = connected().await;
    let payload = test_payload(1024 * 1024);
    let expected = payload.clone();
    let (mut reader, mut writer) = tokio::io::split(TunnelStream::new(id, events));
    let upload = tokio::spawn(async move { writer.write_all(&payload).await });
    let ack = peer.fill_send_buffer().await;
    assert!(!upload.is_finished());

    // Withhold upload ACKs while sending a response in the reverse direction.
    let response = b"response during blocked upload";
    peer.send(peer.initial_ack, response);
    let mut data = vec![0; response.len()];
    time::timeout(TEST_TIMEOUT, reader.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, response);
    assert!(!upload.is_finished());
    assert!(stack.client().is_ready());

    peer.send(ack, &[]);
    while peer.uploaded.len() < expected.len() {
        let ack = peer.receive_upload().await;
        peer.send(ack, &[]);
    }
    time::timeout(TEST_TIMEOUT, upload)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(peer.uploaded, expected);
    assert!(stack.client().is_ready());
    stack.client().tx.send(Command::Close(id)).await.unwrap();
}

#[tokio::test]
async fn blocked_upload_is_released_when_connection_ends() {
    enum Termination {
        Close,
        Reset,
        DropEvents,
    }
    for termination in [
        Termination::Close,
        Termination::Reset,
        Termination::DropEvents,
    ] {
        let (stack, id, events, mut peer) = connected().await;
        let writer = events.writer();
        let upload = tokio::spawn(async move { writer.write(vec![1; 1024 * 1024]).await });
        peer.fill_send_buffer().await;
        assert!(!upload.is_finished());
        match termination {
            Termination::Close => {
                stack.client().tx.send(Command::Close(id)).await.unwrap();
            }
            Termination::Reset => stack.shutdown().await,
            Termination::DropEvents => drop(events),
        }
        let result = time::timeout(TEST_TIMEOUT, upload).await.unwrap().unwrap();
        assert!(matches!(result, Err(StackError::Disconnected)));
    }
}

#[tokio::test]
async fn buffered_download_resumes_after_consumer_queue_fills() {
    let (stack, id, mut events, mut peer) = connected().await;
    let total = 32 * MSS + 60 * 1024;
    let expected = test_payload(total);
    for chunk in expected.chunks(MSS) {
        peer.send(peer.initial_ack, chunk);
    }
    // Wait for the stack to acknowledge the whole burst while the consumer is idle.
    loop {
        let raw = peer.next_packet().await;
        let ip = Ipv4Packet::new_checked(&raw[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        if tcp.ack_number() == TcpSeqNumber(peer.next_seq) {
            break;
        }
    }
    let mut received = Vec::new();
    while received.len() < total {
        match time::timeout(TEST_TIMEOUT, events.recv()).await.unwrap() {
            Some(StreamEvent::Data(data)) => {
                assert_eq!(data.capacity(), data.len());
                assert!(data.len() <= TCP_READ_BUFFER_BYTES);
                received.extend(data);
            }
            event => panic!("unexpected connection event: {event:?}"),
        }
    }
    assert_eq!(received, expected);
    assert!(stack.client().is_ready());
    stack.client().tx.send(Command::Close(id)).await.unwrap();
}

#[tokio::test]
async fn download_preserves_data_across_receive_buffer_wraps() {
    let (stack, id, mut events, mut peer) = connected().await;
    let expected = test_payload(TCP_RECEIVE_BUFFER_BYTES * 2 + 17);
    let mut received = Vec::new();
    for batch in expected.chunks(60 * 1024) {
        for chunk in batch.chunks(MSS) {
            peer.send(peer.initial_ack, chunk);
        }
        let target = received.len() + batch.len();
        while received.len() < target {
            match time::timeout(TEST_TIMEOUT, events.recv()).await.unwrap() {
                Some(StreamEvent::Data(data)) => {
                    assert_eq!(data.capacity(), data.len());
                    assert!(data.len() <= TCP_READ_BUFFER_BYTES);
                    received.extend(data);
                }
                event => panic!("unexpected connection event: {event:?}"),
            }
        }
    }
    assert_eq!(received, expected);
    stack.client().tx.send(Command::Close(id)).await.unwrap();
}

#[tokio::test]
async fn local_half_close_drains_upload_then_receives_response_and_fin() {
    let (owner, id, events, mut peer) = connected().await;
    let mut stream = TunnelStream::new(id, events);
    let expected = test_payload(128 * 1024 + 17);
    stream.write_all(&expected).await.unwrap();
    let (shutdown, ()) = tokio::join!(stream.shutdown(), peer.receive_until_fin());
    shutdown.unwrap();
    assert_eq!(peer.uploaded, expected);

    let response = test_payload(19 * 1024 + 3);
    let ack = peer.initial_ack.wrapping_add(expected.len() as i32 + 1);
    for chunk in response.chunks(MSS) {
        peer.send(ack, chunk);
    }
    peer.finish(ack, &[]);
    let mut received = Vec::new();
    time::timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, response);
    owner.shutdown().await;
}

#[tokio::test]
async fn remote_half_close_allows_remaining_upload_to_finish() {
    let (owner, id, events, mut peer) = connected().await;
    let mut stream = TunnelStream::new(id, events);
    peer.finish(peer.initial_ack, b"last response");
    let mut received = Vec::new();
    time::timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"last response");

    let expected = test_payload(65 * 1024 + 3);
    stream.write_all(&expected).await.unwrap();
    let (shutdown, ()) = tokio::join!(stream.shutdown(), peer.receive_until_fin());
    shutdown.unwrap();
    assert_eq!(peer.uploaded, expected);
    owner.shutdown().await;
}

#[tokio::test]
async fn completed_tcp_close_preserves_download_waiting_for_the_reader() {
    let (owner, id, events, mut peer) = connected().await;
    let mut stream = TunnelStream::new(id, events);
    let response = test_payload(190 * 1024 + 17);
    for chunk in response.chunks(MSS) {
        peer.send(peer.initial_ack, chunk);
    }
    peer.finish(peer.initial_ack, &[]);
    // Ensure the peer FIN arrived before closing our write half. This takes
    // smoltcp through CLOSE-WAIT / LAST-ACK / CLOSED with unread receive data.
    loop {
        let raw = peer.next_packet().await;
        let ip = Ipv4Packet::new_checked(&raw[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        if tcp.ack_number() == TcpSeqNumber(peer.next_seq) {
            break;
        }
    }
    let (shutdown, ()) = tokio::join!(stream.shutdown(), peer.receive_until_fin());
    shutdown.unwrap();
    let mut received = Vec::new();
    time::timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, response);
    owner.shutdown().await;
}

#[tokio::test]
async fn peer_reset_after_fin_rejects_unacknowledged_upload() {
    for reset_claims_ack in [false, true] {
        let (owner, id, events, mut peer) = connected().await;
        let mut stream = TunnelStream::new(id, events);
        peer.finish(peer.initial_ack, b"response EOF");
        let mut response = Vec::new();
        time::timeout(TEST_TIMEOUT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"response EOF");

        stream.write_all(b"unacknowledged upload").await.unwrap();
        let reset_peer = async {
            let uploaded = peer.receive_upload().await;
            // Even an RST carrying an ACK number does not acknowledge TCP data.
            let ack = if reset_claims_ack {
                uploaded
            } else {
                peer.initial_ack
            };
            peer.stack
                .tx
                .try_send(Command::Packet(peer.control_packet(
                    ack,
                    TcpControl::Rst,
                    &[],
                )))
                .ok()
                .unwrap();
        };
        let (shutdown, ()) = time::timeout(TEST_TIMEOUT, async {
            tokio::join!(stream.shutdown(), reset_peer)
        })
        .await
        .unwrap();
        assert!(
            shutdown.is_err(),
            "reset discarded upload bytes but shutdown reported success"
        );
        assert_eq!(shutdown.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn owner_shutdown_invalidates_surviving_handles_and_wakes_streams() {
    let (owner, id, events, _peer) = connected().await;
    let client = owner.client();
    let mut stream = TunnelStream::new(id, events);
    owner.shutdown().await;
    assert!(!client.is_ready());
    assert!(matches!(
        client.connect("1.1.1.1:443".parse().unwrap()).await,
        Err(StackError::VpnDown)
    ));
    let mut byte = [0];
    assert!(
        time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        time::timeout(TEST_TIMEOUT, stream.write(b"data"))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn dropping_owner_cancels_worker_while_handles_remain() {
    let (owner, _id, events, _peer) = connected().await;
    let client = owner.client();
    drop(owner);
    time::timeout(TEST_TIMEOUT, async {
        while client.is_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(events);
}
