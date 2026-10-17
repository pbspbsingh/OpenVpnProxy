use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

use super::*;
use crate::stack::{Stack, StreamEvents};

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
        let src = Ipv4Addr::new(1, 1, 1, 1);
        let dst = Ipv4Addr::new(10, 8, 0, 2);
        let tcp = TcpRepr {
            src_port: 443,
            dst_port: self.port,
            control: if syn {
                TcpControl::Syn
            } else {
                TcpControl::None
            },
            seq_number: TcpSeqNumber(self.next_seq),
            ack_number: Some(TcpSeqNumber(ack)),
            window_len: u16::MAX,
            window_scale: None,
            max_seg_size: syn.then_some(MSS as u16),
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
        self.stack.packet(self.packet(ack, false, payload)).unwrap();
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
}

async fn connected() -> (Stack, u64, StreamEvents, Peer) {
    let stack = Stack::start();
    let (tx, outbound) = mpsc::channel(1024);
    stack
        .configure(
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
    stack.activate().unwrap();
    let (id, mut events) = stack.connect("1.1.1.1:443".parse().unwrap()).await.unwrap();
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
    stack
        .packet(peer.packet(peer.initial_ack, true, &[]))
        .unwrap();
    peer.next_seq += 1;
    assert!(matches!(
        time::timeout(TEST_TIMEOUT, events.recv()).await.unwrap(),
        Some(StreamEvent::Connected)
    ));
    (stack, id, events, peer)
}

#[test]
fn ready_work_yields_without_a_timer() {
    let mut wait = pin!(wait_for_timer(Some(Duration::ZERO)));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    // No runtime or clock advancement is needed to resume ready work.
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(()));
}

#[tokio::test]
async fn blocked_upload_receives_responses_and_resumes_after_ack() {
    let (stack, id, mut events, mut peer) = connected().await;
    let payload = test_payload(1024 * 1024);
    let expected = payload.clone();
    let writer = events.writer();
    let upload = tokio::spawn(async move { writer.write(payload).await });
    let ack = peer.fill_send_buffer().await;
    assert!(!upload.is_finished());

    // Withhold upload ACKs while sending a response in the reverse direction.
    peer.send(peer.initial_ack, b"response during blocked upload");
    match time::timeout(TEST_TIMEOUT, events.recv()).await.unwrap() {
        Some(StreamEvent::Data(data)) => assert_eq!(data, b"response during blocked upload"),
        event => panic!("unexpected connection event: {event:?}"),
    }
    assert!(!upload.is_finished());
    assert!(stack.is_ready());

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
    assert!(stack.is_ready());
    stack.close(id).unwrap();
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
            Termination::Close => stack.close(id).unwrap(),
            Termination::Reset => stack.reset().await.unwrap(),
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
    assert!(stack.is_ready());
    stack.close(id).unwrap();
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
    stack.close(id).unwrap();
}
