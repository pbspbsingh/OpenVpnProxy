use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;

use crate::tcp_diagnostics::control_packet;

const RECEIVE_QUEUE_CAPACITY: usize = 1024;

pub(crate) struct PacketDevice {
    stack_id: u64,
    pub stream_ids: HashMap<(u16, SocketAddr), u64>,
    inbound: VecDeque<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    // Remember a failed reservation even if capacity returns before the worker waits.
    pub output_blocked: bool,
    pub transmitted_packets: u64,
    pub transmitted_bytes: u64,
    mtu: usize,
}

impl PacketDevice {
    pub(crate) fn new(stack_id: u64, mtu: usize, output: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            stack_id,
            stream_ids: HashMap::new(),
            inbound: VecDeque::new(),
            output,
            output_blocked: false,
            transmitted_packets: 0,
            transmitted_bytes: 0,
            mtu,
        }
    }

    /// Drop incoming IP packets only when the bounded receive queue is full.
    /// TCP retransmission recovers these packets after tunnel output resumes.
    pub(crate) fn receive_packet(&mut self, packet: Vec<u8>) -> bool {
        if self.inbound.len() >= RECEIVE_QUEUE_CAPACITY {
            return false;
        }
        self.inbound.push_back(packet);
        true
    }
}

pub(crate) struct ReceivePacket(Vec<u8>);
impl RxToken for ReceivePacket {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(crate) struct TransmitPacket<'a> {
    stack_id: u64,
    stream_ids: &'a HashMap<(u16, SocketAddr), u64>,
    permit: mpsc::Permit<'a, Vec<u8>>,
    packets: &'a mut u64,
    bytes: &'a mut u64,
}
impl TxToken for TransmitPacket<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if let Some(control) = control_packet(&packet) {
            let stream_id = self
                .stream_ids
                .get(&(control.source.port(), control.destination))
                .copied();
            let span = tracing::info_span!("tcp_control", stack_id = self.stack_id, stream_id, direction = "outbound",
                source = %control.source, destination = %control.destination,
                sequence = control.sequence, acknowledgment = ?control.acknowledgment,
                fin = control.fin, rst = control.rst, window = control.window,
                hop_limit = control.hop_limit, payload_bytes = control.payload_bytes);
            let _entered = span.enter();
            if stream_id.is_some() {
                tracing::info!("TCP control packet queued to tunnel");
            } else {
                tracing::debug!("TCP control packet queued without a matching stream");
            }
        }
        self.permit.send(packet);
        *self.packets += 1;
        *self.bytes += len as u64;
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = ReceivePacket;
    type TxToken<'a> = TransmitPacket<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.inbound.is_empty() {
            return None;
        }
        // smoltcp may need to reply while processing an incoming packet.
        // Leave that packet queued until its reply can also be delivered.
        let Ok(permit) = self.output.try_reserve() else {
            self.output_blocked = true;
            return None;
        };
        let packet = self.inbound.pop_front()?;
        Some((
            ReceivePacket(packet),
            TransmitPacket {
                stack_id: self.stack_id,
                stream_ids: &self.stream_ids,
                permit,
                packets: &mut self.transmitted_packets,
                bytes: &mut self.transmitted_bytes,
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        let Ok(permit) = self.output.try_reserve() else {
            self.output_blocked = true;
            return None;
        };
        Some(TransmitPacket {
            stack_id: self.stack_id,
            stream_ids: &self.stream_ids,
            permit,
            packets: &mut self.transmitted_packets,
            bytes: &mut self.transmitted_bytes,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
