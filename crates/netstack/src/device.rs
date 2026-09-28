use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub(crate) struct PacketDevice {
    pub(crate) inbound: VecDeque<Vec<u8>>,
    pub(crate) outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl PacketDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            mtu,
        }
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

pub(crate) struct TransmitPacket<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for TransmitPacket<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = ReceivePacket;
    type TxToken<'a> = TransmitPacket<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inbound
            .pop_front()
            .map(|packet| (ReceivePacket(packet), TransmitPacket(&mut self.outbound)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(TransmitPacket(&mut self.outbound))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
