//! Metadata for TCP connection teardown. Never retains or formats payload bytes.

use std::net::{IpAddr, SocketAddr};

use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};

pub(crate) struct TcpControl {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub sequence: i32,
    pub acknowledgment: Option<i32>,
    pub fin: bool,
    pub rst: bool,
    pub window: u16,
    pub hop_limit: u8,
    pub payload_bytes: usize,
}

pub(crate) fn control_packet(packet: &[u8]) -> Option<TcpControl> {
    let (source, destination, hop_limit, payload) = match packet.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp || ip.frag_offset() != 0 || ip.more_frags() {
                return None;
            }
            (
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.hop_limit(),
                ip.payload(),
            )
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ip.hop_limit(),
                ip.payload(),
            )
        }
        _ => return None,
    };
    let tcp = TcpPacket::new_checked(payload).ok()?;
    if !tcp.rst() && !tcp.fin() {
        return None;
    }
    Some(TcpControl {
        source: SocketAddr::new(source, tcp.src_port()),
        destination: SocketAddr::new(destination, tcp.dst_port()),
        sequence: tcp.seq_number().0,
        acknowledgment: tcp.ack().then(|| tcp.ack_number().0),
        fin: tcp.fin(),
        rst: tcp.rst(),
        window: tcp.window_len(),
        hop_limit,
        payload_bytes: tcp.payload().len(),
    })
}
