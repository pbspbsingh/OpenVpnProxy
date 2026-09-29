use std::net::Ipv4Addr;

use crate::error::{Result, StackError};

pub(crate) const MIN_TUN_MTU: usize = 576;
pub(crate) const MAX_TUN_MTU: usize = 1400;

#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub local: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: usize,
}

impl TunnelConfig {
    pub fn new(local: Ipv4Addr, gateway: Ipv4Addr, dns: Vec<Ipv4Addr>, mtu: usize) -> Result<Self> {
        if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&mtu) {
            return Err(StackError::InvalidMtu);
        }
        Ok(Self {
            local,
            gateway,
            dns,
            mtu,
        })
    }
}

#[derive(Debug)]
pub enum StreamEvent {
    Connected,
    Data(Vec<u8>),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StackPhase {
    Offline = 0,
    Configured = 1,
    Ready = 2,
    Failed = 3,
}

impl StackPhase {
    pub(crate) fn from_raw(value: u8) -> Self {
        match value {
            value if value == Self::Configured as u8 => Self::Configured,
            value if value == Self::Ready as u8 => Self::Ready,
            value if value == Self::Failed as u8 => Self::Failed,
            _ => Self::Offline,
        }
    }
}
