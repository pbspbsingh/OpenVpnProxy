use std::net::Ipv4Addr;

use crate::error::{Result, StackError};

#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub local: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: usize,
}

impl TunnelConfig {
    pub fn new(local: Ipv4Addr, gateway: Ipv4Addr, dns: Vec<Ipv4Addr>, mtu: usize) -> Result<Self> {
        if !(576..=1400).contains(&mtu) {
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
            1 => Self::Configured,
            2 => Self::Ready,
            3 => Self::Failed,
            _ => Self::Offline,
        }
    }
}
