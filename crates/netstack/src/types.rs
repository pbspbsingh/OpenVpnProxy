use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Result, StackError};

pub(crate) const MIN_TUN_MTU: usize = 576;
pub(crate) const MAX_TUN_MTU: usize = 1400;
pub(crate) const MIN_IPV6_MTU: usize = 1280;
const MAX_IPV6_ROUTES: usize = 3;
const MAX_DNS_SERVERS: usize = 4;

/// Address family used for a tunneled DNS lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

/// A route installed in the userspace IPv6 stack.
#[derive(Clone, Debug)]
pub struct Ipv6Route {
    pub network: Ipv6Addr,
    pub prefix_len: u8,
    pub gateway: Ipv6Addr,
}

impl Ipv6Route {
    /// Returns whether the route covers an IPv6 address.
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        if self.prefix_len > 128 {
            return false;
        }
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix_len)
        };
        u128::from(self.network) & mask == u128::from(address) & mask
    }
}

/// IPv6 address and routes assigned by the VPN server.
#[derive(Clone, Debug)]
pub struct Ipv6Config {
    pub local: Ipv6Addr,
    pub prefix_len: u8,
    pub routes: Vec<Ipv6Route>,
}

/// Validated IP settings used to configure a VPN packet stack.
#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub(crate) local: Ipv4Addr,
    pub(crate) gateway: Ipv4Addr,
    pub(crate) dns: Vec<IpAddr>,
    pub(crate) mtu: usize,
    pub(crate) ipv6: Option<Ipv6Config>,
}

impl TunnelConfig {
    /// Validates the tunnel settings and removes DNS servers without a route.
    pub fn new(
        local: Ipv4Addr,
        gateway: Ipv4Addr,
        dns: Vec<IpAddr>,
        mtu: usize,
        ipv6: Option<Ipv6Config>,
    ) -> Result<Self> {
        if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&mtu) {
            return Err(StackError::InvalidMtu);
        }
        let ipv6 = if ipv6
            .as_ref()
            .is_some_and(|config| config.routes.len() > MAX_IPV6_ROUTES)
        {
            tracing::warn!(
                limit = MAX_IPV6_ROUTES,
                "VPN pushed too many IPv6 routes; IPv6 disabled"
            );
            None
        } else {
            ipv6
        };
        if let Some(config) = &ipv6
            && (mtu < MIN_IPV6_MTU
                || config.prefix_len > 128
                || config.local.is_unspecified()
                || config.local.is_multicast()
                || config.routes.iter().any(|route| {
                    route.prefix_len > 128
                        || route.gateway.is_unspecified()
                        || route.gateway.is_multicast()
                }))
        {
            return Err(StackError::InvalidIpv6Config);
        }
        let routes = ipv6
            .as_ref()
            .map_or(&[][..], |config| config.routes.as_slice());
        let mut dns: Vec<_> = dns
            .into_iter()
            .filter(|&server| matches_route(routes, server))
            .collect();
        if dns.len() > MAX_DNS_SERVERS {
            tracing::warn!(
                servers = dns.len(),
                limit = MAX_DNS_SERVERS,
                "VPN pushed too many DNS servers; extra servers ignored"
            );
            dns.truncate(MAX_DNS_SERVERS);
        }
        Ok(Self {
            local,
            gateway,
            dns,
            mtu,
            ipv6,
        })
    }
}

/// An event emitted by a virtual TCP connection.
#[derive(Debug)]
pub enum StreamEvent {
    Connected,
    Data(Vec<u8>),
    Closed,
}

/// Lifecycle state of a VPN packet stack.
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

pub(crate) fn matches_route(routes: &[Ipv6Route], address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => true,
        IpAddr::V6(address) => routes.iter().any(|route| route.contains(address)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_route_matches_only_its_prefix() {
        let route = Ipv6Route {
            network: "2000::".parse().unwrap(),
            prefix_len: 3,
            gateway: "2001:db8::1".parse().unwrap(),
        };
        assert!(route.contains("2606:4700::1111".parse().unwrap()));
        assert!(!route.contains("fe80::1".parse().unwrap()));
        let default = Ipv6Route {
            prefix_len: 0,
            ..route
        };
        assert!(default.contains("fe80::1".parse().unwrap()));
        let invalid = Ipv6Route {
            prefix_len: 129,
            ..default
        };
        assert!(!invalid.contains("fe80::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_dns_server_requires_a_tunnel_route() {
        let server = IpAddr::V6("2001:db8::53".parse().unwrap());
        let local = Ipv4Addr::new(10, 8, 0, 2);
        let gateway = Ipv4Addr::new(10, 8, 0, 1);
        let without_ipv6 = TunnelConfig::new(local, gateway, vec![server], 1400, None).unwrap();
        assert!(without_ipv6.dns.is_empty());
        let ipv6 = Ipv6Config {
            local: "2001:db8:1::2".parse().unwrap(),
            prefix_len: 64,
            routes: vec![Ipv6Route {
                network: "2000::".parse().unwrap(),
                prefix_len: 3,
                gateway: "2001:db8:1::1".parse().unwrap(),
            }],
        };
        let with_ipv6 = TunnelConfig::new(local, gateway, vec![server], 1400, Some(ipv6)).unwrap();
        assert_eq!(with_ipv6.dns, vec![server]);
    }
}
