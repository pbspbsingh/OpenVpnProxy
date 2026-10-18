//! Routing identities, host lifecycle and idle policies shared with observers.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ovpn_socks5::DestinationHost;

pub(crate) const STICKY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub(crate) const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostPhase {
    Dormant,
    Connecting,
    Ready,
    Backoff,
    Stopped,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct StickyKey {
    pub source: IpAddr,
    pub destination: StickyDestination,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) enum StickyDestination {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostActivation {
    Dormant,
    Active {
        epoch: u64,
        preferred_endpoint: SocketAddr,
    },
}

impl HostActivation {
    pub(super) fn epoch(self) -> Option<u64> {
        match self {
            Self::Dormant => None,
            Self::Active { epoch, .. } => Some(epoch),
        }
    }
}

impl StickyKey {
    pub(crate) fn new(source: IpAddr, destination: &DestinationHost) -> Option<Self> {
        let destination = match destination {
            DestinationHost::Ipv4(address) => StickyDestination::Ip(IpAddr::V4(*address)),
            DestinationHost::Ipv6(address) => StickyDestination::Ip(IpAddr::V6(*address)),
            DestinationHost::Domain(name) => {
                let normalized = name.trim_end_matches('.').to_ascii_lowercase();
                if normalized.is_empty() {
                    return None;
                }
                StickyDestination::Domain(
                    psl::domain_str(&normalized)
                        .unwrap_or(&normalized)
                        .to_owned(),
                )
            }
        };
        Some(Self {
            source,
            destination,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains_share_a_sticky_key_per_source() {
        let source = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let key = StickyKey::new(source, &DestinationHost::Domain("ABC.COM".into()));
        assert_eq!(
            key,
            StickyKey::new(source, &DestinationHost::Domain("xyz.abc.com".into()))
        );
        assert_ne!(
            key,
            StickyKey::new(source, &DestinationHost::Domain("other.com".into()))
        );
        assert_ne!(
            key,
            StickyKey::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                &DestinationHost::Domain("abc.com".into())
            )
        );
    }
}
