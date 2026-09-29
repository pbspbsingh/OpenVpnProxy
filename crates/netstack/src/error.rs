use thiserror::Error;

/// Failures while configuring or using the userspace packet stack.
#[derive(Debug, Error)]
pub enum StackError {
    #[error("tunnel MTU must be between 576 and 1400 bytes")]
    InvalidMtu,
    #[error("invalid IPv6 tunnel configuration")]
    InvalidIpv6Config,
    #[error("VPN has no route to this IPv6 destination")]
    NoIpv6Route,
    #[error("tunnel address table is full")]
    AddressTableFull,
    #[error("tunnel route table is full")]
    RouteTableFull,
    #[error("packet stack worker stopped")]
    WorkerStopped,
    #[error("packet stack configuration timed out")]
    ConfigurationTimeout,
    #[error("VPN is down")]
    VpnDown,
    #[error("tunneled DNS timed out")]
    DnsTimeout,
    #[error("VPN pushed no DNS server; set dns_override in config.toml")]
    NoDnsServer,
    #[error("tunneled DNS query failed: {0}")]
    DnsQuery(String),
    #[error("tunneled DNS returned no address")]
    NoDnsAddress,
    #[error("tunneled DNS failed")]
    DnsFailed,
    #[error("VPN disconnected")]
    Disconnected,
    #[error("tunnel command queue is full")]
    CommandQueueFull,
    #[error("VPN packet delivery failed")]
    PacketDelivery,
    #[error("packet stack cannot transition to ready from its current state")]
    InvalidState,
}

/// Result returned by the userspace packet stack.
pub type Result<T> = std::result::Result<T, StackError>;
