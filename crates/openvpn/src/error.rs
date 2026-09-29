use std::io;

use thiserror::Error;

/// Failures while establishing or using an OpenVPN session.
#[derive(Debug, Error)]
pub enum Error {
    #[error("VPN I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("VPN TLS failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid profile CA certificate: {0}")]
    InvalidCa(rustls::Error),
    #[error("profile CA block contains no certificates")]
    MissingCa,
    #[error("randomness unavailable: {0}")]
    Randomness(getrandom::Error),
    #[error("VPN protocol error: {0}")]
    Protocol(&'static str),
    #[error("VPN PUSH_REPLY did not assign an IPv4 address")]
    PushMissingAddress,
    #[error("VPN PUSH_REPLY contains an invalid IPv4 address for {0}")]
    PushInvalidAddress(&'static str),
    #[error("VPN control channel timed out: {0}")]
    Timeout(&'static str),
    #[error("VPN authentication failed")]
    AuthenticationFailed,
    #[error("VPN data authentication failed")]
    DataAuthenticationFailed,
    #[error("VPN TLS-crypt authentication failed")]
    ControlAuthenticationFailed,
    #[error("VPN packet replay detected")]
    Replay,
    #[error("VPN packet ID exhausted; reconnect required")]
    PacketIdExhausted,
    #[error("VPN cryptographic operation failed")]
    Crypto,
    #[error("server control message is not UTF-8: {0}")]
    InvalidControlText(#[from] std::string::FromUtf8Error),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Protocol(message))
    }
}
