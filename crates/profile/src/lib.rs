//! Parsing and validation for supported OpenVPN profiles.

use std::time::Duration;

use thiserror::Error;

const DEFAULT_RENEGOTIATION_INTERVAL: Duration = Duration::from_secs(3600);
const DEFAULT_HANDSHAKE_WINDOW: Duration = Duration::from_secs(30);
const DEFAULT_TRANSITION_WINDOW: Duration = Duration::from_secs(3600);
const DEFAULT_REMOTE_PORT: u16 = 1194;
const TLS_CRYPT_KEY_BYTES: usize = 256;
const HEX_CHARACTERS_PER_BYTE: usize = 2;
const HEX_RADIX: u32 = 16;

/// An unsupported or malformed OpenVPN profile setting.
#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("unsupported inline profile block")]
    UnsupportedInlineBlock,
    #[error("remote directive has no host")]
    MissingRemoteHost,
    #[error("remote directive has an invalid port")]
    InvalidRemotePort,
    #[error("proto directive has no value")]
    MissingProtocol,
    #[error("only UDP profiles are supported")]
    UnsupportedTransport,
    #[error("only TUN profiles are supported")]
    UnsupportedDevice,
    #[error("only tls-crypt v1 is supported")]
    UnsupportedControlProtection,
    #[error("profile requests an unsupported certificate feature")]
    UnsupportedCertificateFeature,
    #[error("remote-cert-tls requires exactly 'server'")]
    UnsupportedRemoteCertTls,
    #[error("reneg-sec requires one nonnegative number of seconds")]
    InvalidRenegotiateInterval,
    #[error("hand-window requires one positive number of seconds")]
    InvalidHandshakeWindow,
    #[error("tran-window requires one nonnegative number of seconds")]
    InvalidTransitionWindow,
    #[error("unterminated inline profile block")]
    UnterminatedBlock,
    #[error("profile has no remote")]
    MissingRemote,
    #[error("profile needs an inline CA")]
    MissingCa,
    #[error("tls-crypt key must contain 256 bytes of hex")]
    InvalidTlsCryptKey,
}

/// Validated settings read from an OpenVPN profile.
pub struct Profile {
    pub remotes: Vec<(String, u16)>,
    pub ca_pem: String,
    pub tls_crypt_key: [u8; TLS_CRYPT_KEY_BYTES],
    pub needs_credentials: bool,
    pub block_ipv6: bool,
    pub require_server_certificate_purpose: bool,
    pub renegotiate_after: Option<Duration>,
    pub handshake_window: Duration,
    pub transition_window: Duration,
}

impl Profile {
    /// Parses a supported OpenVPN profile from its text.
    pub fn parse(content: &str) -> Result<Self, ProfileError> {
        let mut ca = String::new();
        let mut static_key = String::new();
        let mut remotes = Vec::new();
        let mut needs_credentials = false;
        let mut block_ipv6 = false;
        let mut require_server_certificate_purpose = false;
        let mut renegotiate_after = Some(DEFAULT_RENEGOTIATION_INTERVAL);
        let mut handshake_window = DEFAULT_HANDSHAKE_WINDOW;
        let mut transition_window = DEFAULT_TRANSITION_WINDOW;
        let mut protocol = "udp";
        let mut block: Option<&str> = None;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('<') && line.ends_with('>') {
                match line {
                    "<ca>" => block = Some("ca"),
                    "</ca>" if block == Some("ca") => block = None,
                    "<tls-crypt>" => block = Some("tls-crypt"),
                    "</tls-crypt>" if block == Some("tls-crypt") => block = None,
                    _ => return Err(ProfileError::UnsupportedInlineBlock),
                }
                continue;
            }
            match block {
                Some("ca") => {
                    ca.push_str(line);
                    ca.push('\n');
                    continue;
                }
                Some("tls-crypt") => {
                    static_key.push_str(line);
                    static_key.push('\n');
                    continue;
                }
                _ => {}
            }
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let mut words = line.split_whitespace();
            match words.next() {
                Some("remote") => {
                    let host = words
                        .next()
                        .ok_or(ProfileError::MissingRemoteHost)?
                        .to_owned();
                    let port = words
                        .next()
                        .map(|value| {
                            value
                                .parse::<u16>()
                                .map_err(|_| ProfileError::InvalidRemotePort)
                        })
                        .transpose()?
                        .unwrap_or(DEFAULT_REMOTE_PORT);
                    remotes.push((host, port));
                }
                Some("proto") => protocol = words.next().ok_or(ProfileError::MissingProtocol)?,
                Some("auth-user-pass") => needs_credentials = true,
                Some("block-ipv6") => block_ipv6 = true,
                Some("remote-cert-tls") => {
                    if words.next() != Some("server") || words.next().is_some() {
                        return Err(ProfileError::UnsupportedRemoteCertTls);
                    }
                    require_server_certificate_purpose = true;
                }
                Some("reneg-sec") => {
                    let seconds = words
                        .next()
                        .ok_or(ProfileError::InvalidRenegotiateInterval)?
                        .parse::<u64>()
                        .map_err(|_| ProfileError::InvalidRenegotiateInterval)?;
                    if words.next().is_some() {
                        return Err(ProfileError::InvalidRenegotiateInterval);
                    }
                    renegotiate_after = (seconds != 0).then_some(Duration::from_secs(seconds));
                }
                Some("hand-window") => {
                    let seconds = words
                        .next()
                        .ok_or(ProfileError::InvalidHandshakeWindow)?
                        .parse::<u64>()
                        .map_err(|_| ProfileError::InvalidHandshakeWindow)?;
                    if seconds == 0 || words.next().is_some() {
                        return Err(ProfileError::InvalidHandshakeWindow);
                    }
                    handshake_window = Duration::from_secs(seconds);
                }
                Some("tran-window") => {
                    let seconds = words
                        .next()
                        .ok_or(ProfileError::InvalidTransitionWindow)?
                        .parse::<u64>()
                        .map_err(|_| ProfileError::InvalidTransitionWindow)?;
                    if words.next().is_some() {
                        return Err(ProfileError::InvalidTransitionWindow);
                    }
                    transition_window = Duration::from_secs(seconds);
                }
                Some("tls-auth" | "tls-crypt-v2") => {
                    return Err(ProfileError::UnsupportedControlProtection);
                }
                Some(
                    "verify-x509-name" | "tls-verify" | "peer-fingerprint" | "cert" | "key"
                    | "pkcs12" | "remote-cert-ku" | "remote-cert-eku" | "crl-verify"
                    | "ns-cert-type",
                ) => return Err(ProfileError::UnsupportedCertificateFeature),
                Some("dev") if words.next() != Some("tun") => {
                    return Err(ProfileError::UnsupportedDevice);
                }
                _ => {}
            }
        }
        if block.is_some() {
            return Err(ProfileError::UnterminatedBlock);
        }
        if protocol != "udp" && protocol != "udp4" {
            return Err(ProfileError::UnsupportedTransport);
        }
        if remotes.is_empty() {
            return Err(ProfileError::MissingRemote);
        }
        if ca.is_empty() {
            return Err(ProfileError::MissingCa);
        }
        let body: String = static_key
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .flat_map(|line| line.chars().filter(|character| !character.is_whitespace()))
            .collect();
        if body.len() != TLS_CRYPT_KEY_BYTES * HEX_CHARACTERS_PER_BYTE {
            return Err(ProfileError::InvalidTlsCryptKey);
        }
        let mut key = [0; TLS_CRYPT_KEY_BYTES];
        for (index, pair) in body
            .as_bytes()
            .as_chunks::<HEX_CHARACTERS_PER_BYTE>()
            .0
            .iter()
            .enumerate()
        {
            let text = std::str::from_utf8(pair).map_err(|_| ProfileError::InvalidTlsCryptKey)?;
            key[index] = u8::from_str_radix(text, HEX_RADIX)
                .map_err(|_| ProfileError::InvalidTlsCryptKey)?;
        }
        Ok(Self {
            remotes,
            ca_pem: ca,
            tls_crypt_key: key,
            needs_credentials,
            block_ipv6,
            require_server_certificate_purpose,
            renegotiate_after,
            handshake_window,
            transition_window,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_inline_udp_profile() {
        let input = format!(
            "client\nproto udp\nremote vpn.example.test 1194\nauth-user-pass\nremote-cert-tls server\nreneg-sec 0\n<ca>\nCERT\n</ca>\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n</tls-crypt>",
            "00".repeat(256)
        );
        let profile = Profile::parse(&input).unwrap();
        assert_eq!(profile.remotes.len(), 1);
        assert!(profile.needs_credentials);
        assert!(!profile.block_ipv6);
        assert!(profile.require_server_certificate_purpose);
        assert_eq!(profile.renegotiate_after, None);
        assert_eq!(profile.tls_crypt_key, [0; TLS_CRYPT_KEY_BYTES]);
        assert!(
            Profile::parse(&format!("block-ipv6\n{input}"))
                .unwrap()
                .block_ipv6
        );
    }

    #[test]
    fn rejects_unsupported_transport() {
        assert!(Profile::parse("proto tcp\nremote host 443").is_err());
    }
}
