use thiserror::Error;

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
    #[error("unterminated inline profile block")]
    UnterminatedBlock,
    #[error("profile has no remote")]
    MissingRemote,
    #[error("profile needs an inline CA")]
    MissingCa,
    #[error("tls-crypt key must contain 256 bytes of hex")]
    InvalidTlsCryptKey,
}

pub struct Profile {
    pub remotes: Vec<(String, u16)>,
    pub ca_pem: String,
    pub tls_crypt_key: [u8; 256],
    pub needs_credentials: bool,
}

impl Profile {
    pub fn parse(content: &str) -> Result<Self, ProfileError> {
        let mut ca = String::new();
        let mut static_key = String::new();
        let mut remotes = Vec::new();
        let mut needs_credentials = false;
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
                        .unwrap_or("1194")
                        .parse::<u16>()
                        .map_err(|_| ProfileError::InvalidRemotePort)?;
                    remotes.push((host, port));
                }
                Some("proto") => protocol = words.next().ok_or(ProfileError::MissingProtocol)?,
                Some("auth-user-pass") => needs_credentials = true,
                Some("tls-auth" | "tls-crypt-v2") => {
                    return Err(ProfileError::UnsupportedControlProtection);
                }
                Some(
                    "verify-x509-name" | "tls-verify" | "peer-fingerprint" | "cert" | "key"
                    | "pkcs12",
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
        if body.len() != 512 {
            return Err(ProfileError::InvalidTlsCryptKey);
        }
        let mut key = [0; 256];
        for (index, pair) in body.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let text = std::str::from_utf8(pair).map_err(|_| ProfileError::InvalidTlsCryptKey)?;
            key[index] =
                u8::from_str_radix(text, 16).map_err(|_| ProfileError::InvalidTlsCryptKey)?;
        }
        Ok(Self {
            remotes,
            ca_pem: ca,
            tls_crypt_key: key,
            needs_credentials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_inline_udp_profile() {
        let input = format!(
            "client\nproto udp\nremote vpn.example.test 1194\nauth-user-pass\n<ca>\nCERT\n</ca>\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----\n</tls-crypt>",
            "00".repeat(256)
        );
        let profile = Profile::parse(&input).unwrap();
        assert_eq!(profile.remotes.len(), 1);
        assert!(profile.needs_credentials);
        assert_eq!(profile.tls_crypt_key, [0; 256]);
    }

    #[test]
    fn rejects_unsupported_transport() {
        assert!(Profile::parse("proto tcp\nremote host 443").is_err());
    }
}
