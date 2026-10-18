use std::io::Cursor;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    ClientConfig as TlsClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{ClientConfig, TlsVersion};
use crate::error::{Error, Result, require};

pub(crate) fn new_tls_connection(config: &Arc<TlsClientConfig>) -> Result<ClientConnection> {
    let name = ServerName::try_from("openvpn.invalid")
        .map_err(|_| Error::Protocol("invalid internal TLS server name"))?;
    Ok(ClientConnection::new(Arc::clone(config), name)?)
}

pub(super) fn tls_client(profile: &ClientConfig<'_>) -> Result<Arc<TlsClientConfig>> {
    let mut reader = Cursor::new(profile.ca_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<std::io::Result<_>>()?;
    if certs.is_empty() {
        return Err(Error::MissingCa);
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(Error::InvalidCa)?;
    }
    configure_tls(profile, roots)
}

fn configure_tls(profile: &ClientConfig<'_>, roots: RootCertStore) -> Result<Arc<TlsClientConfig>> {
    require(
        profile.tls_version_min <= profile.tls_version_max,
        "invalid TLS version range",
    )?;
    let versions: Vec<_> = [
        (TlsVersion::V1_3, &rustls::version::TLS13),
        (TlsVersion::V1_2, &rustls::version::TLS12),
    ]
    .into_iter()
    .filter_map(|(version, supported)| {
        (version >= profile.tls_version_min && version <= profile.tls_version_max)
            .then_some(supported)
    })
    .collect();
    let provider: CryptoProvider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = OpenVpnVerifier {
        roots,
        algorithms: provider.signature_verification_algorithms,
        require_server_certificate_purpose: profile.require_server_certificate_purpose,
    };
    let mut config = TlsClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.enable_sni = false;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct OpenVpnVerifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
    require_server_certificate_purpose: bool,
}

impl ServerCertVerifier for OpenVpnVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        // OpenVPN profiles authenticate the server role against the profile CA, not a DNS name.
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        if self.require_server_certificate_purpose {
            verify_server_certificate_purpose(end_entity)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn verify_server_certificate_purpose(
    cert: &CertificateDer<'_>,
) -> std::result::Result<(), rustls::Error> {
    use rustls::CertificateError;

    let (remaining, parsed) = X509Certificate::from_der(cert.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    if !remaining.is_empty() {
        return Err(rustls::Error::InvalidCertificate(
            CertificateError::BadEncoding,
        ));
    }
    let key_usage = parsed
        .key_usage()
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let extended_key_usage = parsed
        .extended_key_usage()
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    if key_usage.is_none() || !extended_key_usage.is_some_and(|usage| usage.value.server_auth) {
        return Err(rustls::Error::InvalidCertificate(
            CertificateError::InvalidPurpose,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the actual ClientHello, including TLS 1.2's absent versions extension.
    fn offered_versions(config: &Arc<TlsClientConfig>) -> Vec<u16> {
        let mut connection = new_tls_connection(config).unwrap();
        let mut wire = Vec::new();
        connection.write_tls(&mut wire).unwrap();
        assert_eq!(wire[0], 22); // TLS handshake record
        assert_eq!(wire[5], 1); // ClientHello
        let legacy = u16::from_be_bytes([wire[9], wire[10]]);
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + usize::from(wire[at]);
        let cipher_bytes = usize::from(u16::from_be_bytes([wire[at], wire[at + 1]]));
        at += 2 + cipher_bytes;
        at += 1 + usize::from(wire[at]);
        let extension_bytes = usize::from(u16::from_be_bytes([wire[at], wire[at + 1]]));
        at += 2;
        let end = at + extension_bytes;
        while at < end {
            let kind = u16::from_be_bytes([wire[at], wire[at + 1]]);
            let size = usize::from(u16::from_be_bytes([wire[at + 2], wire[at + 3]]));
            at += 4;
            if kind == 43 {
                return wire[at + 1..at + size]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|version| u16::from_be_bytes([version[0], version[1]]))
                    .collect();
            }
            at += size;
        }
        vec![legacy]
    }

    #[test]
    fn tls_bounds_restrict_initial_and_replacement_client_hellos() {
        for (minimum, maximum, expected) in [
            (TlsVersion::V1_2, TlsVersion::V1_3, vec![0x0304, 0x0303]),
            (TlsVersion::V1_3, TlsVersion::V1_3, vec![0x0304]),
            (TlsVersion::V1_2, TlsVersion::V1_2, vec![0x0303]),
        ] {
            let profile = ClientConfig {
                endpoint: "127.0.0.1:1194".parse().unwrap(),
                ca_pem: "",
                tls_crypt_key: &[0; 256],
                require_server_certificate_purpose: true,
                tls_version_min: minimum,
                tls_version_max: maximum,
                renegotiate_after: None,
                handshake_window: std::time::Duration::from_secs(30),
                transition_window: std::time::Duration::from_secs(3600),
            };
            let config = configure_tls(&profile, RootCertStore::empty()).unwrap();
            assert_eq!(offered_versions(&config), expected);
            // Rekeys construct a fresh connection from this same immutable config.
            assert_eq!(offered_versions(&config), expected);
        }
    }
}
