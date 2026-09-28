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

use super::ClientConfig;
use crate::error::{Error, Result};

#[derive(Debug)]
struct OpenVpnVerifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
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

pub(super) fn tls_client(profile: &ClientConfig<'_>) -> Result<ClientConnection> {
    let mut reader = Cursor::new(profile.ca_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<std::io::Result<_>>()?;
    if certs.is_empty() {
        return Err(Error::MissingCa);
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(Error::InvalidCa)?;
    }
    let provider: CryptoProvider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = OpenVpnVerifier {
        roots,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = TlsClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.enable_sni = false;
    let name = ServerName::try_from("openvpn.invalid")
        .map_err(|_| Error::Protocol("invalid internal TLS server name"))?;
    Ok(ClientConnection::new(Arc::new(config), name)?)
}
