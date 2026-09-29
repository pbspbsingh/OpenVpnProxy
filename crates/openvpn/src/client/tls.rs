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

use super::ClientConfig;
use crate::error::{Error, Result};

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
    let provider: CryptoProvider = rustls::crypto::aws_lc_rs::default_provider();
    let verifier = OpenVpnVerifier {
        roots,
        algorithms: provider.signature_verification_algorithms,
        require_server_certificate_purpose: profile.require_server_certificate_purpose,
    };
    let mut config = TlsClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
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
