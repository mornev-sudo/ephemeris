//! TLS for the connection to the controller (docs/controller-api.md): 1.3
//! only, on ring. The controller is trusted by its pinned key, not by
//! certificate authorities: its certificate's SubjectPublicKeyInfo must
//! hash to the pin from enrolment, whatever names or dates it carries.
//! The router presents a self-signed certificate for its management key;
//! the controller trusts it by that key, the same way.

use super::Identity;
use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The SHA-256 of a certificate's SubjectPublicKeyInfo (DER, with its
/// outer SEQUENCE): what a pin is.
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32]> {
    let ee = webpki::EndEntityCert::try_from(cert)
        .map_err(|e| anyhow::anyhow!("unreadable certificate: {e:?}"))?;
    Ok(Sha256::digest(ee.subject_public_key_info().as_ref()).into())
}

/// The router's certificate: self-signed, for its management key, named
/// by that key.
pub fn client_cert(
    identity: &Identity,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.pkcs8()));
    let pair = rcgen::KeyPair::try_from(&key).context("the management key")?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        crate::sdwan::hex(&identity.public()),
    );
    let cert = params
        .self_signed(&pair)
        .context("the router's certificate")?;
    Ok((cert.der().clone(), key))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The router's TLS settings towards a controller with this pin.
pub fn client_config(identity: &Identity, pin: [u8; 32]) -> Result<Arc<rustls::ClientConfig>> {
    let provider = provider();
    let verifier = Arc::new(PinnedKey {
        pin,
        algorithms: provider.signature_verification_algorithms,
    });
    let (cert, key) = client_cert(identity)?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)?;
    Ok(Arc::new(config))
}

/// Trusts exactly one key.
#[derive(Debug)]
struct PinnedKey {
    pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match spki_sha256(end_entity) {
            Ok(h) if h == self.pin => Ok(ServerCertVerified::assertion()),
            Ok(_) => Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
            Err(_) => Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Only TLS 1.3 is offered.
        Err(rustls::Error::General("TLS 1.2 is never used".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_certificate_carries_the_management_key() {
        let id = Identity::from_seed([3; 32]);
        let (cert, _) = client_cert(&id).unwrap();
        // Its SPKI is the Ed25519 key: the fixed 12-byte header, then the key.
        let ee = webpki::EndEntityCert::try_from(&cert).unwrap();
        let spki = ee.subject_public_key_info();
        assert_eq!(&spki.as_ref()[12..], &id.public()[..]);
        assert_eq!(
            spki_sha256(&cert).unwrap(),
            <[u8; 32]>::from(Sha256::digest(spki.as_ref()))
        );
        // A new certificate for the same key: the same pin (only the key counts).
        assert_eq!(
            spki_sha256(&client_cert(&id).unwrap().0).unwrap(),
            spki_sha256(&cert).unwrap()
        );
        assert!(client_config(&id, [0; 32]).is_ok());
    }
}
