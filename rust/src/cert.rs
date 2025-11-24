use std::{collections::HashSet, str::FromStr};

use base64::Engine;
use ed25519_dalek::Signer;
use quinn::rustls::client::danger::*;
use x509_cert::der::{Encode, asn1::BitString};

pub fn recover_tbs_cert(
    raw_key: ed25519_dalek::SigningKey,
    raw_issuer: ed25519_dalek::VerifyingKey,
    suffix: &str,
) -> anyhow::Result<x509_cert::certificate::TbsCertificate> {
    // Subject is derived from the public key. Since the public key is only 32B long,
    // which is exactly the same length as SHA256, we just use the public key itself.
    let public_key = ed25519_dalek::VerifyingKey::from(&raw_key);

    let public_key_bytes = public_key.to_bytes();
    let name = hex::encode(public_key_bytes);

    let issuer_name = hex::encode(raw_issuer.to_bytes());

    use x509_cert::certificate::*;
    use x509_cert::serial_number::*;
    use x509_cert::name::*;
    use x509_cert::time::*;
    use x509_cert::spki::*;
    use x509_cert::der::asn1::GeneralizedTime;

    let tbs_cert = x509_cert::certificate::TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&public_key_bytes[0..19])?,
        signature: public_key.signature_algorithm_identifier()?,
        issuer: RdnSequence::from_str(&format!("CN={issuer_name}.{suffix}"))?,
        validity: Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_unix_duration(std::time::Duration::new(0, 0))?),
            not_after: Time::INFINITY,
        },
        subject: RdnSequence::from_str(&format!("CN={name}.{suffix}"))?,
        subject_public_key_info: SubjectPublicKeyInfo::from_key(raw_key.verifying_key())?,

        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    Ok(tbs_cert)
}

pub fn sign_cert(
    tbs_cert: &x509_cert::certificate::TbsCertificate,
    issuer_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<ed25519_dalek::Signature> {
    let tbs_der = tbs_cert.to_der()?;
    let signature = issuer_key.sign(&tbs_der);

    Ok(signature)
}

pub fn recover_cert(
    raw_key: ed25519_dalek::SigningKey,
    raw_issuer: ed25519_dalek::VerifyingKey,
    signautre: ed25519_dalek::Signature,
    suffix: &str,
) -> anyhow::Result<x509_cert::certificate::Certificate> {
    use x509_cert::spki::*;

    let tbs_cert = recover_tbs_cert(raw_key, raw_issuer, suffix)?;
    let cert = x509_cert::certificate::Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: raw_issuer.signature_algorithm_identifier()?,
        signature: BitString::from_bytes(&signautre.to_bytes())?,
    };

    Ok(cert)
}

/// Parsing
/// Formats are:
/// - Raw private key: k.<base64>
/// - Raw public key used in trust anchor: t.<base64>
/// - Signed keypair: c.<base64 private key>.<base64 signature>

pub struct ParsedPrivateKey(pub ed25519_dalek::SigningKey);
impl<'a> TryFrom<&'a str> for ParsedPrivateKey {
    type Error = anyhow::Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if !value.starts_with("k.") {
            return Err(anyhow::anyhow!("Private key must start with 'k.'"));
        }
        let encoded = &value[2..];
        let mut decoded: [u8; 32] = [0; 32];
        let len = base64::engine::general_purpose::STANDARD.decode_slice(encoded, &mut decoded)?;
        if len != 32 {
            return Err(anyhow::anyhow!("Invalid private key length"));
        }
        let sk = ed25519_dalek::SigningKey::from_bytes(&decoded);
        Ok(ParsedPrivateKey(sk))
    }
}

pub struct ParsedTrustAnchor(pub ed25519_dalek::VerifyingKey);
impl<'a> TryFrom<&'a str> for ParsedTrustAnchor {
    type Error = anyhow::Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if !value.starts_with("t.") {
            return Err(anyhow::anyhow!("Trust anchor must start with 't.'"));
        }
        let encoded = &value[2..];
        let mut decoded: [u8; 32] = [0; 32];
        let len = base64::engine::general_purpose::STANDARD.decode_slice(encoded, &mut decoded)?;
        if len != 32 {
            return Err(anyhow::anyhow!("Invalid trust anchor length"));
        }
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&decoded)?;
        Ok(ParsedTrustAnchor(pk))
    }
}

// This is a cert verifier that only does one jump in the CA verification, thus only requiring
// the public key of the issuer. Also, the CA used is derived from the issuer common named, based
// on our keygen convention.
#[derive(Debug)]
struct LiteCertVerifier {
    /// Suffix for CN verification
    suffix: String,
    /// CAs, 
    cas: HashSet<ed25519_dalek::VerifyingKey>,
}

impl LiteCertVerifier {
    pub fn new(suffix: String, cas: HashSet<ed25519_dalek::VerifyingKey>) -> Self {
        Self { suffix, cas }
    }
}

impl ServerCertVerifier for LiteCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        server_name: &quinn::rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: quinn::rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, quinn::rustls::Error> {
        if intermediates.len() > 0 {
            // Root CAs should not be served
            return Err(quinn::rustls::Error::General("Too many intermediates".to_string()));
        }
        todo!()
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &quinn::rustls::pki_types::CertificateDer<'_>,
        _: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        Err(quinn::rustls::Error::General("TLS1.2 should not be called".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        todo!()
    }
}