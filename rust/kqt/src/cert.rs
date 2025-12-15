use std::{collections::HashMap, str::FromStr, time::Duration};

use base64::Engine;
use ed25519_dalek::Signer;
use quinn::{ConnectionId, ConnectionIdGenerator, rustls::{
    client::danger::*,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::danger::{ClientCertVerified, ClientCertVerifier},
}};
use quinn_proto::InvalidCid;
use x509_cert::{
    der::{Decode, Encode, asn1::BitString},
    ext::{AsExtension, pkix::BasicConstraints},
    spki::DynSignatureAlgorithmIdentifier,
};

pub fn recover_tbs_cert(
    raw_pk: ed25519_dalek::VerifyingKey,
    raw_issuer: ed25519_dalek::VerifyingKey,
    suffix: &str,
) -> anyhow::Result<x509_cert::certificate::TbsCertificate> {
    // Subject is derived from the public key. Since the public key is only 32B long,
    // which is exactly the same length as SHA256, we just use the public key itself.

    let pk_bytes = raw_pk.to_bytes();
    let name = hex::encode(pk_bytes);

    let issuer_name = hex::encode(raw_issuer.to_bytes());

    use x509_cert::certificate::*;
    use x509_cert::der::asn1::GeneralizedTime;
    use x509_cert::name::*;
    use x509_cert::serial_number::*;
    use x509_cert::spki::*;
    use x509_cert::time::*;

    let bc_ext = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    let subject = RdnSequence::from_str(&format!("CN={name}.{suffix}"))?;
    let bc_ext = bc_ext.to_extension(&subject, &[])?;

    let tbs_cert = x509_cert::certificate::TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&pk_bytes[0..19])?,
        signature: raw_pk.signature_algorithm_identifier()?,
        issuer: RdnSequence::from_str(&format!("CN={issuer_name}.{suffix}"))?,
        validity: Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_unix_duration(
                std::time::Duration::new(0, 0),
            )?),
            not_after: Time::INFINITY,
        },
        subject,
        subject_public_key_info: SubjectPublicKeyInfo::from_key(raw_pk)?,

        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![bc_ext]),
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
    raw_pk: ed25519_dalek::VerifyingKey,
    raw_issuer: ed25519_dalek::VerifyingKey,
    signautre: ed25519_dalek::Signature,
    suffix: &str,
) -> anyhow::Result<x509_cert::certificate::Certificate> {
    use x509_cert::spki::*;

    let tbs_cert = recover_tbs_cert(raw_pk, raw_issuer, suffix)?;
    let cert = x509_cert::certificate::Certificate {
        tbs_certificate: tbs_cert,
        signature_algorithm: raw_issuer.signature_algorithm_identifier()?,
        signature: BitString::from_bytes(&signautre.to_bytes())?,
    };
    // FIXME: verify?

    Ok(cert)
}

/// Parsing
/// Formats are:
/// - Raw public key used in trust anchor: p.<base64>
/// - Signed keypair: s.<base64 private key>.<base64 issuer pk>.<base64 signature>
/// - Self-signed keypair: s.<base64 private key>

pub struct ParsedTrustAnchor(pub ed25519_dalek::VerifyingKey);
impl<'a> TryFrom<&'a str> for ParsedTrustAnchor {
    type Error = anyhow::Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if !value.starts_with("p.") {
            return Err(anyhow::anyhow!("Trust anchor must start with 'p.'"));
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

#[derive(Clone)]
pub struct ParsedKeypair {
    pub sk: ed25519_dalek::SigningKey,
    pub sig: Option<(ed25519_dalek::VerifyingKey, ed25519_dalek::Signature)>,
}

impl ParsedKeypair {
    pub fn try_to_cert(&self, suffix: &str) -> anyhow::Result<x509_cert::certificate::Certificate> {
        let pk = self.sk.verifying_key();
        let cert = match self.sig {
            Some((issuer, sig)) => recover_cert(pk, issuer, sig, suffix)?,
            None => {
                let tbs_cert = recover_tbs_cert(pk, pk, suffix)?;
                let sig = sign_cert(&tbs_cert, &self.sk)?;
                x509_cert::certificate::Certificate {
                    tbs_certificate: tbs_cert,
                    signature_algorithm: pk.signature_algorithm_identifier()?,
                    signature: BitString::from_bytes(&sig.to_bytes())?,
                }
            }
        };
        Ok(cert)
    }

    pub fn try_into_rustls(
        self,
        suffix: &str,
    ) -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let cert = self.try_to_cert(suffix)?;
        let cert_der = cert.to_der()?;
        let cert_der = CertificateDer::from(cert_der);

        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let key_der = self.sk.to_pkcs8_der()?;
        let key_der = PrivatePkcs8KeyDer::from(key_der.as_bytes().to_vec());
        Ok((cert_der, key_der.into()))
    }

    pub fn to_hmac_key(&self) -> ring::hmac::Key {
        const DUMMY_STRING: &'static [u8] = b"KQT-DUMMY-HMAC-KEY/1";
        let sig = self.sk.sign(DUMMY_STRING);
        let key_bytes = sig.r_bytes();
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key_bytes)
    }

    pub fn to_cid_generator(&self) -> CIDGenerator {
        let sig = self.sk.sign(b"KQT-DUMMY-CID-GENERATOR/1");
        let mut key = [0; CID_KEY_LEN];
        key.copy_from_slice(&sig.r_bytes()[..CID_KEY_LEN]);
        CIDGenerator { key }
    }
}

impl<'a> TryFrom<&'a str> for ParsedKeypair {
    type Error = anyhow::Error;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if !value.starts_with("s.") {
            return Err(anyhow::anyhow!("Keypair must start with 's.'"));
        }
        let parts: Vec<&str> = value[2..].split('.').collect();
        if parts.len() != 1 && parts.len() != 3 {
            return Err(anyhow::anyhow!("Keypair must be self-signed or signed"));
        }
        let mut decoded_key: [u8; 32] = [0; 32];
        let len_key =
            base64::engine::general_purpose::STANDARD.decode_slice(parts[0], &mut decoded_key)?;
        if len_key != 32 {
            return Err(anyhow::anyhow!("Invalid length of private key"));
        }
        let sk = ed25519_dalek::SigningKey::from_bytes(&decoded_key);

        let mut sig = None;

        if parts.len() > 1 {
            let mut decoded_issuer: [u8; 32] = [0; 32];
            let mut decoded_sig: [u8; 64] = [0; 64];
            let len_issuer = base64::engine::general_purpose::STANDARD
                .decode_slice(parts[1], &mut decoded_issuer)?;
            let len_sig = base64::engine::general_purpose::STANDARD
                .decode_slice(parts[2], &mut decoded_sig)?;
            if len_issuer != 32 || len_sig != 64 {
                return Err(anyhow::anyhow!("Invalid length of issuer or signature"));
            }
            sig = Some((
                ed25519_dalek::VerifyingKey::from_bytes(&decoded_issuer)?,
                ed25519_dalek::Signature::from_bytes(&decoded_sig),
            ));
        }
        Ok(ParsedKeypair { sk, sig })
    }
}

// This is a cert verifier that only does one jump in the CA verification, thus only requiring
// the public key of the issuer. Also, the CA used is derived from the issuer common named, based
// on our keygen convention.
#[derive(Debug)]
pub struct LiteCertVerifier {
    /// Suffix for CN verification
    suffix: String,
    // Trust anchors
    serialized_anchors: HashMap<String, ed25519_dalek::VerifyingKey>,
}

impl LiteCertVerifier {
    pub fn new<'a>(
        suffix: String,
        anchors: impl Iterator<Item = ed25519_dalek::VerifyingKey>,
    ) -> Self {
        let serialized_anchors = anchors.map(|e| (hex::encode(e.to_bytes()), e)).collect();
        Self {
            suffix,
            serialized_anchors,
        }
    }

    pub fn try_new<'a, E>(
        suffix: String,
        anchors: impl Iterator<Item = Result<ed25519_dalek::VerifyingKey, E>>,
    ) -> Result<Self, E> {
        let serialized_anchors = anchors
            .map(|e| -> Result<_, E> {
                let e = e?;
                Ok((hex::encode(e.to_bytes()), e))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(Self {
            suffix,
            serialized_anchors,
        })
    }
}

impl LiteCertVerifier {
    fn check_anchor(&self, issuer: &str) -> Option<&ed25519_dalek::VerifyingKey> {
        if !issuer.is_ascii() {
            // So that we can arbitrarily slice
            return None;
        }

        if !issuer.ends_with(&self.suffix) {
            return None;
        }

        if &issuer[issuer.len() - self.suffix.len() - 1..issuer.len() - self.suffix.len()] != "." {
            return None;
        }

        self.serialized_anchors
            .get(&issuer[0..issuer.len() - self.suffix.len() - 1])
    }

    fn verify_cert(
        &self,
        end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
    ) -> Result<(), quinn::rustls::Error> {
        // Check presented signature on end-entity cert is in fact signed by one of our CAs
        // FIXME: zero-copy parsing
        let parsed =
            x509_cert::certificate::Certificate::from_der(end_entity.as_ref()).map_err(|_| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadEncoding,
                )
            })?;

        let issuer = parsed
            .tbs_certificate
            .issuer
            .as_ref()
            .iter()
            .flat_map(|rdn| {
                rdn.as_ref()
                    .iter()
                    .find(|e| e.oid == const_oid::db::rfc4519::COMMON_NAME)
            })
            .next()
            .ok_or_else(|| quinn::rustls::Error::General("Issuer CN not found".to_string()))?
            .value
            .decode_as::<String>()
            .map_err(|_| quinn::rustls::Error::General("Failed to decode issuer CN".to_string()))?;

        let Some(issuer) = self.check_anchor(&issuer) else {
            return Err(quinn::rustls::Error::InvalidCertificate(
                quinn::rustls::CertificateError::UnknownIssuer,
            ));
        };

        let tbs_der = parsed.tbs_certificate.to_der().map_err(|_| {
            quinn::rustls::Error::InvalidCertificate(quinn::rustls::CertificateError::BadEncoding)
        })?;
        // FIXME: check signature algo first, then verify. Report error accordingly
        let sig_bytes = parsed.signature;
        sig_bytes
            .as_bytes()
            .and_then(|bytes| ed25519_dalek::Signature::try_from(bytes).ok())
            .and_then(|sig| issuer.verify_strict(&tbs_der, &sig).ok())
            .ok_or_else(|| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadSignature,
                )
            })?;

        // Parse pub key, check algorithms
        let pubkey = parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .and_then(|bytes| ed25519_dalek::VerifyingKey::try_from(bytes).ok())
            .ok_or_else(|| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadEncoding,
                )
            })?;
        if parsed.signature_algorithm
            != issuer.signature_algorithm_identifier().map_err(|_| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadEncoding,
                )
            })?
            || parsed.tbs_certificate.subject_public_key_info.algorithm
                != pubkey.signature_algorithm_identifier().map_err(|_| {
                    quinn::rustls::Error::InvalidCertificate(
                        quinn::rustls::CertificateError::BadEncoding,
                    )
                })?
        {
            return Err(quinn::rustls::Error::InvalidCertificate(
                quinn::rustls::CertificateError::BadEncoding,
            ));
        }

        // Check presented CN
        let expected_name = hex::encode(pubkey.to_bytes());
        let expected_subject =
            x509_cert::name::RdnSequence::from_str(&format!("CN={expected_name}.{}", &self.suffix));
        if expected_subject != Ok(parsed.tbs_certificate.subject) {
            return Err(quinn::rustls::Error::General("CN mismatch".to_string()));
        }

        Ok(())
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<(), quinn::rustls::Error> {
        // FIXME: zero-copy parsing
        let parsed =
            x509_cert::certificate::Certificate::from_der(cert.as_ref()).map_err(|_| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadEncoding,
                )
            })?;
        let pubkey = parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .and_then(|bytes| ed25519_dalek::VerifyingKey::try_from(bytes).ok())
            .ok_or_else(|| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadEncoding,
                )
            })?;
        let sig_bytes = dss.signature();
        ed25519_dalek::Signature::try_from(sig_bytes)
            .and_then(|s| pubkey.verify_strict(message, &s))
            .map_err(|_| {
                quinn::rustls::Error::InvalidCertificate(
                    quinn::rustls::CertificateError::BadSignature,
                )
            })?;
        Ok(())
    }
}

impl ServerCertVerifier for LiteCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        _server_name: &quinn::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: quinn::rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, quinn::rustls::Error> {
        if intermediates.len() > 0 {
            // Root CAs should not be served
            return Err(quinn::rustls::Error::General(
                "Too many intermediates".to_string(),
            ));
        }

        self.verify_cert(end_entity)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &quinn::rustls::pki_types::CertificateDer<'_>,
        _: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        Err(quinn::rustls::Error::General(
            "TLS1.2 should not be called".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        self.verify_signature(message, cert, dss)?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        return vec![quinn::rustls::SignatureScheme::ED25519];
    }
}

impl ClientCertVerifier for LiteCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        _now: quinn::rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, quinn::rustls::Error> {
        if intermediates.len() > 0 {
            // Root CAs should not be served
            return Err(quinn::rustls::Error::General(
                "Too many intermediates".to_string(),
            ));
        }

        self.verify_cert(end_entity)?;

        Ok(ClientCertVerified::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        return vec![quinn::rustls::SignatureScheme::ED25519];
    }

    fn root_hint_subjects(&self) -> &[quinn::rustls::DistinguishedName] {
        // TODO: test this
        return &[];
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        Err(quinn::rustls::Error::General(
            "TLS1.2 should not be called".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, quinn::rustls::Error> {
        self.verify_signature(message, cert, dss)?;
        Ok(HandshakeSignatureValid::assertion())
    }
}


const CID_KEY_LEN: usize = 8;
const CID_NONCE_LEN: usize = 8;
const CID_SIG_LEN: usize = 8;
pub struct CIDGenerator {
    key: [u8; CID_KEY_LEN],
}

impl CIDGenerator {
    pub fn compute_hash(&self, input: &[u8], output: &mut [u8]) {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(&self.key);
        ctx.update(input);
        let digest = ctx.finish();
        output.copy_from_slice(&digest.as_ref()[..output.len()]);
    }
}

impl ConnectionIdGenerator for CIDGenerator {
    fn generate_cid(&mut self) -> ConnectionId {

        use rand_core::RngCore;

        let mut buf = [0; CID_NONCE_LEN + CID_SIG_LEN];
        let (nonce, sig) = buf.split_at_mut(CID_NONCE_LEN);
        rand_core::OsRng.fill_bytes(nonce);
        self.compute_hash(nonce, sig);
        ConnectionId::new(&buf)
    }

    fn validate(&self, cid: &ConnectionId) -> Result<(), InvalidCid> {
        let (nonce, sig) = cid.split_at(CID_NONCE_LEN);
        let mut expected = [0; CID_SIG_LEN];
        self.compute_hash(nonce, &mut expected);
        if expected == sig {
            Ok(())
        } else {
            Err(InvalidCid)
        }
    }

    fn cid_len(&self) -> usize {
        CID_NONCE_LEN + CID_SIG_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}