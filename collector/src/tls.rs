//! TLS utilities and a custom ClientCertVerifier that pins client
//! certificates by DER SHA-256 fingerprint.
//!
//! Security model:
//! - `client_auth_mandatory = false` so the /v1/enroll endpoint works
//!   without a client cert.
//! - If a client cert IS presented, `verify_client_cert` checks its
//!   fingerprint against the pinned set. Unknown certs are REJECTED at
//!   the TLS layer — the handshake fails, no HTTP request is processed.
//! - Push handlers additionally verify that a client cert WAS presented
//!   (guaranteed to be pinned if it survived the verifier).
//!
//! TLS handshake signatures are delegated to ring via rustls's crypto
//! provider, so we don't reimplement any signature math.

#![allow(dead_code)]

use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::error::CollectorError;

/// Compute SHA-256 fingerprint of raw DER bytes, return as hex string.
pub fn fingerprint_hex(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    hex::encode(h.finalize())
}

/// Shared pinned-cert fingerprint set. Updated by enrollment handler,
/// read by the TLS verifier on every handshake.
#[derive(Clone, Default, Debug)]
pub struct PinnedCerts {
    inner: Arc<RwLock<HashSet<String>>>,
}

impl PinnedCerts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_der(&self, cert_der: &[u8]) {
        let fp = fingerprint_hex(cert_der);
        self.inner.write().unwrap().insert(fp);
    }

    pub fn contains_der(&self, cert_der: &[u8]) -> bool {
        let fp = fingerprint_hex(cert_der);
        self.inner.read().unwrap().contains(&fp)
    }

    pub fn add_hex(&self, fp_hex: &str) {
        self.inner.write().unwrap().insert(fp_hex.to_string());
    }

    pub fn remove_hex(&self, fp_hex: &str) {
        self.inner.write().unwrap().remove(fp_hex);
    }
}

/// Custom client-cert verifier that checks fingerprints against a
/// pinned set. Unknown certs are rejected at the TLS layer.
///
/// If no client cert is offered (enrollment flow), the handshake
/// succeeds — `client_auth_mandatory` returns false.
#[derive(Debug)]
pub struct PinnedClientVerifier {
    pinned: PinnedCerts,
    schemes: Vec<SignatureScheme>,
}

impl PinnedClientVerifier {
    pub fn new(pinned: PinnedCerts) -> Arc<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        Arc::new(Self { pinned, schemes })
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // false: enrollment endpoint needs to work without a client cert.
        // Push endpoints check for a cert in the handler and reject if absent.
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Empty: we don't hint which CAs the client should use (self-signed).
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // The client presented a cert. Check its fingerprint.
        if self.pinned.contains_der(end_entity.as_ref()) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "client cert not in pinned set".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        // Delegate signature verification to ring via rustls's crypto provider.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// Generate a self-signed ed25519 cert + key via rcgen.
pub fn generate_self_signed(
    cert_path: &Path,
    key_path: &Path,
    cn: &str,
) -> Result<(), CollectorError> {
    let key_pair = RcgenKeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| CollectorError::Tls(format!("keygen: {e}")))?;

    let mut params = CertificateParams::new(vec![cn.to_string()])
        .map_err(|e| CollectorError::Tls(format!("cert params: {e}")))?;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(365 * 10);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CollectorError::Tls(format!("self-sign: {e}")))?;

    write_pem(key_path, key_pair.serialize_pem().as_bytes(), 0o400)?;
    write_pem(cert_path, cert.pem().as_bytes(), 0o444)?;

    Ok(())
}

fn write_pem(path: &Path, data: &[u8], mode: u32) -> Result<(), CollectorError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CollectorError::Tls(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("pem.tmp");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| CollectorError::Tls(format!("open {}: {e}", tmp.display())))?;
    f.write_all(data)
        .map_err(|e| CollectorError::Tls(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Tls(format!("fsync: {e}")))?;
    drop(f);
    fs::rename(&tmp, path)
        .map_err(|e| CollectorError::Tls(format!("rename: {e}")))?;
    Ok(())
}

/// Read a PEM cert file, return the first cert's DER bytes.
pub fn read_cert_der(path: &Path) -> Result<Vec<u8>, CollectorError> {
    let pem = fs::read(path)
        .map_err(|e| CollectorError::Tls(format!("read {}: {e}", path.display())))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CollectorError::Tls(format!("parse cert: {e}")))?;
    if certs.is_empty() {
        return Err(CollectorError::Tls("no certs in PEM".into()));
    }
    Ok(certs[0].to_vec())
}

/// Read a PEM cert file as a string (for enrollment response).
pub fn read_cert_pem(path: &Path) -> Result<String, CollectorError> {
    fs::read_to_string(path)
        .map_err(|e| CollectorError::Tls(format!("read {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_self_signed_creates_files() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        generate_self_signed(&cert, &key, "test.local").unwrap();
        assert!(cert.exists());
        assert!(key.exists());
        let der = read_cert_der(&cert).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let data = b"some cert der bytes";
        assert_eq!(fingerprint_hex(data), fingerprint_hex(data));
        assert_eq!(fingerprint_hex(data).len(), 64);
    }

    #[test]
    fn pinned_certs_add_contains_remove() {
        let p = PinnedCerts::new();
        let der = b"fake-der";
        assert!(!p.contains_der(der));
        p.add_der(der);
        assert!(p.contains_der(der));
        let fp = fingerprint_hex(der);
        p.remove_hex(&fp);
        assert!(!p.contains_der(der));
    }
}
