//! Verify incoming manifest signatures against a sender's pinned
//! ed25519 signing.pub. Canonicalization MUST match what katagrapho
//! produces — we mirror the field order here.

#![allow(dead_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CollectorError;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Chunk {
    pub seq: u64,
    pub bytes: u64,
    pub messages: u64,
    pub elapsed: f64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Manifest {
    pub v: String,
    pub session_id: String,
    pub part: u32,
    pub user: String,
    pub host: String,
    pub boot_id: String,
    pub audit_session_id: Option<u32>,
    pub started: f64,
    pub ended: f64,
    pub katagrapho_version: String,
    pub katagrapho_commit: String,
    pub epitropos_version: String,
    pub epitropos_commit: String,
    pub recording_file: String,
    pub recording_size: u64,
    pub recording_sha256: String,
    pub chunks: Vec<Chunk>,
    pub end_reason: String,
    pub exit_code: i32,
    pub prev_manifest_hash: String,
    #[serde(default)]
    pub this_manifest_hash: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub signature: String,
}

impl Manifest {
    fn canonical_bytes_for_hashing(&self) -> Result<Vec<u8>, CollectorError> {
        let json = serde_json::to_string(&serde_json::json!({
            "v": self.v,
            "session_id": self.session_id,
            "part": self.part,
            "user": self.user,
            "host": self.host,
            "boot_id": self.boot_id,
            "audit_session_id": self.audit_session_id,
            "started": self.started,
            "ended": self.ended,
            "katagrapho_version": self.katagrapho_version,
            "katagrapho_commit": self.katagrapho_commit,
            "epitropos_version": self.epitropos_version,
            "epitropos_commit": self.epitropos_commit,
            "recording_file": self.recording_file,
            "recording_size": self.recording_size,
            "recording_sha256": self.recording_sha256,
            "chunks": self.chunks,
            "end_reason": self.end_reason,
            "exit_code": self.exit_code,
            "prev_manifest_hash": self.prev_manifest_hash,
        }))
        .map_err(|e| CollectorError::Verify(format!("canonical: {e}")))?;
        Ok(json.into_bytes())
    }

    pub fn compute_hash(&self) -> Result<[u8; 32], CollectorError> {
        let bytes = self.canonical_bytes_for_hashing()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    /// Verify signature and internal hash binding using a raw 32-byte
    /// ed25519 pubkey (the sender's signing.pub).
    pub fn verify(&self, signing_pub: &[u8; 32]) -> Result<(), CollectorError> {
        let recomputed = self.compute_hash()?;
        let stored = hex::decode(&self.this_manifest_hash)
            .map_err(|e| CollectorError::Verify(format!("hex decode hash: {e}")))?;
        if stored.len() != 32 || recomputed[..] != stored[..] {
            return Err(CollectorError::Verify(
                "manifest content != this_manifest_hash".into(),
            ));
        }
        let sig_bytes = base64_decode(&self.signature)
            .map_err(|e| CollectorError::Verify(format!("sig base64: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(CollectorError::Verify("signature wrong length".into()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let vk = VerifyingKey::from_bytes(signing_pub)
            .map_err(|e| CollectorError::Verify(format!("pubkey: {e}")))?;
        let signature = Signature::from_bytes(&sig);
        vk.verify(&recomputed, &signature)
            .map_err(|e| CollectorError::Verify(format!("signature: {e}")))
    }
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, CollectorError> {
    serde_json::from_slice(bytes)
        .map_err(|e| CollectorError::Verify(format!("parse manifest: {e}")))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 char: {c}")),
        }
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length not multiple of 4".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if pad < 2 { val(chunk[2])? } else { 0 };
        let v3 = if pad < 1 { val(chunk[3])? } else { 0 };
        out.push((v0 << 2) | (v1 >> 4));
        if pad < 2 {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if pad < 1 {
            out.push((v2 << 6) | v3);
        }
    }
    Ok(out)
}

fn base64_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPH[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
pub fn test_base64_encode(input: &[u8]) -> String {
    base64_encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;

    fn fresh_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn sample() -> Manifest {
        Manifest {
            v: "katagrapho-manifest-v1".into(),
            session_id: "abc".into(),
            part: 0,
            user: "alice".into(),
            host: "nyx".into(),
            boot_id: "00000000-0000-0000-0000-000000000000".into(),
            audit_session_id: Some(42),
            started: 1.0,
            ended: 2.0,
            katagrapho_version: "0.3.0".into(),
            katagrapho_commit: "deadbee".into(),
            epitropos_version: "0.1.0".into(),
            epitropos_commit: "cafebab".into(),
            recording_file: "abc.part0.kgv1.age".into(),
            recording_size: 1024,
            recording_sha256: "00".repeat(32),
            chunks: vec![],
            end_reason: "eof".into(),
            exit_code: 0,
            prev_manifest_hash: "0".repeat(64),
            this_manifest_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    fn sign_in_place(m: &mut Manifest, sk: &SigningKey) {
        let digest = m.compute_hash().unwrap();
        let sig = sk.sign(&digest).to_bytes();
        m.this_manifest_hash = hex::encode(digest);
        m.signature = base64_encode(&sig);
    }

    #[test]
    fn valid_manifest_verifies() {
        let sk = fresh_signing_key();
        let pub_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let mut m = sample();
        sign_in_place(&mut m, &sk);
        m.verify(&pub_bytes).unwrap();
    }

    #[test]
    fn tampered_user_fails() {
        let sk = fresh_signing_key();
        let pub_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let mut m = sample();
        sign_in_place(&mut m, &sk);
        m.user = "mallory".into();
        assert!(m.verify(&pub_bytes).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk = fresh_signing_key();
        let mut m = sample();
        sign_in_place(&mut m, &sk);
        let other = fresh_signing_key().verifying_key().to_bytes();
        assert!(m.verify(&other).is_err());
    }
}
