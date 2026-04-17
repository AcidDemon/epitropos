//! Ed25519 key loading and signing for sentinel events sidecars.

#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::SentinelError;

pub struct KeyPair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl KeyPair {
    pub fn load(key_path: &Path, pub_path: &Path) -> Result<Self, SentinelError> {
        let key_bytes = fs::read(key_path)
            .map_err(|e| SentinelError::Signing(format!("read {}: {e}", key_path.display())))?;
        if key_bytes.len() != 32 {
            return Err(SentinelError::Signing(format!(
                "{} must be exactly 32 bytes, got {}",
                key_path.display(),
                key_bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();

        if pub_path.exists() {
            let on_disk = fs::read(pub_path).map_err(|e| {
                SentinelError::Signing(format!("read {}: {e}", pub_path.display()))
            })?;
            if on_disk.len() != 32 || on_disk != verifying.as_bytes() {
                return Err(SentinelError::Signing(
                    "signing.pub does not match signing.key".into(),
                ));
            }
        }
        Ok(Self { signing, verifying })
    }

    pub fn generate_to(key_path: &Path, pub_path: &Path) -> Result<Self, SentinelError> {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();

        write_atomic(key_path, signing.as_bytes(), 0o400)?;
        write_atomic(pub_path, verifying.as_bytes(), 0o444)?;
        Ok(Self { signing, verifying })
    }

    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(digest).to_bytes()
    }

    pub fn key_id_hex(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.verifying.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }
}

pub fn verify_with_pub(
    pub_bytes: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), SentinelError> {
    let vk = VerifyingKey::from_bytes(pub_bytes)
        .map_err(|e| SentinelError::Verify(format!("invalid pubkey: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(digest, &sig)
        .map_err(|e| SentinelError::Verify(format!("signature: {e}")))
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), SentinelError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| SentinelError::Signing(format!("mkdir: {e}")))?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| SentinelError::Signing(format!("open: {e}")))?;
    f.write_all(data)
        .map_err(|e| SentinelError::Signing(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| SentinelError::Signing(format!("fsync: {e}")))?;
    drop(f);
    fs::rename(&tmp, path)
        .map_err(|e| SentinelError::Signing(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_load_round_trip() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let kp2 = KeyPair::load(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        assert_eq!(kp.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn sign_verify_round_trip() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let d = [7u8; 32];
        let s = kp.sign(&d);
        verify_with_pub(&kp.public_bytes(), &d, &s).unwrap();
    }

    #[test]
    fn verify_rejects_tampered() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let d = [7u8; 32];
        let mut s = kp.sign(&d);
        s[0] ^= 0xFF;
        assert!(verify_with_pub(&kp.public_bytes(), &d, &s).is_err());
    }
}
