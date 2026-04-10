//! Enrollment tokens: HMAC-SHA256 construction, stateful single-use.

#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CollectorError;

type HmacSha256 = Hmac<Sha256>;
const TOKEN_PREFIX: &str = "epitropos-enroll:";
const BODY_LEN: usize = 16 + 16 + 8;

pub struct EnrollmentDir {
    pub pending: PathBuf,
    pub burned: PathBuf,
    pub lock: PathBuf,
}

impl EnrollmentDir {
    pub fn under(storage_dir: &Path) -> Self {
        let base = storage_dir.join("enrollments");
        Self {
            pending: base.join("pending"),
            burned: base.join("burned"),
            lock: base.join("lock"),
        }
    }

    pub fn ensure_created(&self) -> Result<(), CollectorError> {
        for p in [&self.pending, &self.burned] {
            fs::create_dir_all(p)
                .map_err(|e| CollectorError::Enroll(format!("mkdir {}: {e}", p.display())))?;
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_nonce() -> Result<[u8; 16], CollectorError> {
    let bytes = fs::read("/dev/urandom")
        .map_err(|e| CollectorError::Enroll(format!("urandom: {e}")))?;
    if bytes.len() < 16 {
        return Err(CollectorError::Enroll("urandom < 16 bytes".into()));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    Ok(buf)
}

pub fn load_secret(path: &Path) -> Result<Vec<u8>, CollectorError> {
    let bytes = fs::read(path)
        .map_err(|e| CollectorError::Enroll(format!("read secret: {e}")))?;
    if bytes.len() < 32 {
        return Err(CollectorError::Enroll("secret < 32 bytes".into()));
    }
    Ok(bytes)
}

pub fn generate_secret(path: &Path) -> Result<(), CollectorError> {
    let bytes = fs::read("/dev/urandom")
        .map_err(|e| CollectorError::Enroll(format!("urandom: {e}")))?;
    if bytes.len() < 32 {
        return Err(CollectorError::Enroll("urandom < 32 bytes".into()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CollectorError::Enroll(format!("mkdir: {e}")))?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o400)
        .open(path)
        .map_err(|e| CollectorError::Enroll(format!("open secret: {e}")))?;
    f.write_all(&bytes[..32])
        .map_err(|e| CollectorError::Enroll(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Enroll(format!("fsync: {e}")))?;
    Ok(())
}

fn hmac_body(secret: &[u8], sender_name: &str, nonce: &[u8; 16], expires_at: u64) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key len");
    mac.update(sender_name.as_bytes());
    mac.update(nonce);
    mac.update(&expires_at.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&out[..16]);
    truncated
}

pub struct GeneratedToken {
    pub token: String,
    pub token_hash_hex: String,
    pub expires_at: u64,
}

pub fn generate_token(
    secret: &[u8],
    sender_name: &str,
    ttl_seconds: u64,
) -> Result<GeneratedToken, CollectorError> {
    let nonce = random_nonce()?;
    let expires_at = now_secs() + ttl_seconds;
    let mac = hmac_body(secret, sender_name, &nonce, expires_at);
    let mut body = [0u8; BODY_LEN];
    body[..16].copy_from_slice(&mac);
    body[16..32].copy_from_slice(&nonce);
    body[32..].copy_from_slice(&expires_at.to_be_bytes());
    let encoded = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &body,
    );
    let token = format!("{TOKEN_PREFIX}{encoded}");

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let hash_hex = hex::encode(hasher.finalize());

    Ok(GeneratedToken {
        token,
        token_hash_hex: hash_hex,
        expires_at,
    })
}

pub fn write_pending(
    dir: &EnrollmentDir,
    token_hash_hex: &str,
    sender_name: &str,
    expires_at: u64,
) -> Result<(), CollectorError> {
    dir.ensure_created()?;
    let path = dir.pending.join(format!("{token_hash_hex}.json"));
    let body = serde_json::json!({
        "sender_name": sender_name,
        "expires_at": expires_at,
    });
    let s = serde_json::to_string(&body)
        .map_err(|e| CollectorError::Enroll(format!("serialize: {e}")))?;
    crate::storage::put_atomic(&path, s.as_bytes())
}

#[derive(Debug)]
pub enum ValidateResult {
    Ok { sender_name: String },
    Expired,
    AlreadyBurned,
    NotPending,
    BadMac,
    Malformed,
}

pub fn validate_token(
    secret: &[u8],
    dir: &EnrollmentDir,
    token: &str,
) -> Result<ValidateResult, CollectorError> {
    let body = match token.strip_prefix(TOKEN_PREFIX) {
        Some(b) => b,
        None => return Ok(ValidateResult::Malformed),
    };
    let raw = match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, body) {
        Some(r) if r.len() == BODY_LEN => r,
        _ => return Ok(ValidateResult::Malformed),
    };

    let mut mac = [0u8; 16];
    mac.copy_from_slice(&raw[..16]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&raw[16..32]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&raw[32..]);
    let expires_at = u64::from_be_bytes(ts);

    if expires_at < now_secs() {
        return Ok(ValidateResult::Expired);
    }

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let hash_hex = hex::encode(hasher.finalize());

    if dir.burned.join(&hash_hex).exists() {
        return Ok(ValidateResult::AlreadyBurned);
    }
    let pending_path = dir.pending.join(format!("{hash_hex}.json"));
    if !pending_path.exists() {
        return Ok(ValidateResult::NotPending);
    }
    let pending_json = fs::read(&pending_path)
        .map_err(|e| CollectorError::Enroll(format!("read pending: {e}")))?;
    let pending: serde_json::Value = serde_json::from_slice(&pending_json)
        .map_err(|e| CollectorError::Enroll(format!("parse pending: {e}")))?;
    let sender_name = pending["sender_name"].as_str().unwrap_or("").to_string();
    if sender_name.is_empty() {
        return Ok(ValidateResult::Malformed);
    }

    let expected = hmac_body(secret, &sender_name, &nonce, expires_at);
    let mut match_bytes: u8 = 0;
    for (a, b) in expected.iter().zip(mac.iter()) {
        match_bytes |= a ^ b;
    }
    if match_bytes != 0 {
        return Ok(ValidateResult::BadMac);
    }

    Ok(ValidateResult::Ok { sender_name })
}

pub fn burn(dir: &EnrollmentDir, token_hash_hex: &str) -> Result<(), CollectorError> {
    dir.ensure_created()?;
    let burn_path = dir.burned.join(token_hash_hex);
    fs::write(&burn_path, b"")
        .map_err(|e| CollectorError::Enroll(format!("write burn: {e}")))?;
    let _ = fs::remove_file(dir.pending.join(format!("{token_hash_hex}.json")));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup() -> (tempfile::TempDir, Vec<u8>, EnrollmentDir) {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("enroll.secret");
        generate_secret(&secret_path).unwrap();
        let secret = load_secret(&secret_path).unwrap();
        let edir = EnrollmentDir::under(dir.path());
        edir.ensure_created().unwrap();
        (dir, secret, edir)
    }

    #[test]
    fn generate_and_validate_round_trip() {
        let (_dir, secret, edir) = setup();
        let gt = generate_token(&secret, "alice", 60).unwrap();
        write_pending(&edir, &gt.token_hash_hex, "alice", gt.expires_at).unwrap();
        match validate_token(&secret, &edir, &gt.token).unwrap() {
            ValidateResult::Ok { sender_name } => assert_eq!(sender_name, "alice"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn burned_token_rejected() {
        let (_dir, secret, edir) = setup();
        let gt = generate_token(&secret, "alice", 60).unwrap();
        write_pending(&edir, &gt.token_hash_hex, "alice", gt.expires_at).unwrap();
        burn(&edir, &gt.token_hash_hex).unwrap();
        assert!(matches!(
            validate_token(&secret, &edir, &gt.token).unwrap(),
            ValidateResult::AlreadyBurned
        ));
    }

    #[test]
    fn malformed_token_rejected() {
        let (_dir, secret, edir) = setup();
        assert!(matches!(
            validate_token(&secret, &edir, "not-a-token").unwrap(),
            ValidateResult::Malformed
        ));
    }

    #[test]
    fn wrong_secret_rejected() {
        let (dir, _secret, edir) = setup();
        let mut other = vec![0u8; 32];
        other[0] = 0xFF;
        let gt = generate_token(&other, "alice", 60).unwrap();
        write_pending(&edir, &gt.token_hash_hex, "alice", gt.expires_at).unwrap();
        let secret_path = dir.path().join("enroll.secret");
        let good = load_secret(&secret_path).unwrap();
        assert!(matches!(
            validate_token(&good, &edir, &gt.token).unwrap(),
            ValidateResult::BadMac
        ));
    }
}
