//! Events sidecar: build + sign + atomic write + verify.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::SentinelError;
use crate::signing::{KeyPair, verify_with_pub};

pub const EVENTS_VERSION: &str = "epitropos-sentinel-events-v1";
pub const GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub t: f64,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub matched_text: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsSidecar {
    pub v: String,
    pub session_id: String,
    pub part: u32,
    pub sentinel_version: String,
    pub sentinel_commit: String,
    pub rules_file_sha256: String,
    pub analyzed_at: f64,
    pub events: Vec<EventRecord>,
    pub prev_events_hash: String,
    #[serde(default)]
    pub this_events_hash: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub signature: String,
}

impl EventsSidecar {
    fn canonical_bytes(&self) -> Result<Vec<u8>, SentinelError> {
        let json = serde_json::to_string(&serde_json::json!({
            "v": self.v,
            "session_id": self.session_id,
            "part": self.part,
            "sentinel_version": self.sentinel_version,
            "sentinel_commit": self.sentinel_commit,
            "rules_file_sha256": self.rules_file_sha256,
            "analyzed_at": self.analyzed_at,
            "events": self.events,
            "prev_events_hash": self.prev_events_hash,
        }))
        .map_err(|e| SentinelError::Events(format!("canonical: {e}")))?;
        Ok(json.into_bytes())
    }

    pub fn compute_hash(&self) -> Result<[u8; 32], SentinelError> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Ok(h.finalize().into())
    }

    pub fn sign(&mut self, key: &KeyPair) -> Result<(), SentinelError> {
        let digest = self.compute_hash()?;
        let sig = key.sign(&digest);
        self.this_events_hash = hex::encode(digest);
        self.key_id = key.key_id_hex();
        self.signature = base64_encode(&sig);
        Ok(())
    }

    pub fn verify(&self, pub_bytes: &[u8; 32]) -> Result<(), SentinelError> {
        let recomputed = self.compute_hash()?;
        let stored = hex::decode(&self.this_events_hash)
            .map_err(|e| SentinelError::Verify(format!("hex: {e}")))?;
        if stored.len() != 32 || recomputed[..] != stored[..] {
            return Err(SentinelError::Verify("content != this_events_hash".into()));
        }
        let sig_bytes = base64_decode(&self.signature)
            .map_err(|e| SentinelError::Verify(format!("sig: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(SentinelError::Verify("sig wrong length".into()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        verify_with_pub(pub_bytes, &recomputed, &sig)
    }

    pub fn write_to(&self, path: &Path) -> Result<(), SentinelError> {
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SentinelError::Events(format!("serialize: {e}")))?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o640)
            .open(&tmp)
            .map_err(|e| SentinelError::Events(format!("open: {e}")))?;
        f.write_all(json.as_bytes())
            .map_err(|e| SentinelError::Events(format!("write: {e}")))?;
        f.sync_all()
            .map_err(|e| SentinelError::Events(format!("fsync: {e}")))?;
        drop(f);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))
            .map_err(|e| SentinelError::Events(format!("chmod: {e}")))?;
        fs::rename(&tmp, path)
            .map_err(|e| SentinelError::Events(format!("rename: {e}")))?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self, SentinelError> {
        let bytes = fs::read(path)
            .map_err(|e| SentinelError::Events(format!("read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| SentinelError::Events(format!("parse {}: {e}", path.display())))
    }
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
        return Err("base64 len not multiple of 4".into());
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample() -> EventsSidecar {
        EventsSidecar {
            v: EVENTS_VERSION.into(),
            session_id: "s1".into(),
            part: 0,
            sentinel_version: "0.1.0".into(),
            sentinel_commit: "abc".into(),
            rules_file_sha256: "00".repeat(32),
            analyzed_at: 1.0,
            events: vec![EventRecord {
                t: 1.23,
                rule_id: "test".into(),
                severity: "high".into(),
                category: "test".into(),
                description: "test".into(),
                matched_text: "sudo".into(),
                context: "prompt$ sudo".into(),
            }],
            prev_events_hash: GENESIS_PREV.into(),
            this_events_hash: String::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        s.verify(&kp.public_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        s.events[0].matched_text = "tampered".into();
        assert!(s.verify(&kp.public_bytes()).is_err());
    }

    #[test]
    fn write_load_round_trip() {
        let dir = tempdir().unwrap();
        let kp =
            KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        let path = dir.path().join("events.json");
        s.write_to(&path).unwrap();
        let loaded = EventsSidecar::load_from(&path).unwrap();
        loaded.verify(&kp.public_bytes()).unwrap();
    }
}
