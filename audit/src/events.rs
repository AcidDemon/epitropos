//! Privilege-events sidecar: build + sign + atomic write + verify. Same
//! canonical-bytes + ed25519 + hash-chain contract as the sentinel events
//! sidecar, but an authoritative kernel-sourced feed (not content regex).

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::AuditError;
use crate::signing::{KeyPair, verify_with_pub};

pub const EVENTS_VERSION: &str = "epitropos-audit-events-v1";
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Quantize a timestamp to milliseconds. Every float in the sidecar is a time
/// value with no sub-ms meaning, and full-precision floats (notably `t`, a
/// `event_ts - started` subtraction) don't survive the JSON write→parse round
/// trip bit-for-bit — which would make the signed canonical hash unverifiable.
/// Rounding to ms keeps the canonical form stable across the round trip.
pub(crate) fn round_ms(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// One authoritative privilege-escalation event, from the kernel audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEvent {
    /// seconds into the recording (kernel event time − session start).
    pub t: f64,
    /// sudo | su | doas | setuid | auth
    pub kind: String,
    /// real user behind the escalation (auid resolved).
    pub actor_user: String,
    /// user escalated to (euid resolved, e.g. "root").
    pub target_user: String,
    /// the command executed, if captured (EXECVE), else "".
    pub command: String,
    pub tty: String,
    /// success | denied
    pub result: String,
    /// kernel audit session id this event carried (== recording audit_session_id).
    pub ses: u32,
    /// absolute kernel event timestamp (provenance).
    pub audit_ts: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEventsSidecar {
    pub v: String,
    pub session_id: String,
    pub part: u32,
    pub audit_version: String,
    pub audit_commit: String,
    /// The (boot_id, audit_session_id) tuple this sidecar was joined on — the
    /// authoritative provenance linking these kernel events to the recording.
    pub boot_id: String,
    pub audit_session_id: u32,
    pub analyzed_at: f64,
    pub events: Vec<PrivilegeEvent>,
    pub prev_events_hash: String,
    #[serde(default)]
    pub this_events_hash: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub signature: String,
}

impl PrivilegeEventsSidecar {
    fn canonical_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let json = serde_json::to_string(&serde_json::json!({
            "v": self.v,
            "session_id": self.session_id,
            "part": self.part,
            "audit_version": self.audit_version,
            "audit_commit": self.audit_commit,
            "boot_id": self.boot_id,
            "audit_session_id": self.audit_session_id,
            "analyzed_at": self.analyzed_at,
            "events": self.events,
            "prev_events_hash": self.prev_events_hash,
        }))
        .map_err(|e| AuditError::Events(format!("canonical: {e}")))?;
        Ok(json.into_bytes())
    }

    pub fn compute_hash(&self) -> Result<[u8; 32], AuditError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn sign(&mut self, key: &KeyPair) -> Result<(), AuditError> {
        let digest = self.compute_hash()?;
        self.this_events_hash = hex::encode(digest);
        self.key_id = key.key_id_hex();
        self.signature = base64_encode(&key.sign(&digest));
        Ok(())
    }

    pub fn verify(&self, pub_bytes: &[u8; 32]) -> Result<(), AuditError> {
        let recomputed = self.compute_hash()?;
        let stored = hex::decode(&self.this_events_hash)
            .map_err(|e| AuditError::Verify(format!("hex: {e}")))?;
        if stored.len() != 32 || recomputed[..] != stored[..] {
            return Err(AuditError::Verify("content != this_events_hash".into()));
        }
        let sig_bytes =
            base64_decode(&self.signature).map_err(|e| AuditError::Verify(format!("sig: {e}")))?;
        if sig_bytes.len() != 64 {
            return Err(AuditError::Verify("sig wrong length".into()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        verify_with_pub(pub_bytes, &recomputed, &sig)
    }

    pub fn write_to(&self, path: &Path) -> Result<(), AuditError> {
        let tmp = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AuditError::Events(format!("serialize: {e}")))?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o640)
            .open(&tmp)
            .map_err(|e| AuditError::Events(format!("open: {e}")))?;
        f.write_all(json.as_bytes())
            .map_err(|e| AuditError::Events(format!("write: {e}")))?;
        f.sync_all()
            .map_err(|e| AuditError::Events(format!("fsync: {e}")))?;
        drop(f);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))
            .map_err(|e| AuditError::Events(format!("chmod: {e}")))?;
        fs::rename(&tmp, path).map_err(|e| AuditError::Events(format!("rename: {e}")))?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self, AuditError> {
        let bytes = fs::read(path)
            .map_err(|e| AuditError::Events(format!("read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AuditError::Events(format!("parse {}: {e}", path.display())))
    }
}

fn base64_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

    fn sample() -> PrivilegeEventsSidecar {
        PrivilegeEventsSidecar {
            v: EVENTS_VERSION.into(),
            session_id: "s1".into(),
            part: 0,
            audit_version: "0.1.0".into(),
            audit_commit: "abc".into(),
            boot_id: "11111111-2222-3333-4444-555555555555".into(),
            audit_session_id: 42,
            analyzed_at: 1.0,
            events: vec![PrivilegeEvent {
                t: 7.1,
                kind: "su".into(),
                actor_user: "p.okonkwo".into(),
                target_user: "root".into(),
                command: "su -".into(),
                tty: "pts/0".into(),
                result: "success".into(),
                ses: 42,
                audit_ts: 1_712_500_007.1,
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
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        s.verify(&kp.public_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        s.events[0].target_user = "mallory".into();
        assert!(s.verify(&kp.public_bytes()).is_err());
    }

    #[test]
    fn write_load_round_trip() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.sign(&kp).unwrap();
        let path = dir.path().join("privileges.json");
        s.write_to(&path).unwrap();
        PrivilegeEventsSidecar::load_from(&path)
            .unwrap()
            .verify(&kp.public_bytes())
            .unwrap();
    }

    // Regression: full-precision runtime timestamps (e.g. the `t` subtraction)
    // don't survive the JSON write→parse round trip bit-for-bit, so the signed
    // canonical hash was unverifiable. Quantized to ms (as correlate does), the
    // canonical form must be stable across write→load. Raw (unrounded) values
    // reproduce the original failure.
    #[test]
    fn sign_verify_survives_ms_rounded_floats() {
        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_to(&dir.path().join("k"), &dir.path().join("p")).unwrap();
        let mut s = sample();
        s.analyzed_at = round_ms(1783980930.187805);
        s.audit_session_id = 1;
        s.events[0].t = round_ms(119.97199988365173);
        s.events[0].audit_ts = round_ms(1783980929.972);
        s.events[0].ses = 1;
        s.sign(&kp).unwrap();
        let path = dir.path().join("privileges.json");
        s.write_to(&path).unwrap();
        PrivilegeEventsSidecar::load_from(&path)
            .unwrap()
            .verify(&kp.public_bytes())
            .unwrap();
    }
}
