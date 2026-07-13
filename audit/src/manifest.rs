//! Minimal reader for the katagrapho `.manifest.json` — the bridge table that
//! carries BOTH the kernel join keys (host, boot_id, audit_session_id) AND the
//! random recording session_id/part. We deserialize only the fields the
//! correlation needs; serde ignores the rest.

use serde::Deserialize;
use std::path::Path;

use crate::error::AuditError;

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub session_id: String,
    pub part: u32,
    pub host: String,
    pub boot_id: String,
    pub audit_session_id: Option<u32>,
    pub started: f64,
    pub ended: f64,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self, AuditError> {
        let bytes = fs_read(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AuditError::Manifest(format!("parse {}: {e}", path.display())))
    }
}

fn fs_read(path: &Path) -> Result<Vec<u8>, AuditError> {
    std::fs::read(path).map_err(|e| AuditError::Manifest(format!("read {}: {e}", path.display())))
}
