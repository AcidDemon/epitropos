//! The correlate-sign-write-chain flow, shared by the CLI (`analyze`) and the
//! watcher daemon (`serve`).

use std::path::{Path, PathBuf};

use crate::chain::{self, ChainLock, ChainPaths};
use crate::correlate::correlate;
use crate::error::AuditError;
use crate::events::PrivilegeEventsSidecar;
use crate::manifest::Manifest;
use crate::parse;
use crate::signing::KeyPair;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn commit() -> &'static str {
    option_env!("EPITROPOS_AUDIT_GIT_COMMIT").unwrap_or("dev")
}

/// Correlate `audit_log_path` to the recording named by `manifest_path`, sign
/// the sidecar, write it, and advance the per-host chain (under the chain lock).
pub fn run_once(
    manifest_path: &Path,
    audit_log_path: &Path,
    key: &KeyPair,
    chain_head: &Path,
    out: Option<PathBuf>,
) -> Result<PrivilegeEventsSidecar, AuditError> {
    let manifest = Manifest::load(manifest_path)?;
    let audit_text = std::fs::read_to_string(audit_log_path)?;
    let audit_events = parse::parse(&audit_text);

    let chain_paths = ChainPaths::new(chain_head.to_path_buf());
    let _lock = ChainLock::acquire(&chain_paths)?;
    let prev = chain::read_head(&chain_paths)?;

    let mut sidecar = correlate(
        &manifest,
        &audit_events,
        VERSION,
        commit(),
        now_secs(),
        &prev,
    )?;
    sidecar.sign(key)?;

    let out = out.unwrap_or_else(|| default_out(manifest_path));
    sidecar.write_to(&out)?;
    chain::write_head(&chain_paths, &sidecar.this_events_hash)?;
    Ok(sidecar)
}

/// `<recording>.privileges.json`: strip the manifest's `.manifest.json` suffix.
pub fn default_out(manifest_path: &Path) -> PathBuf {
    let s = manifest_path.to_string_lossy();
    let recording = s.strip_suffix(".manifest.json").unwrap_or(&s);
    PathBuf::from(format!("{recording}.privileges.json"))
}

fn now_secs() -> f64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    crate::events::round_ms(secs)
}
