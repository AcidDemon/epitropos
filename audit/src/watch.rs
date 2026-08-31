//! Inotify-driven daemon: when katagrapho finalizes a recording (its
//! `.manifest.json` lands), correlate the local audit trail and write the
//! `<recording>.privileges.json` sidecar. Mirrors epitropos-sentinel/watcher.rs,
//! but runs on the RECORDING host reading the local `audit.log` (the sudo/su
//! events happen here) rather than decrypting recordings on the collector.

#![allow(dead_code)]

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::analyze::{self, default_out};
use crate::error::AuditError;
use crate::signing::KeyPair;

pub struct WatchConfig {
    pub recordings_dir: PathBuf,
    pub audit_log: PathBuf,
    pub chain_head: PathBuf,
}

pub fn serve(cfg: &WatchConfig, key: &KeyPair) -> Result<(), AuditError> {
    let mut inotify = Inotify::init().map_err(AuditError::Io)?;
    // MOVED_TO because katagrapho writes the manifest via tmp+rename; CREATE to
    // pick up new sender/user subdirectories; CLOSE_WRITE for good measure.
    let mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE;
    let mut wd_paths: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

    watch_tree(&mut inotify, &cfg.recordings_dir, mask, &mut wd_paths, true)?;
    scan_tree(cfg, key, &cfg.recordings_dir); // backfill existing recordings

    eprintln!("epitropos-audit: watching {}", cfg.recordings_dir.display());
    let mut buffer = [0; 4096];
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .map_err(AuditError::Io)?;
        let mut new_dirs: Vec<PathBuf> = Vec::new();
        let mut manifests: Vec<PathBuf> = Vec::new();
        for ev in events {
            let Some(dir) = wd_paths.get(&ev.wd).cloned() else {
                continue;
            };
            let Some(name) = ev.name else { continue };
            let child = dir.join(name.to_string_lossy().as_ref());
            if ev.mask.contains(EventMask::ISDIR) {
                new_dirs.push(child);
            } else if name.to_string_lossy().ends_with(".manifest.json") {
                manifests.push(child);
            }
        }
        for d in new_dirs {
            let _ = watch_tree(&mut inotify, &d, mask, &mut wd_paths, false);
            scan_tree(cfg, key, &d);
        }
        for m in manifests {
            if m.exists() {
                handle_manifest(cfg, key, &m);
            }
        }
    }
}

fn watch_tree(
    inotify: &mut Inotify,
    dir: &Path,
    mask: WatchMask,
    wd_paths: &mut HashMap<WatchDescriptor, PathBuf>,
    fatal: bool,
) -> Result<(), AuditError> {
    match inotify.watches().add(dir, mask) {
        Ok(wd) => {
            wd_paths.insert(wd, dir.to_path_buf());
        }
        Err(e) => {
            eprintln!("epitropos-audit: cannot watch {}: {e}", dir.display());
            if fatal {
                return Err(AuditError::Io(e));
            }
            return Ok(());
        }
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let _ = watch_tree(inotify, &p, mask, wd_paths, false);
            }
        }
    }
    Ok(())
}

fn scan_tree(cfg: &WatchConfig, key: &KeyPair, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            scan_tree(cfg, key, &p);
        } else if p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".manifest.json"))
        {
            handle_manifest(cfg, key, &p);
        }
    }
}

fn handle_manifest(cfg: &WatchConfig, key: &KeyPair, manifest_path: &Path) {
    // idempotent: skip if the sidecar already exists
    if default_out(manifest_path).exists() {
        return;
    }
    match analyze::run_once(manifest_path, &cfg.audit_log, key, &cfg.chain_head, None) {
        Ok(sc) => eprintln!(
            "epitropos-audit: wrote sidecar for {} ({} events)",
            sc.session_id,
            sc.events.len()
        ),
        // an unjoinable recording (null audit_session_id / boot_id) is expected
        // and not fatal — log at low volume and move on.
        Err(AuditError::Correlate(msg)) => {
            eprintln!("epitropos-audit: skip {}: {msg}", manifest_path.display())
        }
        Err(e) => eprintln!("epitropos-audit: {} failed: {e}", manifest_path.display()),
    }
}
