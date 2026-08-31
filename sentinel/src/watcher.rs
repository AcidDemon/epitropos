//! Inotify-driven discovery of new .manifest.json files.

#![allow(dead_code)]

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::engine::{self, AnalysisContext, ManifestHeader};
use crate::error::SentinelError;
use crate::rules::RuleSet;
use crate::signing::KeyPair;

pub fn watch_and_analyze(
    cfg: &Config,
    rules: &RuleSet,
    age_identity: &str,
    signing: &KeyPair,
) -> Result<(), SentinelError> {
    let mut inotify = Inotify::init().map_err(SentinelError::Io)?;
    // CLOSE_WRITE: locally-finished files. MOVED_TO: the collector writes
    // manifests via a tmp+rename (put_atomic), so the final .manifest.json
    // arrives as IN_MOVED_TO — the previous CLOSE_WRITE|CREATE mask missed
    // this, which is why live analysis never fired. CREATE|MOVED_TO also
    // surface new subdirectories to watch and scan.
    let mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE;
    let mut wd_paths: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

    // Recursively watch the whole storage subtree. Failing to watch the root is
    // fatal; an individual unwatchable subtree is logged and skipped (so a new
    // sender/user directory created after startup still gets watched+analyzed,
    // closing the previous "discovered once at startup" detection bypass).
    watch_tree(&mut inotify, &cfg.storage.dir, mask, &mut wd_paths, true)?;

    // Initial pass: analyze any existing recordings that lack a sidecar.
    scan_tree(cfg, rules, age_identity, signing, &cfg.storage.dir);

    let mut buffer = [0; 4096];
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .map_err(SentinelError::Io)?;

        // Resolve each event to its originating directory via the watch
        // descriptor (the previous code joined the name onto EVERY watched dir).
        // Defer watch-adds and analysis until the event borrow ends.
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
            // Watch the new subtree BEFORE scanning it — add-before-scan closes
            // the mkdir -> manifest-drop race.
            let _ = watch_tree(&mut inotify, &d, mask, &mut wd_paths, false);
            scan_tree(cfg, rules, age_identity, signing, &d);
        }
        for m in manifests {
            if m.exists() {
                handle_manifest(cfg, rules, age_identity, signing, &m);
            }
        }
    }
}

/// Recursively add an inotify watch to `dir` and every directory beneath it,
/// recording each watch descriptor -> path. Re-watching a directory is
/// idempotent (inotify returns the existing descriptor). A failure to watch a
/// non-root dir is logged and skipped rather than silently swallowed.
fn watch_tree(
    inotify: &mut Inotify,
    dir: &Path,
    mask: WatchMask,
    wd_paths: &mut HashMap<WatchDescriptor, PathBuf>,
    fatal: bool,
) -> Result<(), SentinelError> {
    match inotify.watches().add(dir, mask) {
        Ok(wd) => {
            wd_paths.insert(wd, dir.to_path_buf());
        }
        Err(e) => {
            eprintln!("epitropos-sentinel: cannot watch {}: {e}", dir.display());
            if fatal {
                return Err(SentinelError::Io(e));
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

/// Recursively analyze every recording under `dir` that has a manifest but no
/// events sidecar yet.
fn scan_tree(cfg: &Config, rules: &RuleSet, identity: &str, signing: &KeyPair, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            scan_tree(cfg, rules, identity, signing, &p);
        } else if p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".manifest.json"))
        {
            let recording = strip_manifest_suffix(&p);
            let sidecar = engine::sidecar_path_for(&recording);
            if !sidecar.exists() {
                handle_manifest(cfg, rules, identity, signing, &p);
            }
        }
    }
}

fn strip_manifest_suffix(manifest_path: &Path) -> PathBuf {
    let s = manifest_path.as_os_str().to_string_lossy().to_string();
    if let Some(stripped) = s.strip_suffix(".manifest.json") {
        return PathBuf::from(stripped);
    }
    manifest_path.to_path_buf()
}

fn handle_manifest(
    cfg: &Config,
    rules: &RuleSet,
    identity: &str,
    signing: &KeyPair,
    manifest_path: &Path,
) {
    let recording = strip_manifest_suffix(manifest_path);
    if !recording.exists() {
        eprintln!(
            "epitropos-sentinel: recording missing for {}",
            manifest_path.display()
        );
        return;
    }

    let header = match read_manifest_header(manifest_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("epitropos-sentinel: skip {}: {e}", manifest_path.display());
            return;
        }
    };

    let ctx = AnalysisContext {
        cfg,
        rules,
        age_identity: identity,
        signing,
        emit_journal: cfg.journal.enabled,
    };

    match engine::analyze_recording(&ctx, &recording, &header, false) {
        Ok(p) => eprintln!(
            "epitropos-sentinel: analyzed {} -> {}",
            recording.display(),
            p.display()
        ),
        Err(SentinelError::Events(msg)) if msg.contains("already exists") => {}
        Err(e) => eprintln!(
            "epitropos-sentinel: analyze {} failed: {e}",
            recording.display()
        ),
    }
}

fn read_manifest_header(path: &Path) -> Result<ManifestHeader, SentinelError> {
    let bytes = std::fs::read(path)
        .map_err(|e| SentinelError::Events(format!("read {}: {e}", path.display())))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| SentinelError::Events(format!("parse: {e}")))?;
    Ok(ManifestHeader {
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        user: v["user"].as_str().unwrap_or("").to_string(),
        host: v["host"].as_str().unwrap_or("").to_string(),
        part: v["part"].as_u64().unwrap_or(0) as u32,
    })
}
