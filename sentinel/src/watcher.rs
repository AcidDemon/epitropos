//! Inotify-driven discovery of new .manifest.json files.

#![allow(dead_code)]

use inotify::{Inotify, WatchMask};
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

    let watched = discover_dirs(&cfg.storage.dir)?;
    for dir in &watched {
        let _ = inotify
            .watches()
            .add(dir, WatchMask::CLOSE_WRITE | WatchMask::CREATE);
    }

    // Initial pass: analyze any recordings without events sidecars.
    initial_pass(cfg, rules, age_identity, signing, &watched);

    let mut buffer = [0; 4096];
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .map_err(SentinelError::Io)?;

        for ev in events {
            if let Some(name) = ev.name {
                let name_s = name.to_string_lossy();
                if !name_s.ends_with(".manifest.json") {
                    continue;
                }
                for dir in &watched {
                    let candidate = dir.join(name_s.as_ref());
                    if candidate.exists() {
                        handle_manifest(cfg, rules, age_identity, signing, &candidate);
                    }
                }
            }
        }
    }
}

fn initial_pass(
    cfg: &Config,
    rules: &RuleSet,
    identity: &str,
    signing: &KeyPair,
    watched: &[PathBuf],
) {
    for dir in watched {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if name.ends_with(".manifest.json") {
                    let recording = strip_manifest_suffix(&path);
                    let sidecar = engine::sidecar_path_for(&recording);
                    if !sidecar.exists() {
                        handle_manifest(cfg, rules, identity, signing, &path);
                    }
                }
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

fn discover_dirs(storage_dir: &Path) -> Result<Vec<PathBuf>, SentinelError> {
    let mut dirs = Vec::new();
    let senders = storage_dir.join("senders");
    if !senders.exists() {
        return Ok(dirs);
    }
    if let Ok(entries) = std::fs::read_dir(&senders) {
        for entry in entries.flatten() {
            let recs = entry.path().join("recordings");
            if recs.exists() {
                if let Ok(user_dirs) = std::fs::read_dir(&recs) {
                    for user_entry in user_dirs.flatten() {
                        if user_entry.path().is_dir() {
                            dirs.push(user_entry.path());
                        }
                    }
                }
            }
        }
    }
    Ok(dirs)
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
            eprintln!(
                "epitropos-sentinel: skip {}: {e}",
                manifest_path.display()
            );
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
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| SentinelError::Events(format!("parse: {e}")))?;
    Ok(ManifestHeader {
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        user: v["user"].as_str().unwrap_or("").to_string(),
        host: v["host"].as_str().unwrap_or("").to_string(),
        part: v["part"].as_u64().unwrap_or(0) as u32,
    })
}
