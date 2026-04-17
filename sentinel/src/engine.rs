//! Per-session orchestration: decrypt → match → emit journald + write events sidecar.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::chain::{self, ChainLock, ChainPaths};
use crate::config::Config;
use crate::decrypt::iterate_records;
use crate::error::SentinelError;
use crate::events::{EventRecord, EventsSidecar, EVENTS_VERSION};
use crate::journal::{self, MatchEvent};
use crate::rules::{RuleSet, SessionMatcher};
use crate::signing::KeyPair;

pub struct AnalysisContext<'a> {
    pub cfg: &'a Config,
    pub rules: &'a RuleSet,
    pub age_identity: &'a str,
    pub signing: &'a KeyPair,
    pub emit_journal: bool,
}

pub struct ManifestHeader {
    pub session_id: String,
    pub user: String,
    pub host: String,
    pub part: u32,
}

pub fn analyze_recording(
    ctx: &AnalysisContext,
    recording_path: &Path,
    manifest: &ManifestHeader,
    force: bool,
) -> Result<PathBuf, SentinelError> {
    let sidecar_path = sidecar_path_for(recording_path);
    if sidecar_path.exists() && !force {
        return Err(SentinelError::Events(format!(
            "events sidecar already exists at {} (use --force to overwrite)",
            sidecar_path.display()
        )));
    }

    let mut matcher = SessionMatcher::new(
        ctx.rules,
        ctx.cfg.cooldown.per_rule_per_session_seconds,
        ctx.cfg.context.before_chars,
        ctx.cfg.context.after_chars,
    );

    let mut events: Vec<EventRecord> = Vec::new();

    iterate_records(recording_path, ctx.age_identity, |rec| {
        if (rec.kind == "out" || rec.kind == "in")
            && let Some(ref text) = rec.data
        {
                let hits = matcher.feed(rec.t, text);
                for h in hits {
                    if ctx.emit_journal {
                        journal::emit_match(&MatchEvent {
                            rule_id: &h.rule_id,
                            severity: &h.severity,
                            category: &h.category,
                            session_id: &manifest.session_id,
                            part: manifest.part,
                            user: &manifest.user,
                            host: &manifest.host,
                            t: h.session_time,
                            matched_text: &h.matched_text,
                        });
                    }
                    events.push(EventRecord {
                        t: h.session_time,
                        rule_id: h.rule_id,
                        severity: h.severity,
                        category: h.category,
                        description: h.description,
                        matched_text: h.matched_text,
                        context: h.context,
                    });
                }
            }
        Ok(())
    })?;

    let chain_paths = ChainPaths::new(ctx.cfg.chain.head_path.clone());
    let _lock = ChainLock::acquire(&chain_paths)?;
    let prev = chain::read_head(&chain_paths)?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let mut sidecar = EventsSidecar {
        v: EVENTS_VERSION.into(),
        session_id: manifest.session_id.clone(),
        part: manifest.part,
        sentinel_version: env!("CARGO_PKG_VERSION").into(),
        sentinel_commit: option_env!("EPITROPOS_SENTINEL_GIT_COMMIT")
            .unwrap_or("unknown")
            .into(),
        rules_file_sha256: ctx.rules.source_sha256.clone(),
        analyzed_at: now_unix,
        events,
        prev_events_hash: prev,
        this_events_hash: String::new(),
        key_id: String::new(),
        signature: String::new(),
    };
    sidecar.sign(ctx.signing)?;
    sidecar.write_to(&sidecar_path)?;

    chain::write_head(&chain_paths, &sidecar.this_events_hash)?;

    Ok(sidecar_path)
}

pub fn sidecar_path_for(recording: &Path) -> PathBuf {
    let mut s = recording.as_os_str().to_os_string();
    s.push(".events.json");
    PathBuf::from(s)
}
