//! Correlate parsed kernel audit events to a recording via the authoritative
//! tuple (host, boot_id, audit_session_id), building an unsigned sidecar.
//! Rejects unjoinable recordings (null audit_session_id or boot_id=="unknown").

use crate::error::AuditError;
use crate::events::{
    EVENTS_VERSION, GENESIS_PREV, PrivilegeEvent, PrivilegeEventsSidecar, round_ms,
};
use crate::manifest::Manifest;
use crate::parse::AuditEvent;

/// Small tolerance (seconds) around the recording window: a PAM auth fires just
/// before the exec, and clocks aren't perfectly aligned.
const WINDOW_SLACK: f64 = 3.0;

pub fn correlate(
    manifest: &Manifest,
    audit_events: &[AuditEvent],
    audit_version: &str,
    audit_commit: &str,
    analyzed_at: f64,
    prev_events_hash: &str,
) -> Result<PrivilegeEventsSidecar, AuditError> {
    let ses = manifest.audit_session_id.ok_or_else(|| {
        AuditError::Correlate(
            "recording has no audit_session_id (pam_loginuid absent?) — unjoinable".into(),
        )
    })?;
    if manifest.boot_id == "unknown" || manifest.boot_id.is_empty() {
        return Err(AuditError::Correlate(
            "recording boot_id is unknown — unjoinable".into(),
        ));
    }

    let lo = manifest.started - WINDOW_SLACK;
    let hi = manifest.ended + WINDOW_SLACK;

    let mut events: Vec<PrivilegeEvent> = audit_events
        .iter()
        .filter(|e| e.ses == Some(ses) && e.ts >= lo && e.ts <= hi)
        .map(|e| PrivilegeEvent {
            t: round_ms((e.ts - manifest.started).max(0.0)),
            kind: e.kind.clone(),
            actor_user: uid_to_name(e.auid),
            target_user: if !e.acct.is_empty() {
                e.acct.clone()
            } else {
                uid_to_name(e.euid)
            },
            command: e.command.clone(),
            tty: e.tty.clone(),
            result: e.result.clone(),
            ses,
            audit_ts: round_ms(e.ts),
        })
        .collect();

    // dedup identical markers (same rounded time + kind + command)
    events.sort_by(|a, b| a.t.partial_cmp(&b.t).unwrap_or(std::cmp::Ordering::Equal));
    events.dedup_by(|a, b| {
        (a.t - b.t).abs() < 0.5
            && a.kind == b.kind
            && a.command == b.command
            && a.result == b.result
    });

    Ok(PrivilegeEventsSidecar {
        v: EVENTS_VERSION.to_string(),
        session_id: manifest.session_id.clone(),
        part: manifest.part,
        audit_version: audit_version.to_string(),
        audit_commit: audit_commit.to_string(),
        boot_id: manifest.boot_id.clone(),
        audit_session_id: ses,
        analyzed_at,
        events,
        prev_events_hash: if prev_events_hash.is_empty() {
            GENESIS_PREV.to_string()
        } else {
            prev_events_hash.to_string()
        },
        this_events_hash: String::new(),
        key_id: String::new(),
        signature: String::new(),
    })
}

/// Resolve a numeric uid to a username via getpwuid; falls back to "uid:N".
fn uid_to_name(uid: Option<u32>) -> String {
    let Some(u) = uid else {
        return String::new();
    };
    unsafe {
        let pw = libc::getpwuid(u as libc::uid_t);
        if pw.is_null() {
            format!("uid:{u}")
        } else {
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(ses: Option<u32>, boot: &str) -> Manifest {
        Manifest {
            session_id: "S1".into(),
            part: 0,
            host: "h".into(),
            boot_id: boot.into(),
            audit_session_id: ses,
            started: 1000.0,
            ended: 1100.0,
        }
    }
    fn ev(ts: f64, ses: Option<u32>) -> AuditEvent {
        AuditEvent {
            ts,
            ses,
            kind: "su".into(),
            auid: Some(0),
            euid: Some(0),
            tty: "pts/0".into(),
            command: "su -".into(),
            result: "success".into(),
            acct: String::new(),
        }
    }

    #[test]
    fn joins_by_ses_and_window() {
        let m = manifest(Some(42), "boot-1");
        let events = [
            ev(1007.0, Some(42)), // in session, right ses → kept, t=7
            ev(1050.0, Some(99)), // wrong ses → dropped
            ev(5000.0, Some(42)), // out of window → dropped
        ];
        let sc = correlate(&m, &events, "0.1", "c", 0.0, "").unwrap();
        assert_eq!(sc.events.len(), 1);
        assert_eq!(sc.events[0].t, 7.0);
        assert_eq!(sc.audit_session_id, 42);
    }

    #[test]
    fn quantizes_event_times_for_stable_signing() {
        let m = manifest(Some(1), "boot-1"); // started 1000.0, ended 1100.0
        let events = [ev(1050.97199988365173, Some(1))]; // full-precision ts, in window
        let sc = correlate(&m, &events, "0.1", "c", 0.0, "").unwrap();
        assert_eq!(sc.events[0].t, 50.972); // ms-quantized, round-trip stable
        assert_eq!(sc.events[0].audit_ts, round_ms(1050.97199988365173));
    }

    #[test]
    fn rejects_null_ses() {
        assert!(correlate(&manifest(None, "boot-1"), &[], "0.1", "c", 0.0, "").is_err());
    }

    #[test]
    fn rejects_unknown_boot() {
        assert!(correlate(&manifest(Some(42), "unknown"), &[], "0.1", "c", 0.0, "").is_err());
    }
}
