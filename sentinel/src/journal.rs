//! Structured journald emission for sentinel matches.

#![allow(dead_code)]

use std::os::unix::net::UnixDatagram;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

pub struct MatchEvent<'a> {
    pub rule_id: &'a str,
    pub severity: &'a str,
    pub category: &'a str,
    pub session_id: &'a str,
    pub part: u32,
    pub user: &'a str,
    pub host: &'a str,
    pub t: f64,
    pub matched_text: &'a str,
}

pub fn emit_match(ev: &MatchEvent) {
    let priority = match ev.severity {
        "critical" => "2",
        "high" => "4",
        _ => "5",
    };
    let msg = format!(
        "sentinel: {} matched in session {} at t={:.3}",
        ev.rule_id, ev.session_id, ev.t
    );
    let part_s = ev.part.to_string();
    let t_s = format!("{:.3}", ev.t);

    let fields: &[(&str, &str)] = &[
        ("MESSAGE", &msg),
        ("PRIORITY", priority),
        ("SYSLOG_IDENTIFIER", "epitropos-sentinel"),
        ("EPITROPOS_SENTINEL_EVENT", "match"),
        ("EPITROPOS_SENTINEL_RULE", ev.rule_id),
        ("EPITROPOS_SENTINEL_SEVERITY", ev.severity),
        ("EPITROPOS_SENTINEL_CATEGORY", ev.category),
        ("EPITROPOS_SENTINEL_SESSION", ev.session_id),
        ("EPITROPOS_SENTINEL_PART", &part_s),
        ("EPITROPOS_SENTINEL_USER", ev.user),
        ("EPITROPOS_SENTINEL_HOST", ev.host),
        ("EPITROPOS_SENTINEL_T", &t_s),
        ("EPITROPOS_SENTINEL_MATCH", ev.matched_text),
    ];

    let mut payload = String::new();
    for (k, v) in fields {
        payload.push_str(k);
        payload.push('=');
        payload.push_str(v);
        payload.push('\n');
    }

    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };
    let _ = sock.send_to(payload.as_bytes(), JOURNAL_SOCKET);
}
