//! Structured journald entries for session start/end events.
//!
//! Sends native journal protocol datagrams to /run/systemd/journal/socket
//! with EPITROPOS_* fields for SIEM ingestion. No external crate needed.

use std::os::unix::net::UnixDatagram;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

fn send_journal_fields(fields: &[(&str, &str)]) {
    let mut payload = String::new();
    for (key, value) in fields {
        payload.push_str(key);
        payload.push('=');
        payload.push_str(value);
        payload.push('\n');
    }

    let Ok(sock) = UnixDatagram::unbound() else {
        return;
    };
    // Best-effort: if the socket isn't available, silently skip.
    let _ = sock.send_to(payload.as_bytes(), JOURNAL_SOCKET);
}

pub fn session_start(
    session_id: &str,
    user: &str,
    host: &str,
    ssh_client: &str,
    audit_session_id: Option<u32>,
) {
    let msg = format!("session started: user={user} host={host}");
    let asid = audit_session_id
        .map(|id| id.to_string())
        .unwrap_or_default();

    let mut fields: Vec<(&str, &str)> = vec![
        ("MESSAGE", &msg),
        ("PRIORITY", "6"),
        ("SYSLOG_IDENTIFIER", "epitropos"),
        ("EPITROPOS_EVENT", "session_start"),
        ("EPITROPOS_SESSION_ID", session_id),
        ("EPITROPOS_USER", user),
        ("EPITROPOS_HOST", host),
    ];

    if !ssh_client.is_empty() {
        fields.push(("EPITROPOS_SSH_CLIENT", ssh_client));
    }
    if !asid.is_empty() {
        fields.push(("EPITROPOS_AUDIT_SESSION", &asid));
    }

    send_journal_fields(&fields);
}

pub fn session_end(
    session_id: &str,
    user: &str,
    host: &str,
    duration_secs: f64,
    exit_code: i32,
    end_reason: &str,
    total_bytes: u64,
) {
    let dur_display = if duration_secs < 60.0 {
        format!("{}s", duration_secs as u64)
    } else if duration_secs < 3600.0 {
        format!("{}m{}s", duration_secs as u64 / 60, duration_secs as u64 % 60)
    } else {
        let h = duration_secs as u64 / 3600;
        let m = (duration_secs as u64 % 3600) / 60;
        format!("{h}h{m}m")
    };

    let msg = format!(
        "session ended: user={user} duration={dur_display} exit_code={exit_code} reason={end_reason}"
    );
    let dur_str = (duration_secs as u64).to_string();
    let exit_str = exit_code.to_string();
    let bytes_str = total_bytes.to_string();

    let fields: Vec<(&str, &str)> = vec![
        ("MESSAGE", &msg),
        ("PRIORITY", "6"),
        ("SYSLOG_IDENTIFIER", "epitropos"),
        ("EPITROPOS_EVENT", "session_end"),
        ("EPITROPOS_SESSION_ID", session_id),
        ("EPITROPOS_USER", user),
        ("EPITROPOS_HOST", host),
        ("EPITROPOS_DURATION", &dur_str),
        ("EPITROPOS_EXIT_CODE", &exit_str),
        ("EPITROPOS_END_REASON", end_reason),
        ("EPITROPOS_BYTES", &bytes_str),
    ];

    send_journal_fields(&fields);
}
