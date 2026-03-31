/// Structured JSON logging for audit events.
/// Writes to stderr where journald can pick it up.

pub fn session_start(session_id: &str, username: &str) {
    let timestamp = timestamp_now();
    eprintln!(
        "{{\"event\":\"session_start\",\"session_id\":\"{session_id}\",\"username\":\"{username}\",\"timestamp\":\"{timestamp}\"}}"
    );
}

pub fn session_end(session_id: &str, username: &str, elapsed_secs: f64, exit_code: i32) {
    let timestamp = timestamp_now();
    eprintln!(
        "{{\"event\":\"session_end\",\"session_id\":\"{session_id}\",\"username\":\"{username}\",\"elapsed_seconds\":{elapsed_secs:.1},\"exit_code\":{exit_code},\"timestamp\":\"{timestamp}\"}}"
    );
}

pub fn recording_interrupted(session_id: &str, username: &str, reason: &str, elapsed_secs: f64) {
    let timestamp = timestamp_now();
    eprintln!(
        "{{\"event\":\"recording_interrupted\",\"session_id\":\"{session_id}\",\"username\":\"{username}\",\"reason\":\"{reason}\",\"elapsed_seconds\":{elapsed_secs:.1},\"timestamp\":\"{timestamp}\"}}"
    );
}

pub fn nesting_skip(session_id: &str, username: &str, pam_service: &str) {
    let timestamp = timestamp_now();
    eprintln!(
        "{{\"event\":\"nesting_skip\",\"session_id\":\"{session_id}\",\"username\":\"{username}\",\"pam_service\":\"{pam_service}\",\"timestamp\":\"{timestamp}\"}}"
    );
}

fn timestamp_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}
