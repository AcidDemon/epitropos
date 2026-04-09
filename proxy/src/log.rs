use serde_json::json;

pub fn session_start(session_id: &str, username: &str) {
    emit(&json!({
        "event": "session_start",
        "session_id": session_id,
        "username": username,
        "timestamp": timestamp_now(),
    }));
}

pub fn session_end(session_id: &str, username: &str, elapsed_secs: f64, exit_code: i32) {
    emit(&json!({
        "event": "session_end",
        "session_id": session_id,
        "username": username,
        "elapsed_seconds": elapsed_secs,
        "exit_code": exit_code,
        "timestamp": timestamp_now(),
    }));
}

pub fn recording_interrupted(session_id: &str, username: &str, reason: &str, elapsed_secs: f64) {
    emit(&json!({
        "event": "recording_interrupted",
        "session_id": session_id,
        "username": username,
        "reason": reason,
        "elapsed_seconds": elapsed_secs,
        "timestamp": timestamp_now(),
    }));
}

pub fn nesting_skip(session_id: &str, username: &str, reason: &str) {
    emit(&json!({
        "event": "nesting_skip",
        "session_id": session_id,
        "username": username,
        "reason": reason,
        "timestamp": timestamp_now(),
    }));
}

fn emit(v: &serde_json::Value) {
    if let Ok(s) = serde_json::to_string(v) {
        eprintln!("{s}");
    }
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
