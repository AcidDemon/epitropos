// Human-facing session event lines, printed to the proxy's stderr (the user's
// terminal). The machine-readable copy of these events goes to the journal
// (see journal.rs); this module is purely the interactive presentation, so it
// is free to be pretty. Rendered as a dim tree block with bold keys.

pub fn session_start(session_id: &str, username: &str) {
    emit_block(
        "session recording started",
        &[
            ("user", username.to_string()),
            ("session", session_id.to_string()),
            ("started", fmt_utc(timestamp_now())),
        ],
    );
}

pub fn session_end(session_id: &str, username: &str, elapsed_secs: f64, exit_code: i32) {
    emit_block(
        "session recording ended",
        &[
            ("user", username.to_string()),
            ("session", session_id.to_string()),
            ("elapsed", format!("{elapsed_secs:.2}s")),
            ("exit", exit_code.to_string()),
            ("ended", fmt_utc(timestamp_now())),
        ],
    );
}

pub fn recording_interrupted(session_id: &str, username: &str, reason: &str, elapsed_secs: f64) {
    emit_block(
        "recording interrupted",
        &[
            ("user", username.to_string()),
            ("session", session_id.to_string()),
            ("reason", reason.to_string()),
            ("elapsed", format!("{elapsed_secs:.2}s")),
            ("at", fmt_utc(timestamp_now())),
        ],
    );
}

pub fn nesting_skip(session_id: &str, username: &str, reason: &str) {
    emit_block(
        "nested session (not re-recorded)",
        &[
            ("user", username.to_string()),
            ("session", session_id.to_string()),
            ("reason", reason.to_string()),
        ],
    );
}

pub fn live_mirror_started(session_id: &str, path: impl std::fmt::Display) {
    emit_block(
        "live mirror started",
        &[
            ("session", session_id.to_string()),
            ("path", path.to_string()),
        ],
    );
}

const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Render a dim tree block: a title line, then one `key  value` row per pair
/// with bold keys and box-drawing connectors. Keys are padded to align values.
fn emit_block(title: &str, pairs: &[(&str, String)]) {
    let key_w = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = format!("{DIM}epitropos ▸ {title}{RESET}\n");
    for (i, (k, v)) in pairs.iter().enumerate() {
        let conn = if i + 1 == pairs.len() { "└─" } else { "├─" };
        out.push_str(&format!(
            "{DIM}  {conn} {RESET}{BOLD}{k:<key_w$}{RESET}{DIM}  {v}{RESET}\n"
        ));
    }
    eprint!("{out}");
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS UTC" without pulling in a
/// date crate. Howard Hinnant's days-from-civil algorithm.
fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn days_to_ymd(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_utc_known_epoch() {
        // 1788813438 = 2026-09-07 20:37:18 UTC
        assert_eq!(fmt_utc(1788813438), "2026-09-07 20:37:18 UTC");
        // epoch
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
    }
}
