use std::io::BufRead;
use std::path::{Path, PathBuf};

pub struct SessionInfo {
    pub session_id: String,
    pub user: String,
    pub host: String,
    pub started: f64,
    pub cols: u64,
    pub rows: u64,
    #[allow(dead_code)]
    pub path: PathBuf,
}

pub fn list_sessions(live_dir: &Path) -> Vec<SessionInfo> {
    let entries = match std::fs::read_dir(live_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("kgv1") {
            continue;
        }
        if let Some(info) = parse_header(&path) {
            sessions.push(info);
        }
    }
    sessions.sort_by(|a, b| {
        a.started
            .partial_cmp(&b.started)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sessions
}

fn parse_header(path: &Path) -> Option<SessionInfo> {
    let file = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(file);
    let first_line = reader.lines().next()?.ok()?;
    let v: serde_json::Value = serde_json::from_str(&first_line).ok()?;
    if v["kind"].as_str() != Some("header") {
        return None;
    }
    if v["v"].as_str() != Some("katagrapho-v1") {
        return None;
    }
    Some(SessionInfo {
        session_id: v["session_id"].as_str()?.to_string(),
        user: v["user"].as_str()?.to_string(),
        host: v["host"].as_str().unwrap_or("?").to_string(),
        started: v["started"].as_f64()?,
        cols: v["cols"].as_u64().unwrap_or(80),
        rows: v["rows"].as_u64().unwrap_or(24),
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_session(dir: &Path, session_id: &str, user: &str) -> PathBuf {
        let path = dir.join(format!("{session_id}.kgv1"));
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"{{"kind":"header","v":"katagrapho-v1","session_id":"{session_id}","user":"{user}","host":"testhost","boot_id":"b","part":0,"prev_manifest_hash_link":null,"started":1700000000.0,"cols":80,"rows":24,"shell":"/bin/bash","epitropos_version":"0.1.0","epitropos_commit":"abc","katagrapho_version":"0","katagrapho_commit":"0","audit_session_id":null,"ppid":1,"ssh_client":null,"ssh_connection":null,"ssh_original_command":null,"parent_comm":null,"parent_cmdline":null,"pam_rhost":null,"pam_service":null}}"#
        )
        .unwrap();
        writeln!(f, r#"{{"kind":"out","t":0.1,"b":"aGk="}}"#).unwrap();
        path
    }

    #[test]
    fn list_finds_sessions_in_directory() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "sess-aaa", "alice");
        write_session(dir.path(), "sess-bbb", "bob");
        let sessions = list_sessions(dir.path());
        assert_eq!(sessions.len(), 2);
        let users: Vec<&str> = sessions.iter().map(|s| s.user.as_str()).collect();
        assert!(users.contains(&"alice"));
        assert!(users.contains(&"bob"));
    }

    #[test]
    fn list_skips_non_kgv1_files() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "sess-ccc", "carol");
        std::fs::write(dir.path().join("junk.txt"), "not a session").unwrap();
        let sessions = list_sessions(dir.path());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "sess-ccc");
    }

    #[test]
    fn list_returns_empty_for_missing_dir() {
        let sessions = list_sessions(Path::new("/nonexistent/dir"));
        assert!(sessions.is_empty());
    }

    #[test]
    fn parse_header_extracts_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_session(dir.path(), "sess-ddd", "dave");
        let info = parse_header(&path).unwrap();
        assert_eq!(info.session_id, "sess-ddd");
        assert_eq!(info.user, "dave");
        assert_eq!(info.host, "testhost");
        assert_eq!(info.cols, 80);
        assert_eq!(info.rows, 24);
        assert!(info.started > 0.0);
    }
}
