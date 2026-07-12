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

pub fn list_sessions(live_dir: &Path, identity: &age::x25519::Identity) -> Vec<SessionInfo> {
    let entries = match std::fs::read_dir(live_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("age") {
            continue;
        }
        if let Some(info) = parse_header(&path, identity) {
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

fn parse_header(path: &Path, identity: &age::x25519::Identity) -> Option<SessionInfo> {
    // The header is the first encrypted frame; decrypt just that.
    let plain = crate::stream::decrypt_first_frame(path, identity)?;
    let line = std::str::from_utf8(&plain).ok()?;
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
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

    fn frame(rec: &[u8], recipient: &age::x25519::Recipient) -> Vec<u8> {
        let enc =
            age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
                .unwrap();
        let mut blob = Vec::new();
        let mut w = enc.wrap_output(&mut blob).unwrap();
        w.write_all(rec).unwrap();
        w.finish().unwrap();
        let mut f = (blob.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(&blob);
        f
    }

    fn write_session(
        dir: &Path,
        session_id: &str,
        user: &str,
        recipient: &age::x25519::Recipient,
    ) -> PathBuf {
        let path = dir.join(format!("{session_id}.age"));
        let header = format!(
            r#"{{"kind":"header","v":"katagrapho-v1","session_id":"{session_id}","user":"{user}","host":"testhost","started":1700000000.0,"cols":80,"rows":24}}"#
        );
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&frame(header.as_bytes(), recipient)).unwrap();
        f.write_all(&frame(br#"{"kind":"out","t":0.1,"b":"aGk="}"#, recipient))
            .unwrap();
        path
    }

    #[test]
    fn list_finds_sessions_in_directory() {
        let id = age::x25519::Identity::generate();
        let recip = id.to_public();
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "sess-aaa", "alice", &recip);
        write_session(dir.path(), "sess-bbb", "bob", &recip);
        let sessions = list_sessions(dir.path(), &id);
        assert_eq!(sessions.len(), 2);
        let users: Vec<&str> = sessions.iter().map(|s| s.user.as_str()).collect();
        assert!(users.contains(&"alice"));
        assert!(users.contains(&"bob"));
    }

    #[test]
    fn list_skips_non_age_files() {
        let id = age::x25519::Identity::generate();
        let recip = id.to_public();
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "sess-ccc", "carol", &recip);
        std::fs::write(dir.path().join("junk.txt"), "not a session").unwrap();
        let sessions = list_sessions(dir.path(), &id);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "sess-ccc");
    }

    #[test]
    fn list_returns_empty_for_missing_dir() {
        let id = age::x25519::Identity::generate();
        let sessions = list_sessions(Path::new("/nonexistent/dir"), &id);
        assert!(sessions.is_empty());
    }

    #[test]
    fn parse_header_extracts_metadata() {
        let id = age::x25519::Identity::generate();
        let recip = id.to_public();
        let dir = tempfile::tempdir().unwrap();
        let path = write_session(dir.path(), "sess-ddd", "dave", &recip);
        let info = parse_header(&path, &id).unwrap();
        assert_eq!(info.session_id, "sess-ddd");
        assert_eq!(info.user, "dave");
        assert_eq!(info.host, "testhost");
        assert_eq!(info.cols, 80);
        assert_eq!(info.rows, 24);
        assert!(info.started > 0.0);
    }

    #[test]
    fn parse_header_fails_with_wrong_identity() {
        let id = age::x25519::Identity::generate();
        let recip = id.to_public();
        let wrong = age::x25519::Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        let path = write_session(dir.path(), "s", "u", &recip);
        assert!(
            parse_header(&path, &wrong).is_none(),
            "a wrong identity must not decrypt session metadata"
        );
    }
}
