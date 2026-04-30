use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::Path;

pub struct StreamResult {
    pub records_played: u64,
}

pub fn stream_session(
    path: &Path,
    sink: &mut dyn IoWrite,
    ctrl_c: &std::sync::atomic::AtomicBool,
) -> Result<StreamResult, String> {
    use inotify::{Inotify, WatchMask};
    use std::sync::atomic::Ordering;

    let mut inotify = Inotify::init().map_err(|e| format!("inotify_init: {e}"))?;
    inotify
        .watches()
        .add(path, WatchMask::MODIFY | WatchMask::DELETE_SELF)
        .map_err(|e| format!("inotify watch: {e}"))?;

    let file = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut reader = BufReader::new(file);
    let mut line_buf = String::new();
    let mut records_played: u64 = 0;
    let mut event_buf = [0u8; 4096];

    loop {
        line_buf.clear();
        let n = reader
            .read_line(&mut line_buf)
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        if play_record(line_buf.trim(), sink).is_some() {
            records_played += 1;
        }
    }

    loop {
        if ctrl_c.load(Ordering::Relaxed) {
            break;
        }

        let mut deleted = false;

        match inotify.read_events(&mut event_buf) {
            Ok(events) => {
                for event in events {
                    if event.mask.contains(inotify::EventMask::DELETE_SELF) {
                        deleted = true;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !path.exists() {
                    deleted = true;
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            Err(e) => return Err(format!("inotify read: {e}")),
        }

        loop {
            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            if play_record(line_buf.trim(), sink).is_some() {
                records_played += 1;
            }
        }

        if deleted {
            break;
        }
    }

    Ok(StreamResult { records_played })
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("base64: {e}"))
}

fn play_record(line: &str, sink: &mut dyn IoWrite) -> Option<()> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v["kind"].as_str() != Some("out") {
        return None;
    }
    let b64 = v["b"].as_str()?;
    let bytes = decode_base64(b64).ok()?;
    sink.write_all(&bytes).ok()?;
    let _ = sink.flush();
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn play_record_writes_out_data() {
        let line = r#"{"kind":"out","t":0.1,"b":"aGVsbG8="}"#;
        let mut buf = Vec::new();
        play_record(line, &mut buf).unwrap();
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn play_record_ignores_non_out_kinds() {
        let line =
            r#"{"kind":"chunk","seq":0,"bytes":100,"messages":5,"elapsed":1.0,"sha256":"abc"}"#;
        let mut buf = Vec::new();
        let result = play_record(line, &mut buf);
        assert!(result.is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn play_record_ignores_header() {
        let line = r#"{"kind":"header","v":"katagrapho-v1","session_id":"s","user":"u","host":"h","boot_id":"b","part":0,"prev_manifest_hash_link":null,"started":1.0,"cols":80,"rows":24,"shell":"/bin/sh","epitropos_version":"0","epitropos_commit":"0","katagrapho_version":"0","katagrapho_commit":"0","audit_session_id":null,"ppid":1,"ssh_client":null,"ssh_connection":null,"ssh_original_command":null,"parent_comm":null,"parent_cmdline":null,"pam_rhost":null,"pam_service":null}"#;
        let mut buf = Vec::new();
        assert!(play_record(line, &mut buf).is_none());
    }

    #[test]
    fn play_record_ignores_in_records() {
        let line = r#"{"kind":"in","t":0.5,"b":"eA=="}"#;
        let mut buf = Vec::new();
        assert!(play_record(line, &mut buf).is_none());
    }

    #[test]
    fn stream_reads_existing_and_new_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stream-test.kgv1");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, r#"{{"kind":"header","v":"katagrapho-v1","session_id":"s","user":"u","host":"h","boot_id":"b","part":0,"prev_manifest_hash_link":null,"started":1.0,"cols":80,"rows":24,"shell":"/bin/sh","epitropos_version":"0","epitropos_commit":"0","katagrapho_version":"0","katagrapho_commit":"0","audit_session_id":null,"ppid":1,"ssh_client":null,"ssh_connection":null,"ssh_original_command":null,"parent_comm":null,"parent_cmdline":null,"pam_rhost":null,"pam_service":null}}"#).unwrap();
            writeln!(f, r#"{{"kind":"out","t":0.1,"b":"aGk="}}"#).unwrap();
        }
        let path_clone = path.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path_clone)
                    .unwrap();
                writeln!(f, r#"{{"kind":"out","t":0.5,"b":"d29ybGQ="}}"#).unwrap();
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            std::fs::remove_file(&path_clone).unwrap();
        });
        let ctrl_c = AtomicBool::new(false);
        let mut sink = Vec::new();
        let result = stream_session(&path, &mut sink, &ctrl_c).unwrap();
        handle.join().unwrap();
        assert_eq!(result.records_played, 2);
        assert_eq!(String::from_utf8(sink).unwrap(), "hiworld");
    }
}
