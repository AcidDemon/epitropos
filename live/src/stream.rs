use std::io::{Read, Write as IoWrite};
use std::path::Path;

pub struct StreamResult {
    pub records_played: u64,
}

/// Tail an encrypted live mirror. The file is a stream of `[u32 LE len][age
/// blob]` frames, one age blob per kgv1 record, encrypted to the operator
/// recipient. Each frame is decrypted with `identity` as it arrives and played.
pub fn stream_session(
    path: &Path,
    sink: &mut dyn IoWrite,
    ctrl_c: &std::sync::atomic::AtomicBool,
    identity: &age::x25519::Identity,
) -> Result<StreamResult, String> {
    use inotify::{Inotify, WatchMask};
    use std::sync::atomic::Ordering;

    let mut inotify = Inotify::init().map_err(|e| format!("inotify_init: {e}"))?;
    inotify
        .watches()
        .add(path, WatchMask::MODIFY | WatchMask::DELETE_SELF)
        .map_err(|e| format!("inotify watch: {e}"))?;

    let mut file = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut carry: Vec<u8> = Vec::new();
    let mut records_played: u64 = 0;
    let mut event_buf = [0u8; 4096];

    read_available(&mut file, &mut carry);
    records_played += drain_frames(&mut carry, identity, sink);

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

        read_available(&mut file, &mut carry);
        records_played += drain_frames(&mut carry, identity, sink);

        if deleted {
            break;
        }
    }

    Ok(StreamResult { records_played })
}

/// Read all bytes currently available from `file` (from its current offset to
/// EOF) and append them to `carry`. On the next MODIFY the file has grown and
/// reading resumes from where it stopped.
fn read_available(file: &mut std::fs::File, carry: &mut Vec<u8>) {
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => carry.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
}

/// Extract every COMPLETE `[u32 len][age blob]` frame from `carry`, decrypt each
/// with `identity`, and play the resulting record. A trailing partial frame is
/// retained in `carry` for the next read. Returns the number of records played.
fn drain_frames(
    carry: &mut Vec<u8>,
    identity: &age::x25519::Identity,
    sink: &mut dyn IoWrite,
) -> u64 {
    let mut played = 0u64;
    let mut off = 0usize;
    loop {
        if carry.len() - off < 4 {
            break;
        }
        let len = u32::from_le_bytes(carry[off..off + 4].try_into().unwrap()) as usize;
        if carry.len() - off - 4 < len {
            break; // blob not fully arrived yet
        }
        let blob = &carry[off + 4..off + 4 + len];
        if let Some(plain) = decrypt_blob(blob, identity)
            && let Ok(line) = std::str::from_utf8(&plain)
            && play_record(line.trim(), sink).is_some()
        {
            played += 1;
        }
        off += 4 + len;
    }
    carry.drain(0..off);
    played
}

fn decrypt_blob(blob: &[u8], identity: &age::x25519::Identity) -> Option<Vec<u8>> {
    let dec = age::Decryptor::new(std::io::Cursor::new(blob)).ok()?;
    let mut r = dec
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .ok()?;
    let mut plain = Vec::new();
    r.read_to_end(&mut plain).ok()?;
    Some(plain)
}

/// Read and decrypt just the first frame of a mirror file — the header record,
/// which the proxy writes first. Used by `list` to show session metadata
/// without streaming the whole session.
pub(crate) fn decrypt_first_frame(
    path: &Path,
    identity: &age::x25519::Identity,
) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf).ok()?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut blob = vec![0u8; len];
    file.read_exact(&mut blob).ok()?;
    decrypt_blob(&blob, identity)
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

    /// Encrypt one record to `[u32 len][age blob]`, mirroring the proxy's
    /// LiveMirror framing (`recipient_str` = an `age1...` public key).
    fn frame_record(rec: &[u8], recipient_str: &str) -> Vec<u8> {
        let recipient: age::x25519::Recipient = recipient_str.parse().unwrap();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .unwrap();
        let mut blob = Vec::new();
        let mut w = encryptor.wrap_output(&mut blob).unwrap();
        IoWrite::write_all(&mut w, rec).unwrap();
        w.finish().unwrap();
        let mut frame = (blob.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&blob);
        frame
    }

    #[test]
    fn drain_frames_decrypts_and_plays_out_records() {
        let identity = age::x25519::Identity::generate();
        let recip = identity.to_public().to_string();
        let mut carry = Vec::new();
        carry.extend(frame_record(
            br#"{"kind":"out","t":0.1,"b":"aGk="}"#,
            &recip,
        ));
        carry.extend(frame_record(br#"{"kind":"in","t":0.2,"b":"eA=="}"#, &recip)); // ignored
        carry.extend(frame_record(
            br#"{"kind":"out","t":0.3,"b":"d29ybGQ="}"#,
            &recip,
        ));
        let mut sink = Vec::new();
        let played = drain_frames(&mut carry, &identity, &mut sink);
        assert_eq!(played, 2, "only the two out records play");
        assert_eq!(sink, b"hiworld");
        assert!(carry.is_empty(), "all complete frames drained");
    }

    #[test]
    fn drain_frames_retains_partial_frame() {
        let identity = age::x25519::Identity::generate();
        let recip = identity.to_public().to_string();
        let full = frame_record(br#"{"kind":"out","t":0.1,"b":"aGk="}"#, &recip);
        let mut carry = full.clone();
        carry.truncate(full.len() - 3); // chop the tail -> incomplete blob
        let mut sink = Vec::new();
        let played = drain_frames(&mut carry, &identity, &mut sink);
        assert_eq!(played, 0, "a partial frame is not played");
        assert_eq!(
            carry.len(),
            full.len() - 3,
            "partial frame retained for later"
        );
    }

    #[test]
    fn stream_reads_existing_and_new_encrypted_data() {
        let identity = age::x25519::Identity::generate();
        let recip = identity.to_public().to_string();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stream-test.age");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            IoWrite::write_all(&mut f, &frame_record(br#"{"kind":"header"}"#, &recip)).unwrap();
            IoWrite::write_all(
                &mut f,
                &frame_record(br#"{"kind":"out","t":0.1,"b":"aGk="}"#, &recip),
            )
            .unwrap();
        }
        let path_clone = path.clone();
        let recip_clone = recip.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path_clone)
                    .unwrap();
                IoWrite::write_all(
                    &mut f,
                    &frame_record(br#"{"kind":"out","t":0.5,"b":"d29ybGQ="}"#, &recip_clone),
                )
                .unwrap();
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            std::fs::remove_file(&path_clone).unwrap();
        });
        let ctrl_c = AtomicBool::new(false);
        let mut sink = Vec::new();
        let result = stream_session(&path, &mut sink, &ctrl_c, &identity).unwrap();
        handle.join().unwrap();
        assert_eq!(result.records_played, 2);
        assert_eq!(String::from_utf8(sink).unwrap(), "hiworld");
    }
}
