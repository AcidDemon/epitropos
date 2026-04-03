use std::io::Write;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

/// Session metadata embedded in the asciicinema header.
pub struct Metadata {
    pub hostname: String,
    pub boot_id: String,
    pub audit_session_id: Option<u32>,
    pub recording_id: String,
}

pub struct Recorder {
    start: Instant,
}

impl Recorder {
    pub fn new() -> Self {
        Recorder {
            start: Instant::now(),
        }
    }

    pub fn write_header(
        &self,
        w: &mut dyn Write,
        width: u16,
        height: u16,
        shell: &str,
        term: &str,
        meta: &Metadata,
    ) -> Result<(), String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();

        let mut header = json!({
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": timestamp,
            "env": {
                "SHELL": shell,
                "TERM": term,
            },
            "epitropos": {
                "host": meta.hostname,
                "boot_id": meta.boot_id,
                "rec": meta.recording_id,
            }
        });

        if let Some(asid) = meta.audit_session_id {
            header["epitropos"]["audit_session"] = json!(asid);
        }

        let line =
            serde_json::to_string(&header).map_err(|e| format!("JSON serialization error: {e}"))?;
        writeln!(w, "{line}").map_err(|e| format!("write error: {e}"))
    }

    pub fn write_output(&self, w: &mut dyn Write, data: &[u8]) -> Result<(), String> {
        self.write_data_event(w, "o", data)
    }

    pub fn write_input(&self, w: &mut dyn Write, data: &[u8]) -> Result<(), String> {
        self.write_data_event(w, "i", data)
    }

    pub fn write_resize(&self, w: &mut dyn Write, width: u16, height: u16) -> Result<(), String> {
        let elapsed = self.start.elapsed().as_secs_f64();
        let line = serde_json::to_string(&json!([elapsed, "r", format!("{width}x{height}")]))
            .map_err(|e| format!("JSON serialization error: {e}"))?;
        writeln!(w, "{line}").map_err(|e| format!("write error: {e}"))
    }

    /// Write a data event with lossless UTF-8 handling.
    /// Valid UTF-8 goes in the data field. If invalid bytes are present,
    /// they are base64-encoded in an extra 4th element.
    fn write_data_event(
        &self,
        w: &mut dyn Write,
        event_type: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let elapsed = self.start.elapsed().as_secs_f64();

        let event = match std::str::from_utf8(data) {
            Ok(valid) => json!([elapsed, event_type, valid]),
            Err(_) => {
                // Split: lossy text for display, raw base64 for fidelity.
                let text = String::from_utf8_lossy(data);
                use base64::Engine;
                let bin = base64::engine::general_purpose::STANDARD.encode(data);
                json!([elapsed, event_type, text, bin])
            }
        };

        let line =
            serde_json::to_string(&event).map_err(|e| format!("JSON serialization error: {e}"))?;
        writeln!(w, "{line}").map_err(|e| format!("write error: {e}"))
    }
}

/// Read hostname from /proc/sys/kernel/hostname.
pub fn get_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

/// Read boot_id from /proc/sys/kernel/random/boot_id.
pub fn get_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn test_meta() -> Metadata {
        Metadata {
            hostname: "testhost".to_string(),
            boot_id: "abc-123".to_string(),
            audit_session_id: Some(42),
            recording_id: "rec-001".to_string(),
        }
    }

    fn capture(f: impl FnOnce(&Recorder, &mut Vec<u8>) -> Result<(), String>) -> String {
        let recorder = Recorder::new();
        let mut buf: Vec<u8> = Vec::new();
        f(&recorder, &mut buf).expect("write failed");
        String::from_utf8(buf).expect("output is not valid UTF-8")
    }

    #[test]
    fn header_contains_metadata() {
        let output =
            capture(|r, w| r.write_header(w, 80, 24, "/bin/bash", "xterm-256color", &test_meta()));

        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        assert_eq!(v["version"], 2);
        assert_eq!(v["width"], 80);
        assert_eq!(v["height"], 24);
        assert_eq!(v["env"]["SHELL"], "/bin/bash");
        assert_eq!(v["epitropos"]["host"], "testhost");
        assert_eq!(v["epitropos"]["boot_id"], "abc-123");
        assert_eq!(v["epitropos"]["audit_session"], 42);
        assert_eq!(v["epitropos"]["rec"], "rec-001");
    }

    #[test]
    fn header_without_audit_session() {
        let meta = Metadata {
            audit_session_id: None,
            ..test_meta()
        };
        let output = capture(|r, w| r.write_header(w, 80, 24, "/bin/bash", "xterm", &meta));
        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        assert!(v["epitropos"]["audit_session"].is_null());
    }

    #[test]
    fn output_event_format() {
        let output = capture(|r, w| r.write_output(w, b"hello"));
        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr[0].is_number());
        assert_eq!(arr[1], "o");
        assert_eq!(arr[2], "hello");
    }

    #[test]
    fn input_event_format() {
        let output = capture(|r, w| r.write_input(w, b"world"));
        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        assert_eq!(v[1], "i");
        assert_eq!(v[2], "world");
    }

    #[test]
    fn resize_event_format() {
        let output = capture(|r, w| r.write_resize(w, 120, 40));
        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        assert_eq!(v[1], "r");
        assert_eq!(v[2], "120x40");
    }

    #[test]
    fn valid_utf8_has_no_binary_field() {
        let output = capture(|r, w| r.write_output(w, b"hello"));
        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        assert_eq!(
            v.as_array().unwrap().len(),
            3,
            "valid UTF-8 should have 3 fields"
        );
    }

    #[test]
    fn invalid_utf8_has_binary_field() {
        let output = capture(|r, w| r.write_output(w, &[0xFF, 0xFE, b'h', b'i']));
        let v: serde_json::Value = serde_json::from_str(output.trim_end()).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(
            arr.len(),
            4,
            "invalid UTF-8 should have 4 fields (with base64)"
        );
        assert_eq!(arr[1], "o");
        assert!(arr[3].is_string(), "4th field must be base64 string");
    }

    #[test]
    fn timestamps_are_monotonic() {
        let recorder = Recorder::new();
        let mut buf1: Vec<u8> = Vec::new();
        let mut buf2: Vec<u8> = Vec::new();

        recorder.write_output(&mut buf1, b"first").unwrap();
        thread::sleep(Duration::from_millis(10));
        recorder.write_output(&mut buf2, b"second").unwrap();

        let v1: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf1).unwrap().trim_end()).unwrap();
        let v2: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf2).unwrap().trim_end()).unwrap();

        let t1 = v1[0].as_f64().unwrap();
        let t2 = v2[0].as_f64().unwrap();
        assert!(t2 >= t1);
    }
}
