use std::io::Write;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
    ) -> Result<(), String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();

        let header = serde_json::json!({
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": timestamp,
            "env": {
                "SHELL": shell,
                "TERM": term,
            }
        });

        let line = serde_json::to_string(&header)
            .map_err(|e| format!("JSON serialization error: {e}"))?;

        writeln!(w, "{line}").map_err(|e| format!("write error: {e}"))
    }

    pub fn write_output(&self, w: &mut dyn Write, data: &[u8]) -> Result<(), String> {
        let s = String::from_utf8_lossy(data).into_owned();
        self.write_event(w, "o", &s)
    }

    pub fn write_input(&self, w: &mut dyn Write, data: &[u8]) -> Result<(), String> {
        let s = String::from_utf8_lossy(data).into_owned();
        self.write_event(w, "i", &s)
    }

    pub fn write_resize(&self, w: &mut dyn Write, width: u16, height: u16) -> Result<(), String> {
        let s = format!("{width}x{height}");
        self.write_event(w, "r", &s)
    }

    fn write_event(&self, w: &mut dyn Write, event_type: &str, data: &str) -> Result<(), String> {
        let elapsed = self.start.elapsed().as_secs_f64();

        let event = serde_json::json!([elapsed, event_type, data]);

        let line = serde_json::to_string(&event)
            .map_err(|e| format!("JSON serialization error: {e}"))?;

        writeln!(w, "{line}").map_err(|e| format!("write error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn capture(f: impl FnOnce(&Recorder, &mut Vec<u8>) -> Result<(), String>) -> String {
        let recorder = Recorder::new();
        let mut buf: Vec<u8> = Vec::new();
        f(&recorder, &mut buf).expect("write failed");
        String::from_utf8(buf).expect("output is not valid UTF-8")
    }

    #[test]
    fn header_is_valid_json() {
        let output = capture(|r, w| r.write_header(w, 80, 24, "/bin/bash", "xterm-256color"));

        let v: serde_json::Value =
            serde_json::from_str(output.trim_end()).expect("header must be valid JSON");

        assert_eq!(v["version"], 2);
        assert_eq!(v["width"], 80);
        assert_eq!(v["height"], 24);
        assert!(v["timestamp"].is_number(), "timestamp must be a number");
        assert_eq!(v["env"]["SHELL"], "/bin/bash");
        assert_eq!(v["env"]["TERM"], "xterm-256color");
    }

    #[test]
    fn output_event_format() {
        let output = capture(|r, w| r.write_output(w, b"hello"));

        let v: serde_json::Value =
            serde_json::from_str(output.trim_end()).expect("event must be valid JSON");

        assert!(v.is_array());
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr[0].is_number(), "first element must be elapsed time");
        assert_eq!(arr[1], "o");
        assert_eq!(arr[2], "hello");
    }

    #[test]
    fn input_event_format() {
        let output = capture(|r, w| r.write_input(w, b"world"));

        let v: serde_json::Value =
            serde_json::from_str(output.trim_end()).expect("event must be valid JSON");

        assert!(v.is_array());
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr[0].is_number(), "first element must be elapsed time");
        assert_eq!(arr[1], "i");
        assert_eq!(arr[2], "world");
    }

    #[test]
    fn resize_event_format() {
        let output = capture(|r, w| r.write_resize(w, 120, 40));

        let v: serde_json::Value =
            serde_json::from_str(output.trim_end()).expect("event must be valid JSON");

        assert!(v.is_array());
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr[0].is_number(), "first element must be elapsed time");
        assert_eq!(arr[1], "r");
        assert_eq!(arr[2], "120x40");
    }

    #[test]
    fn handles_non_utf8_data() {
        // 0xFF 0xFE are invalid UTF-8 bytes — must not panic
        let invalid_bytes: &[u8] = &[0xFF, 0xFE, b'h', b'i'];
        let result = capture(|r, w| r.write_output(w, invalid_bytes));
        // just verify it parsed as valid JSON without panicking
        let v: serde_json::Value =
            serde_json::from_str(result.trim_end()).expect("event must be valid JSON");
        assert_eq!(v[1], "o");
    }

    #[test]
    fn timestamps_are_monotonic() {
        let recorder = Recorder::new();
        let mut buf1: Vec<u8> = Vec::new();
        let mut buf2: Vec<u8> = Vec::new();

        recorder.write_output(&mut buf1, b"first").expect("write failed");
        thread::sleep(Duration::from_millis(10));
        recorder.write_output(&mut buf2, b"second").expect("write failed");

        let v1: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf1).unwrap().trim_end()).unwrap();
        let v2: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf2).unwrap().trim_end()).unwrap();

        let t1 = v1[0].as_f64().expect("t1 must be a number");
        let t2 = v2[0].as_f64().expect("t2 must be a number");

        assert!(t2 >= t1, "second timestamp ({t2}) must be >= first ({t1})");
    }
}
