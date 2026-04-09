//! Recording writer. The module is named `asciicinema` for historical
//! reasons (it used to emit asciicast v2). It now emits the
//! `katagrapho-v1` JSONL format defined in
//! `docs/superpowers/specs/2026-04-07-track-b-manifest-chain-and-format.md`.
//!
//! API surface (preserved from the v2 era):
//! - `Recorder::new(meta)` — construct with session metadata
//! - `write_header(w, cols, rows, shell, term)` — write header to `w`,
//!   update the internal ChunkTracker, return the bytes for mirroring
//! - `write_output(w, data)` / `write_input(w, data)` — PTY event records
//! - `write_resize(w, cols, rows)` — resize event
//! - `elapsed_secs()` — seconds since the recorder was created
//! - `write_raw(w, bytes)` — mirror already-serialized bytes to another
//!   writer without touching the chunk tracker
//! - `maybe_flush_chunk(w)` — emit a chunk record to `w` if the
//!   ChunkTracker says it's time
//! - `force_flush_chunk(w)` — unconditionally emit a trailing chunk
//!
//! ChunkTracker state lives behind RefCell so `&self` methods can
//! mutate it; the Recorder is not Send across threads, which is fine
//! because the event loop is single-threaded.

use std::cell::RefCell;
use std::io::Write;
use std::time::Instant;

use crate::auth_meta::AuthMeta;
use crate::buffer::ChunkTracker;
use crate::config::Chunk as ChunkCfg;
use crate::kgv1;

pub struct Metadata {
    pub hostname: String,
    pub boot_id: String,
    pub audit_session_id: Option<u32>,
    pub recording_id: String,
    pub user: String,
    pub auth: AuthMeta,
}

pub struct Recorder {
    start: Instant,
    meta: Metadata,
    chunks: RefCell<ChunkTracker>,
    started_unix: f64,
}

impl Recorder {
    pub fn new(meta: Metadata, chunk_cfg: ChunkCfg) -> Self {
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        Recorder {
            start: Instant::now(),
            meta,
            chunks: RefCell::new(ChunkTracker::new(chunk_cfg)),
            started_unix,
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Serialize a header record, write it to `w`, update the chunk
    /// tracker, and return the raw bytes so the caller can mirror
    /// them to side-channel writers via `write_raw`.
    pub fn write_header(
        &self,
        w: &mut dyn Write,
        cols: u16,
        rows: u16,
        shell: &str,
        _term: &str,
    ) -> Result<Vec<u8>, String> {
        let h = kgv1::HeaderFields {
            session_id: &self.meta.recording_id,
            user: &self.meta.user,
            host: &self.meta.hostname,
            boot_id: &self.meta.boot_id,
            part: 0,
            prev_manifest_hash_link: None,
            started_unix: self.started_unix,
            cols,
            rows,
            shell,
            epitropos_version: env!("CARGO_PKG_VERSION"),
            epitropos_commit: env!("EPITROPOS_GIT_COMMIT"),
            katagrapho_version: "track-b",
            katagrapho_commit: "track-b",
            audit_session_id: self.meta.audit_session_id,
            auth: &self.meta.auth,
        };
        let mut bytes = Vec::with_capacity(512);
        kgv1::write_header(&mut bytes, &h).map_err(|e| format!("serialize header: {e}"))?;
        w.write_all(&bytes)
            .map_err(|e| format!("write header: {e}"))?;
        self.chunks.borrow_mut().record(&bytes);
        Ok(bytes)
    }

    /// Write an `out` record to `w` and return the serialized bytes so
    /// the caller can mirror them to side-channel writers via `write_raw`.
    /// The ChunkTracker is updated exactly once.
    pub fn write_output(&self, w: &mut dyn Write, data: &[u8]) -> Result<Vec<u8>, String> {
        let t = self.elapsed_secs();
        let mut bytes = Vec::with_capacity(data.len() + 64);
        kgv1::write_out(&mut bytes, t, data).map_err(|e| format!("serialize out: {e}"))?;
        w.write_all(&bytes).map_err(|e| format!("write out: {e}"))?;
        self.chunks.borrow_mut().record(&bytes);
        Ok(bytes)
    }

    pub fn write_input(&self, w: &mut dyn Write, data: &[u8]) -> Result<Vec<u8>, String> {
        let t = self.elapsed_secs();
        let mut bytes = Vec::with_capacity(data.len() + 64);
        kgv1::write_in(&mut bytes, t, data).map_err(|e| format!("serialize in: {e}"))?;
        w.write_all(&bytes).map_err(|e| format!("write in: {e}"))?;
        self.chunks.borrow_mut().record(&bytes);
        Ok(bytes)
    }

    pub fn write_resize(&self, w: &mut dyn Write, cols: u16, rows: u16) -> Result<Vec<u8>, String> {
        let t = self.elapsed_secs();
        let mut bytes = Vec::with_capacity(64);
        kgv1::write_resize(&mut bytes, t, cols, rows)
            .map_err(|e| format!("serialize resize: {e}"))?;
        w.write_all(&bytes)
            .map_err(|e| format!("write resize: {e}"))?;
        self.chunks.borrow_mut().record(&bytes);
        Ok(bytes)
    }

    /// Mirror already-serialized bytes to a side-channel writer. Does
    /// NOT update the chunk tracker — that state is owned by the
    /// primary writer channel.
    pub fn write_raw(&self, w: &mut dyn Write, bytes: &[u8]) -> Result<(), String> {
        w.write_all(bytes).map_err(|e| format!("write raw: {e}"))
    }

    /// If the ChunkTracker says a boundary has been hit, emit a
    /// `chunk` record into `w` and reset. Called by the event loop
    /// after each primary write.
    pub fn maybe_flush_chunk(&self, w: &mut dyn Write) -> Result<(), String> {
        let should = self.chunks.borrow().should_flush();
        if should {
            self.emit_chunk(w)?;
        }
        Ok(())
    }

    /// Emit a trailing chunk unconditionally if any records have been
    /// written since the last chunk boundary. Called at session end.
    pub fn force_flush_chunk(&self, w: &mut dyn Write) -> Result<(), String> {
        if self.chunks.borrow().message_count() > 0 {
            self.emit_chunk(w)?;
        }
        Ok(())
    }

    fn emit_chunk(&self, w: &mut dyn Write) -> Result<(), String> {
        let summary = self.chunks.borrow_mut().finalize();
        let mut bytes = Vec::with_capacity(256);
        kgv1::write_chunk(
            &mut bytes,
            summary.seq,
            summary.bytes,
            summary.messages,
            summary.elapsed,
            &summary.sha256_hex,
        )
        .map_err(|e| format!("serialize chunk: {e}"))?;
        w.write_all(&bytes)
            .map_err(|e| format!("write chunk: {e}"))?;
        // Chunk records are NOT recorded into the tracker.
        self.chunks.borrow_mut().reset();
        Ok(())
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
    use serde_json::Value;

    fn test_meta() -> Metadata {
        Metadata {
            hostname: "testhost".to_string(),
            boot_id: "abc-123".to_string(),
            audit_session_id: Some(42),
            recording_id: "rec-001".to_string(),
            user: "alice".to_string(),
            auth: AuthMeta::default(),
        }
    }

    fn test_cfg() -> ChunkCfg {
        ChunkCfg {
            max_bytes: usize::MAX,
            max_messages: u64::MAX,
            max_seconds: f64::MAX,
        }
    }

    #[test]
    fn header_is_kgv1_format() {
        let r = Recorder::new(test_meta(), test_cfg());
        let mut buf = Vec::new();
        r.write_header(&mut buf, 80, 24, "/bin/bash", "xterm")
            .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["kind"], "header");
        assert_eq!(v["v"], "katagrapho-v1");
        assert_eq!(v["cols"], 80);
        assert_eq!(v["rows"], 24);
        assert_eq!(v["session_id"], "rec-001");
        assert_eq!(v["user"], "alice");
    }

    #[test]
    fn output_event_is_kgv1_out_with_base64() {
        let r = Recorder::new(test_meta(), test_cfg());
        let mut buf = Vec::new();
        r.write_output(&mut buf, b"hello").unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["kind"], "out");
        assert_eq!(v["b"], "aGVsbG8=");
    }

    #[test]
    fn resize_event_has_cols_rows() {
        let r = Recorder::new(test_meta(), test_cfg());
        let mut buf = Vec::new();
        r.write_resize(&mut buf, 120, 40).unwrap();
        let v: Value = serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["kind"], "resize");
        assert_eq!(v["cols"], 120);
        assert_eq!(v["rows"], 40);
    }

    #[test]
    fn force_flush_emits_trailing_chunk() {
        let r = Recorder::new(test_meta(), test_cfg());
        let mut buf = Vec::new();
        r.write_header(&mut buf, 80, 24, "/bin/sh", "xterm")
            .unwrap();
        r.write_output(&mut buf, b"hi").unwrap();
        r.force_flush_chunk(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let last_line = s.trim().lines().last().unwrap();
        let v: Value = serde_json::from_str(last_line).unwrap();
        assert_eq!(v["kind"], "chunk");
        assert_eq!(v["messages"], 2);
    }

    #[test]
    fn maybe_flush_fires_at_message_threshold() {
        let mut cfg = test_cfg();
        cfg.max_messages = 2;
        let r = Recorder::new(test_meta(), cfg);
        let mut buf = Vec::new();
        r.write_header(&mut buf, 80, 24, "/bin/sh", "xterm")
            .unwrap();
        r.maybe_flush_chunk(&mut buf).unwrap();
        // Only 1 record so far → no chunk.
        assert!(!String::from_utf8_lossy(&buf).contains("\"kind\":\"chunk\""));
        r.write_output(&mut buf, b"x").unwrap();
        r.maybe_flush_chunk(&mut buf).unwrap();
        // 2 records → chunk should have fired.
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"kind\":\"chunk\""));
    }
}
