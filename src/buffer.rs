use std::io::Write;
use std::os::unix::io::RawFd;
use std::time::Instant;

/// Time-windowed write buffer with hard memory cap.
pub struct FlushBuffer {
    buf: Vec<u8>,
    fd: RawFd,
    capacity: usize,
    max_size: usize,
    latency_secs: u64,
    last_flush: Instant,
    broken: bool,
}

impl FlushBuffer {
    pub fn new(fd: RawFd, latency_secs: u64) -> Self {
        let capacity = 64 * 1024;
        let max_size = 4 * 1024 * 1024; // 4 MiB hard limit
        FlushBuffer {
            buf: Vec::with_capacity(capacity),
            fd,
            capacity,
            max_size,
            latency_secs,
            last_flush: Instant::now(),
            broken: false,
        }
    }

    pub fn should_flush(&self) -> bool {
        !self.buf.is_empty() && self.last_flush.elapsed().as_secs() >= self.latency_secs
    }

    #[allow(dead_code)]
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    pub fn flush(&mut self) -> Result<(), String> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut offset = 0;
        while offset < self.buf.len() {
            let n = unsafe {
                libc::write(
                    self.fd,
                    self.buf[offset..].as_ptr() as *const libc::c_void,
                    self.buf.len() - offset,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                self.buf.clear();
                self.broken = true;
                return Err("pipe write failed".to_string());
            }
            if n == 0 {
                self.buf.clear();
                self.broken = true;
                return Err("pipe write returned 0".to_string());
            }
            offset += n as usize;
        }
        self.buf.clear();
        self.last_flush = Instant::now();
        Ok(())
    }
}

impl Write for FlushBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.broken {
            return Err(std::io::Error::other("pipe broken"));
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() >= self.max_size {
            self.flush().map_err(std::io::Error::other)?;
            if self.buf.len() >= self.max_size {
                self.broken = true;
                return Err(std::io::Error::other(
                    "buffer overflow: katagrapho pipe stalled",
                ));
            }
        } else if self.buf.len() >= self.capacity {
            self.flush().map_err(std::io::Error::other)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        FlushBuffer::flush(self).map_err(std::io::Error::other)
    }
}

// ---------------------------------------------------------------------------
// ChunkTracker: decides chunk boundaries and computes a streaming SHA-256 over
// the records in the current chunk. Used by kgv1_writer to emit `chunk`
// records at flush boundaries.
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

use crate::config::Chunk as ChunkCfg;

pub struct ChunkTracker {
    cfg: ChunkCfg,
    seq: u64,
    bytes: u64,
    messages: u64,
    chunk_start: Instant,
    hasher: Sha256,
}

pub struct ChunkSummary {
    pub seq: u64,
    pub bytes: u64,
    pub messages: u64,
    pub elapsed: f64,
    pub sha256_hex: String,
}

impl ChunkTracker {
    pub fn new(cfg: ChunkCfg) -> Self {
        Self {
            cfg,
            seq: 0,
            bytes: 0,
            messages: 0,
            chunk_start: Instant::now(),
            hasher: Sha256::new(),
        }
    }

    /// Feed a serialized record (JSON line + trailing \n).
    pub fn record(&mut self, record_bytes: &[u8]) {
        self.bytes += record_bytes.len() as u64;
        self.messages += 1;
        self.hasher.update(record_bytes);
    }

    pub fn should_flush(&self) -> bool {
        if self.bytes >= self.cfg.max_bytes as u64 {
            return true;
        }
        if self.messages >= self.cfg.max_messages {
            return true;
        }
        if self.chunk_start.elapsed().as_secs_f64() >= self.cfg.max_seconds {
            return true;
        }
        false
    }

    pub fn finalize(&mut self) -> ChunkSummary {
        let digest = std::mem::take(&mut self.hasher).finalize();
        ChunkSummary {
            seq: self.seq,
            bytes: self.bytes,
            messages: self.messages,
            elapsed: self.chunk_start.elapsed().as_secs_f64(),
            sha256_hex: hex::encode(digest),
        }
    }

    pub fn reset(&mut self) {
        self.seq += 1;
        self.bytes = 0;
        self.messages = 0;
        self.chunk_start = Instant::now();
        self.hasher = Sha256::new();
    }

    pub fn message_count(&self) -> u64 {
        self.messages
    }
}

#[cfg(test)]
mod chunk_tracker_tests {
    use super::*;

    fn cfg(max_bytes: usize, max_messages: u64, max_seconds: f64) -> ChunkCfg {
        ChunkCfg {
            max_bytes,
            max_messages,
            max_seconds,
        }
    }

    #[test]
    fn flush_fires_on_message_count() {
        let mut t = ChunkTracker::new(cfg(usize::MAX, 3, f64::MAX));
        t.record(b"a\n");
        t.record(b"b\n");
        assert!(!t.should_flush());
        t.record(b"c\n");
        assert!(t.should_flush());
    }

    #[test]
    fn flush_fires_on_byte_count() {
        let mut t = ChunkTracker::new(cfg(10, u64::MAX, f64::MAX));
        t.record(b"hello\n");
        assert!(!t.should_flush());
        t.record(b"world\n");
        assert!(t.should_flush());
    }

    #[test]
    fn finalize_returns_running_hash_and_resets() {
        let mut t = ChunkTracker::new(cfg(usize::MAX, u64::MAX, f64::MAX));
        t.record(b"abc\n");
        let s1 = t.finalize();
        assert_eq!(s1.seq, 0);
        assert_eq!(s1.bytes, 4);
        assert_eq!(s1.messages, 1);
        let mut h = Sha256::new();
        h.update(b"abc\n");
        assert_eq!(s1.sha256_hex, hex::encode(h.finalize()));

        t.reset();
        assert_eq!(t.message_count(), 0);
        t.record(b"def\n");
        let s2 = t.finalize();
        assert_eq!(s2.seq, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_broken_on_closed_pipe() {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let mut buf = FlushBuffer::new(fds[1], 60);
        unsafe { libc::close(fds[0]) }; // close read end

        let big = vec![0u8; 65 * 1024];
        let result = Write::write_all(&mut buf, &big);
        assert!(result.is_err() || buf.is_broken());

        unsafe { libc::close(fds[1]) };
    }

    #[test]
    fn rejects_writes_when_broken() {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let mut buf = FlushBuffer::new(fds[1], 60);
        unsafe { libc::close(fds[0]) };

        let big = vec![0u8; 65 * 1024];
        let _ = Write::write_all(&mut buf, &big);

        // Subsequent writes should fail immediately
        let result = Write::write(&mut buf, b"hello");
        assert!(result.is_err());

        unsafe { libc::close(fds[1]) };
    }

    #[test]
    fn buffers_until_capacity() {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let mut buf = FlushBuffer::new(fds[1], 60);

        // Write less than capacity — should stay buffered
        Write::write_all(&mut buf, b"hello").unwrap();
        assert!(!buf.buf.is_empty());

        // Explicit flush
        buf.flush().unwrap();
        assert!(buf.buf.is_empty());

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
