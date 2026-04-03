use std::io::Write;
use std::os::unix::io::RawFd;
use std::time::Instant;

/// Time-windowed write buffer. Accumulates data and flushes either
/// when the latency window expires or the buffer reaches capacity.
pub struct FlushBuffer {
    buf: Vec<u8>,
    fd: RawFd,
    capacity: usize,
    latency_secs: u64,
    last_flush: Instant,
}

impl FlushBuffer {
    pub fn new(fd: RawFd, latency_secs: u64) -> Self {
        let capacity = 64 * 1024;
        FlushBuffer {
            buf: Vec::with_capacity(capacity),
            fd,
            capacity,
            latency_secs,
            last_flush: Instant::now(),
        }
    }

    pub fn should_flush(&self) -> bool {
        !self.buf.is_empty() && self.last_flush.elapsed().as_secs() >= self.latency_secs
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
            if n <= 0 {
                self.buf.clear();
                return Err("pipe write failed".to_string());
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
        self.buf.extend_from_slice(data);
        if self.buf.len() >= self.capacity {
            self.flush().map_err(std::io::Error::other)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        FlushBuffer::flush(self).map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
