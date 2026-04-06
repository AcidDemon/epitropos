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
                return Err(std::io::Error::other("buffer overflow: katagrapho pipe stalled"));
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
