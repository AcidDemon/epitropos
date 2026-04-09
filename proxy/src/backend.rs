use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

pub struct MultiWriter {
    writers: Vec<Box<dyn Write>>,
}

impl MultiWriter {
    pub fn new(writers: Vec<Box<dyn Write>>) -> Self {
        MultiWriter { writers }
    }
}

impl Write for MultiWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut last_err = None;
        for w in &mut self.writers {
            if let Err(e) = w.write_all(buf) {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut last_err = None;
        for w in &mut self.writers {
            if let Err(e) = w.flush() {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

pub struct SyslogWriter {
    initialized: bool,
    _ident: std::ffi::CString, // must outlive openlog
}

impl SyslogWriter {
    pub fn new(ident: &str, facility: libc::c_int) -> Self {
        let c_ident = std::ffi::CString::new(ident).unwrap_or_default();
        unsafe {
            libc::openlog(c_ident.as_ptr(), libc::LOG_NDELAY, facility);
        }
        SyslogWriter {
            initialized: true,
            _ident: c_ident,
        }
    }
}

impl Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.initialized {
            return Ok(buf.len());
        }
        // Replace NUL bytes so CString doesn't silently discard the message
        let cleaned: Vec<u8> = buf.iter().map(|&b| if b == 0 { b'?' } else { b }).collect();
        let msg = std::ffi::CString::new(cleaned).unwrap_or_default();
        unsafe {
            libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), msg.as_ptr());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for SyslogWriter {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { libc::closelog() };
        }
    }
}

pub struct JournaldWriter {
    identifier: String,
}

impl JournaldWriter {
    pub fn new(identifier: &str) -> Self {
        JournaldWriter {
            identifier: identifier.to_string(),
        }
    }
}

impl Write for JournaldWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let msg = String::from_utf8_lossy(buf);
        for line in msg.lines() {
            if !line.is_empty() {
                eprintln!("<6>{}: {line}", self.identifier);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct FileWriter {
    file: std::fs::File,
}

impl FileWriter {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(FileWriter { file })
    }
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailWriter;
    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fail"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("fail"))
        }
    }

    #[test]
    fn multi_writer_all_succeed() {
        let mut mw = MultiWriter::new(vec![Box::new(Vec::<u8>::new()), Box::new(Vec::<u8>::new())]);
        assert!(mw.write(b"hello").is_ok());
        assert_eq!(mw.write(b"hello").unwrap(), 5);
    }

    #[test]
    fn multi_writer_returns_error_but_writes_all() {
        let mut mw = MultiWriter::new(vec![Box::new(FailWriter), Box::new(Vec::<u8>::new())]);
        // Should return error from FailWriter but second writer still gets data
        assert!(mw.write(b"hello").is_err());
    }
}
