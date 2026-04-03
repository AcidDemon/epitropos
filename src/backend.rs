use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

pub struct SyslogWriter {
    initialized: bool,
}

impl SyslogWriter {
    pub fn new(ident: &str, facility: libc::c_int) -> Self {
        let c_ident = std::ffi::CString::new(ident).unwrap_or_default();
        unsafe {
            libc::openlog(c_ident.as_ptr(), libc::LOG_NDELAY, facility);
        }
        std::mem::forget(c_ident);
        SyslogWriter { initialized: true }
    }
}

impl Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.initialized {
            return Ok(buf.len());
        }
        let msg = std::ffi::CString::new(buf).unwrap_or_default();
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
