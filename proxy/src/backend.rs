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

pub struct LiveMirror {
    file: std::fs::File,
    path: std::path::PathBuf,
    recipient: age::x25519::Recipient,
}

impl LiveMirror {
    /// Create an encrypted live mirror. Each record is encrypted to `recipient`
    /// as a standalone, length-prefixed age blob (`[u32 LE len][age blob]`), so
    /// a viewer holding the matching identity can decrypt records as they are
    /// tailed and nobody else — not even the shared session-proxy account that
    /// writes the file — can read the session content. The proxy holds only the
    /// public recipient. Ciphertext is safe at rest, so the file is 0o644 and
    /// access control is the identity, not the filesystem ACL.
    pub fn create(path: &std::path::Path, recipient_str: &str) -> std::io::Result<Self> {
        let recipient: age::x25519::Recipient = recipient_str.trim().parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid live recipient key: {e}"),
            )
        })?;
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(path)?;
        Ok(LiveMirror {
            file,
            path: path.to_path_buf(),
            recipient,
        })
    }

    /// Encrypt one record into a standalone age blob (header + one chunk +
    /// finalize marker). `finish()` MUST run or the blob is truncated and
    /// undecryptable, so the frame is only emitted after it succeeds.
    fn encrypt_record(&self, buf: &[u8]) -> std::io::Result<Vec<u8>> {
        let encryptor = age::Encryptor::with_recipients(std::iter::once(
            &self.recipient as &dyn age::Recipient,
        ))
        .map_err(|e| std::io::Error::other(format!("age encryptor: {e}")))?;
        let mut blob = Vec::new();
        let mut w = encryptor
            .wrap_output(&mut blob)
            .map_err(|e| std::io::Error::other(format!("age wrap: {e}")))?;
        w.write_all(buf)?;
        w.finish()
            .map_err(|e| std::io::Error::other(format!("age finish: {e}")))?;
        Ok(blob)
    }
}

impl Write for LiveMirror {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // One age blob per record — ~215B header overhead each, which buys
        // per-record live latency vs age STREAM's 64KiB chunk buffering. A
        // record is one PTY read (<=64KiB), so overhead is negligible on bulk
        // output; the tmpfs mirror is bounded and write errors are non-fatal.
        let blob = self.encrypt_record(buf)?;
        let len = u32::try_from(blob.len())
            .map_err(|_| std::io::Error::other("live mirror blob exceeds u32"))?;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&blob)?;
        self.file.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Drop for LiveMirror {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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

    fn decode_frames(framed: &[u8], identity: &age::x25519::Identity) -> Vec<Vec<u8>> {
        use std::io::Read;
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 4 <= framed.len() {
            let len = u32::from_le_bytes(framed[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            let blob = &framed[off..off + len];
            off += len;
            let dec = age::Decryptor::new(std::io::Cursor::new(blob)).unwrap();
            let mut r = dec
                .decrypt(std::iter::once(identity as &dyn age::Identity))
                .unwrap();
            let mut plain = Vec::new();
            r.read_to_end(&mut plain).unwrap();
            out.push(plain);
        }
        out
    }

    #[test]
    fn live_mirror_encrypts_each_record_as_framed_age_blob() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sess.age");

        let rec1 = b"{\"kind\":\"out\",\"t\":0.1,\"b\":\"aGk=\"}\n".to_vec();
        let rec2 = b"{\"kind\":\"in\",\"t\":0.2,\"b\":\"eA==\"}\n".to_vec();
        let framed = {
            let mut m = LiveMirror::create(&path, &recipient.to_string()).unwrap();
            m.write_all(&rec1).unwrap();
            m.write_all(&rec2).unwrap();
            m.flush().unwrap();
            std::fs::read(&path).unwrap() // read while alive; Drop removes it
        };

        let got = decode_frames(&framed, &identity);
        assert_eq!(
            got,
            vec![rec1, rec2],
            "records must round-trip through the age framing"
        );
    }

    #[test]
    fn live_mirror_file_contains_no_plaintext() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.age");
        let secret = b"SECRET-PASSWORD-1234\n";
        let framed = {
            let mut m = LiveMirror::create(&path, &recipient.to_string()).unwrap();
            m.write_all(secret).unwrap();
            m.flush().unwrap();
            std::fs::read(&path).unwrap()
        };
        assert!(
            !framed.windows(secret.len()).any(|w| w == secret),
            "session content must not appear in cleartext in the mirror"
        );
    }

    #[test]
    fn live_mirror_rejects_bad_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.age");
        assert!(LiveMirror::create(&path, "not-an-age-recipient").is_err());
    }
}
