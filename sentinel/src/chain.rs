//! Per-host head pointer for events sidecars.

#![allow(dead_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use crate::error::SentinelError;
use crate::events::GENESIS_PREV;

pub struct ChainPaths {
    pub head: PathBuf,
    pub lock: PathBuf,
}

impl ChainPaths {
    pub fn new(head: PathBuf) -> Self {
        let lock = head.with_extension("lock");
        Self { head, lock }
    }
}

pub struct ChainLock {
    file: fs::File,
}

impl ChainLock {
    pub fn acquire(paths: &ChainPaths) -> Result<Self, SentinelError> {
        if let Some(parent) = paths.lock.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| SentinelError::Chain(format!("mkdir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&paths.lock)
            .map_err(|e| SentinelError::Chain(format!("open lock: {e}")))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(SentinelError::Chain(format!(
                "flock: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for ChainLock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub fn read_head(paths: &ChainPaths) -> Result<String, SentinelError> {
    if !paths.head.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let s = fs::read_to_string(&paths.head)
        .map_err(|e| SentinelError::Chain(format!("read head: {e}")))?;
    let t = s.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SentinelError::Chain(format!("head not 64 hex: {t:?}")));
    }
    Ok(t.to_string())
}

pub fn write_head(paths: &ChainPaths, hex: &str) -> Result<(), SentinelError> {
    if hex.len() != 64 {
        return Err(SentinelError::Chain("hash not 64 hex".into()));
    }
    let tmp = paths.head.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| SentinelError::Chain(format!("open tmp: {e}")))?;
    f.write_all(hex.as_bytes())
        .map_err(|e| SentinelError::Chain(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| SentinelError::Chain(format!("fsync: {e}")))?;
    drop(f);
    fs::rename(&tmp, &paths.head)
        .map_err(|e| SentinelError::Chain(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn genesis_when_missing() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        assert_eq!(read_head(&c).unwrap(), GENESIS_PREV);
    }

    #[test]
    fn write_read_round_trip() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        let h = "a".repeat(64);
        write_head(&c, &h).unwrap();
        assert_eq!(read_head(&c).unwrap(), h);
    }

    #[test]
    fn reject_bad_length() {
        let dir = tempdir().unwrap();
        let c = ChainPaths::new(dir.path().join("head.hash"));
        assert!(write_head(&c, "deadbeef").is_err());
    }
}
