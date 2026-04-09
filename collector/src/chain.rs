//! Per-sender head pointer + append-only log. Strict mode: advance
//! only if the supplied prev_manifest_hash equals the current head.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::CollectorError;

pub const GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[allow(dead_code)]
pub struct SenderChain {
    pub head: PathBuf,
    pub log: PathBuf,
    pub lock: PathBuf,
}

#[allow(dead_code)]
impl SenderChain {
    pub fn under(sender_dir: &Path) -> Self {
        Self {
            head: sender_dir.join("head.hash"),
            log: sender_dir.join("head.hash.log"),
            lock: sender_dir.join("head.hash.lock"),
        }
    }
}

pub struct ChainLock {
    file: fs::File,
}

#[allow(dead_code)]
impl ChainLock {
    pub fn acquire(chain: &SenderChain) -> Result<Self, CollectorError> {
        if let Some(parent) = chain.lock.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                CollectorError::Chain(format!("mkdir {}: {e}", parent.display()))
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&chain.lock)
            .map_err(|e| CollectorError::Chain(format!("open lock: {e}")))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(CollectorError::Chain(format!(
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

#[allow(dead_code)]
pub fn read_head(chain: &SenderChain) -> Result<String, CollectorError> {
    if !chain.head.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let s = fs::read_to_string(&chain.head)
        .map_err(|e| CollectorError::Chain(format!("read head: {e}")))?;
    let trimmed = s.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CollectorError::Chain(format!(
            "head.hash not 64 hex: {trimmed:?}"
        )));
    }
    Ok(trimmed.to_string())
}

#[allow(dead_code)]
pub fn write_head(chain: &SenderChain, hex_hash: &str) -> Result<(), CollectorError> {
    if hex_hash.len() != 64 {
        return Err(CollectorError::Chain(
            "hash must be 64 hex chars".into(),
        ));
    }
    let tmp = chain.head.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| CollectorError::Chain(format!("open head tmp: {e}")))?;
    f.write_all(hex_hash.as_bytes())
        .map_err(|e| CollectorError::Chain(format!("write head: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Chain(format!("fsync head: {e}")))?;
    drop(f);
    fs::rename(&tmp, &chain.head)
        .map_err(|e| CollectorError::Chain(format!("rename head: {e}")))?;
    Ok(())
}

#[allow(dead_code)]
pub fn append_log(
    chain: &SenderChain,
    iso_ts: &str,
    user: &str,
    session_id: &str,
    part: u32,
    hex_hash: &str,
) -> Result<(), CollectorError> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(&chain.log)
        .map_err(|e| CollectorError::Chain(format!("open log: {e}")))?;
    let line = format!("{iso_ts} {user} {session_id} {part} {hex_hash}\n");
    f.write_all(line.as_bytes())
        .map_err(|e| CollectorError::Chain(format!("write log: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Chain(format!("fsync log: {e}")))?;
    Ok(())
}

/// Strict advance: fails if `prev` does not match the current head.
/// Must be called with `ChainLock` held.
#[allow(dead_code)]
pub fn strict_advance(
    chain: &SenderChain,
    prev: &str,
    new_head: &str,
) -> Result<(), CollectorError> {
    let current = read_head(chain)?;
    if current != prev {
        return Err(CollectorError::Chain(format!(
            "chain gap: expected prev={current} but manifest said {prev}"
        )));
    }
    write_head(chain, new_head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn genesis_when_missing() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        assert_eq!(read_head(&c).unwrap(), GENESIS_PREV);
    }

    #[test]
    fn advance_once_from_genesis() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        let _g = ChainLock::acquire(&c).unwrap();
        let new_hash = "a".repeat(64);
        strict_advance(&c, GENESIS_PREV, &new_hash).unwrap();
        assert_eq!(read_head(&c).unwrap(), new_hash);
    }

    #[test]
    fn advance_with_wrong_prev_fails() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        let _g = ChainLock::acquire(&c).unwrap();
        strict_advance(&c, GENESIS_PREV, &"a".repeat(64)).unwrap();
        let wrong_prev = "b".repeat(64);
        assert!(strict_advance(&c, &wrong_prev, &"c".repeat(64)).is_err());
    }

    #[test]
    fn append_log_appends_lines() {
        let dir = tempdir().unwrap();
        let c = SenderChain::under(dir.path());
        append_log(
            &c,
            "2026-04-07T12:00:00Z",
            "alice",
            "s1",
            0,
            &"a".repeat(64),
        )
        .unwrap();
        append_log(
            &c,
            "2026-04-07T12:01:00Z",
            "alice",
            "s1",
            1,
            &"b".repeat(64),
        )
        .unwrap();
        let content = fs::read_to_string(&c.log).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("alice s1 0"));
        assert!(content.contains("alice s1 1"));
    }
}
