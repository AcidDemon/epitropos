//! Per-host head pointer for the privilege-events sidecar chain. Copied from
//! epitropos-sentinel/src/chain.rs — an INDEPENDENT chain (own head file) so the
//! audit feed's tamper-evidence does not entangle the sentinel's.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use crate::error::AuditError;
use crate::events::GENESIS_PREV;

#[derive(Debug)]
pub struct ChainWalk {
    pub links_traversed: usize,
}

/// Walk the sidecar chain from `head` to genesis. A hash absent from `links` is
/// a deleted/moved sidecar — a privilege event may have been erased. Pure.
pub fn walk_chain(head: &str, links: &HashMap<String, String>) -> Result<ChainWalk, AuditError> {
    let mut current = head.to_string();
    let mut seen: HashSet<String> = HashSet::new();
    let mut n = 0usize;
    while current != GENESIS_PREV {
        if !seen.insert(current.clone()) {
            return Err(AuditError::Chain(format!("chain cycle detected at {current}")));
        }
        match links.get(&current) {
            Some(prev) => {
                current.clone_from(prev);
                n += 1;
            }
            None => {
                return Err(AuditError::Chain(format!(
                    "broken chain: sidecar {current} is missing (deleted or moved)"
                )));
            }
        }
    }
    Ok(ChainWalk { links_traversed: n })
}

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
    pub fn acquire(paths: &ChainPaths) -> Result<Self, AuditError> {
        if let Some(parent) = paths.lock.parent() {
            fs::create_dir_all(parent).map_err(|e| AuditError::Chain(format!("mkdir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&paths.lock)
            .map_err(|e| AuditError::Chain(format!("open lock: {e}")))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(AuditError::Chain(format!(
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

pub fn read_head(paths: &ChainPaths) -> Result<String, AuditError> {
    if !paths.head.exists() {
        return Ok(GENESIS_PREV.to_string());
    }
    let s = fs::read_to_string(&paths.head)
        .map_err(|e| AuditError::Chain(format!("read head: {e}")))?;
    let t = s.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuditError::Chain(format!("head not 64 hex: {t:?}")));
    }
    Ok(t.to_string())
}

pub fn write_head(paths: &ChainPaths, hex: &str) -> Result<(), AuditError> {
    if hex.len() != 64 {
        return Err(AuditError::Chain("hash not 64 hex".into()));
    }
    let tmp = paths.head.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| AuditError::Chain(format!("open tmp: {e}")))?;
    f.write_all(hex.as_bytes())
        .map_err(|e| AuditError::Chain(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| AuditError::Chain(format!("fsync: {e}")))?;
    drop(f);
    fs::rename(&tmp, &paths.head).map_err(|e| AuditError::Chain(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(t, p)| (t.to_string(), p.to_string())).collect()
    }

    #[test]
    fn walk_intact() {
        let l = links(&[("s1", GENESIS_PREV), ("s2", "s1")]);
        assert_eq!(walk_chain("s2", &l).unwrap().links_traversed, 2);
    }

    #[test]
    fn walk_detects_deleted() {
        let l = links(&[("s1", GENESIS_PREV), ("s3", "s2")]);
        assert!(walk_chain("s3", &l).unwrap_err().to_string().contains("s2"));
    }

    #[test]
    fn walk_detects_cycle() {
        assert!(walk_chain("a", &links(&[("a", "b"), ("b", "a")])).is_err());
    }
}
