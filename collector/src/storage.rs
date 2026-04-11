//! Storage layout under the collector's root directory.

#![allow(dead_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::CollectorError;

const SAFE_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| SAFE_CHARS.contains(c))
        && !name.starts_with('.')
}

pub struct SenderDirs {
    pub root: PathBuf,
    pub cert_pem: PathBuf,
    pub cert_fingerprint: PathBuf,
    pub signing_pub: PathBuf,
    pub enrolled_at: PathBuf,
    pub recordings: PathBuf,
}

impl SenderDirs {
    pub fn under(storage_dir: &Path, sender_name: &str) -> Result<Self, CollectorError> {
        if !is_safe_name(sender_name) {
            return Err(CollectorError::Storage(format!(
                "unsafe sender name: {sender_name:?}"
            )));
        }
        let root = storage_dir.join("senders").join(sender_name);
        Ok(Self {
            cert_pem: root.join("cert.pem"),
            cert_fingerprint: root.join("cert.fingerprint"),
            signing_pub: root.join("signing.pub"),
            enrolled_at: root.join("enrolled_at"),
            recordings: root.join("recordings"),
            root,
        })
    }

    pub fn ensure_created(&self) -> Result<(), CollectorError> {
        fs::create_dir_all(&self.root)
            .map_err(|e| CollectorError::Storage(format!("mkdir {}: {e}", self.root.display())))?;
        fs::create_dir_all(&self.recordings).map_err(|e| {
            CollectorError::Storage(format!("mkdir {}: {e}", self.recordings.display()))
        })?;
        let mut perms = fs::metadata(&self.root)
            .map_err(|e| CollectorError::Storage(format!("stat: {e}")))?
            .permissions();
        perms.set_mode(0o750);
        let _ = fs::set_permissions(&self.root, perms);
        Ok(())
    }
}

pub fn recording_paths(
    sender: &SenderDirs,
    user: &str,
    session_id: &str,
    part: u32,
) -> Result<(PathBuf, PathBuf), CollectorError> {
    if !is_safe_name(user) {
        return Err(CollectorError::Storage(format!("unsafe user: {user:?}")));
    }
    if !is_safe_name(session_id) {
        return Err(CollectorError::Storage(format!(
            "unsafe session_id: {session_id:?}"
        )));
    }
    let dir = sender.recordings.join(user);
    let rec = dir.join(format!("{session_id}.part{part}.kgv1.age"));
    let sidecar = dir.join(format!("{session_id}.part{part}.kgv1.age.manifest.json"));
    if !rec.starts_with(&sender.root) || !sidecar.starts_with(&sender.root) {
        return Err(CollectorError::Storage("path escapes sender root".into()));
    }
    Ok((rec, sidecar))
}

/// Atomic write: tmp file + fsync + rename. Mode 0640.
pub fn put_atomic(path: &Path, data: &[u8]) -> Result<(), CollectorError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CollectorError::Storage(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o640)
        .open(&tmp)
        .map_err(|e| CollectorError::Storage(format!("open tmp: {e}")))?;
    f.write_all(data)
        .map_err(|e| CollectorError::Storage(format!("write: {e}")))?;
    f.sync_all()
        .map_err(|e| CollectorError::Storage(format!("fsync: {e}")))?;
    drop(f);
    // Force mode AFTER open: OpenOptions::mode is subject to the caller's
    // umask, which can strip group bits. Collector runs as its own user
    // and needs deterministic modes regardless of the invoking umask.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))
        .map_err(|e| CollectorError::Storage(format!("chmod: {e}")))?;
    fs::rename(&tmp, path)
        .map_err(|e| CollectorError::Storage(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn safe_name_rejects_slashes() {
        assert!(!is_safe_name("foo/bar"));
        assert!(!is_safe_name(".hidden"));
        assert!(!is_safe_name(""));
        assert!(is_safe_name("alice-laptop"));
        assert!(is_safe_name("node01.nyx"));
    }

    #[test]
    fn sender_dirs_rejects_bad_name() {
        let dir = tempdir().unwrap();
        assert!(SenderDirs::under(dir.path(), "../evil").is_err());
        assert!(SenderDirs::under(dir.path(), "good").is_ok());
    }

    #[test]
    fn recording_paths_rejects_bad_input() {
        let dir = tempdir().unwrap();
        let s = SenderDirs::under(dir.path(), "alice").unwrap();
        assert!(recording_paths(&s, "../etc", "s1", 0).is_err());
        assert!(recording_paths(&s, "alice", "s/1", 0).is_err());
        let (rec, sc) = recording_paths(&s, "alice", "s1", 0).unwrap();
        assert!(rec.starts_with(&s.root));
        assert!(sc.starts_with(&s.root));
    }

    #[test]
    fn put_atomic_creates_parent_and_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sub/file.bin");
        put_atomic(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}
