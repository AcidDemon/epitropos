//! Best-effort scrape of SSH/PAM-adjacent metadata for the recording
//! header. Called BEFORE env::sanitize() so SSH_* env vars are still
//! present. Never panics, never errors — missing fields become None.

use std::fs;

#[derive(Debug, Clone, Default)]
pub struct AuthMeta {
    pub ssh_client: Option<String>,
    pub ssh_connection: Option<String>,
    pub ssh_original_command: Option<String>,
    pub ppid: i32,
    pub parent_comm: Option<String>,
    pub parent_cmdline: Option<String>,
    pub pam_rhost: Option<String>,   // reserved for Track D
    pub pam_service: Option<String>, // reserved for Track D
}

impl AuthMeta {
    pub fn capture() -> Self {
        let ppid = unsafe { libc::getppid() };
        AuthMeta {
            ssh_client: std::env::var("SSH_CLIENT").ok(),
            ssh_connection: std::env::var("SSH_CONNECTION").ok(),
            ssh_original_command: std::env::var("SSH_ORIGINAL_COMMAND").ok(),
            ppid,
            parent_comm: read_proc_field(ppid, "comm"),
            parent_cmdline: read_proc_cmdline(ppid),
            pam_rhost: None,
            pam_service: None,
        }
    }
}

fn read_proc_field(pid: i32, field: &str) -> Option<String> {
    let path = format!("/proc/{pid}/{field}");
    let bytes = fs::read(&path).ok()?;
    let s = String::from_utf8_lossy(&bytes).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn read_proc_cmdline(pid: i32) -> Option<String> {
    let path = format!("/proc/{pid}/cmdline");
    let bytes = fs::read(&path).ok()?;
    let truncated = &bytes[..bytes.len().min(4096)];
    let parts: Vec<&str> = truncated
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .filter_map(|p| std::str::from_utf8(p).ok())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_with_no_ssh_env_returns_none_for_ssh_fields() {
        unsafe {
            std::env::remove_var("SSH_CLIENT");
            std::env::remove_var("SSH_CONNECTION");
            std::env::remove_var("SSH_ORIGINAL_COMMAND");
        }
        let m = AuthMeta::capture();
        assert!(m.ssh_client.is_none());
        assert!(m.ssh_connection.is_none());
        assert!(m.ssh_original_command.is_none());
        assert_eq!(m.pam_rhost, None);
        assert_eq!(m.pam_service, None);
        assert!(m.ppid > 0);
    }

    #[test]
    fn read_proc_field_for_self_returns_some() {
        let pid = unsafe { libc::getpid() };
        let comm = read_proc_field(pid, "comm");
        assert!(comm.is_some());
    }
}
