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
        let (pam_rhost, pam_service) = read_pam_stash(ppid);
        AuthMeta {
            ssh_client: std::env::var("SSH_CLIENT").ok(),
            ssh_connection: std::env::var("SSH_CONNECTION").ok(),
            ssh_original_command: std::env::var("SSH_ORIGINAL_COMMAND").ok(),
            ppid,
            parent_comm: read_proc_field(ppid, "comm"),
            parent_cmdline: read_proc_cmdline(ppid),
            pam_rhost,
            pam_service,
        }
    }
}

/// Read PAM variables stashed by pam_epitropos.so during open_session.
/// The file is at /var/run/epitropos/pam.<ppid>.env where ppid is
/// the sshd process that forked us.
fn read_pam_stash(ppid: i32) -> (Option<String>, Option<String>) {
    let path = format!("/var/run/epitropos/pam.{ppid}.env");
    let Ok(content) = fs::read_to_string(&path) else {
        return (None, None);
    };
    parse_pam_stash(&content)
}

/// Parse the PAM stash content into (rhost, service). Pure + testable.
/// Rejects any value containing a control byte (0x00-0x1f) or DEL (0x7f):
/// the values derive from attacker-influenceable PAM items (e.g. rhost from
/// unverified reverse DNS) and flow unescaped-in-spirit into the recording
/// header and the theatron web UI, so an escape/control sequence must not
/// survive. Newline injection is prevented at the write side (pam_epitropos.c);
/// this is defense-in-depth against a malformed or hand-crafted stash file.
fn parse_pam_stash(content: &str) -> (Option<String>, Option<String>) {
    let mut rhost = None;
    let mut service = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PAM_RHOST=") {
            rhost = clean_value(v);
        } else if let Some(v) = line.strip_prefix("PAM_SERVICE=") {
            service = clean_value(v);
        }
    }
    (rhost, service)
}

/// Accept a stash value only if it has no control/DEL bytes; otherwise drop it.
fn clean_value(v: &str) -> Option<String> {
    if v.bytes().any(|b| b < 0x20 || b == 0x7f) {
        None
    } else {
        Some(v.to_string())
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
    fn parse_pam_stash_parses_clean_fields() {
        let (rhost, service) = parse_pam_stash(
            "PAM_RHOST=10.0.0.1\nPAM_SERVICE=sshd\nPAM_TTY=/dev/pts/0\nPAM_USER=alice\n",
        );
        assert_eq!(rhost.as_deref(), Some("10.0.0.1"));
        assert_eq!(service.as_deref(), Some("sshd"));
    }

    #[test]
    fn parse_pam_stash_rejects_control_chars_in_values() {
        // A value carrying an escape/control sequence (attacker-influenced PAM
        // item) must be dropped, not propagated into the recording header / UI.
        let (rhost, service) =
            parse_pam_stash("PAM_RHOST=1.2.3.4\x1b[31mINJECT\nPAM_SERVICE=sshd\n");
        assert_eq!(rhost, None, "control-char rhost must be rejected");
        assert_eq!(service.as_deref(), Some("sshd"));
    }

    #[test]
    fn clean_value_accepts_normal_and_rejects_control() {
        assert_eq!(clean_value("sshd").as_deref(), Some("sshd"));
        assert_eq!(clean_value("host.example.com").as_deref(), Some("host.example.com"));
        assert_eq!(clean_value("bad\x07bell"), None);
        assert_eq!(clean_value("carriage\rreturn"), None);
    }

    #[test]
    fn read_proc_field_for_self_returns_some() {
        let pid = unsafe { libc::getpid() };
        let comm = read_proc_field(pid, "comm");
        assert!(comm.is_some());
    }
}
