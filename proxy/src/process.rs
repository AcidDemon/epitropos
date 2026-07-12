use std::ffi::{CStr, CString};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};

const LOCK_DIR: &str = "/var/run/epitropos";

pub struct UserInfo {
    pub username: String,
}

pub fn sanitize_std_fds() {
    let devnull = CString::new("/dev/null").unwrap();
    for target_fd in 0..=2i32 {
        if unsafe { libc::fcntl(target_fd, libc::F_GETFD) } < 0 {
            let fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
            if fd >= 0 && fd != target_fd {
                unsafe {
                    libc::dup2(fd, target_fd);
                    libc::close(fd);
                }
            }
        }
    }
}

pub fn get_audit_session_id() -> Option<u32> {
    let content = std::fs::read_to_string("/proc/self/sessionid").ok()?;
    let id: u32 = content.trim().parse().ok()?;
    if id == 4294967295 {
        return None;
    }
    Some(id)
}

/// Acquire flock on session lock file. Returns held fd or None if nested.
pub fn try_session_lock(audit_session_id: u32) -> Result<Option<OwnedFd>, String> {
    let lock_path = format!("{LOCK_DIR}/session.{audit_session_id}.lock");
    let c_path = CString::new(lock_path.as_str()).unwrap();

    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "session lock open: {}",
            std::io::Error::last_os_error()
        ));
    }

    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        return Err(format!("session lock flock: {err}"));
    }

    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Result of a nesting check.
pub enum NestStatus {
    /// Kernel audit not available or no audit session assigned: skip
    /// nesting detection, caller proceeds to record as a fresh session.
    NoAuditSession,
    /// Lock acquired — this is the outer session. Caller must hold the
    /// OwnedFd for the session lifetime.
    Outer(OwnedFd),
    /// Another process already holds the lock for this audit session id
    /// — we're nested inside an existing recording.
    Nested,
}

/// Check whether the current process is a nested session.
///
/// Returns Err on real lock-system failures (e.g. /var/run/epitropos
/// unreadable, flock returns an unexpected errno). The caller MUST
/// treat Err as fail-closed: a silent "no lock file so record as
/// fresh" fallback would create an auditable gap when the lock
/// directory is unreachable, which is exactly the case an attacker
/// would try to create.
pub fn check_nesting(audit_session_id: Option<u32>) -> Result<NestStatus, String> {
    let asid = match audit_session_id {
        Some(id) => id,
        None => return Ok(NestStatus::NoAuditSession),
    };
    match try_session_lock(asid)? {
        Some(fd) => Ok(NestStatus::Outer(fd)),
        None => Ok(NestStatus::Nested),
    }
}

pub fn resolve_caller() -> Result<UserInfo, String> {
    let uid = unsafe { libc::getuid() };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(format!("getpwuid({uid}) failed"));
    }
    let pw = unsafe { &*pw };
    let username = unsafe {
        CStr::from_ptr(pw.pw_name)
            .to_str()
            .map_err(|_| "pw_name not UTF-8")?
            .to_owned()
    };
    Ok(UserInfo { username })
}

pub fn user_in_group(username: &str, group_name: &str) -> bool {
    let c_group = match CString::new(group_name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let gr = unsafe { libc::getgrnam(c_group.as_ptr()) };
    if gr.is_null() {
        return false;
    }
    let gr = unsafe { &*gr };

    // Check if the user's primary GID matches this group.
    let c_user = match CString::new(username) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if !pw.is_null() && unsafe { (*pw).pw_gid } == gr.gr_gid {
        return true;
    }

    // Check supplementary membership list.
    if gr.gr_mem.is_null() {
        return false;
    }
    let mut ptr = gr.gr_mem;
    loop {
        let member_ptr = unsafe { *ptr };
        if member_ptr.is_null() {
            break;
        }
        if unsafe { CStr::from_ptr(member_ptr) }.to_str().unwrap_or("") == username {
            return true;
        }
        ptr = unsafe { ptr.add(1) };
    }
    false
}

/// Verify we're running as the expected setuid user (not root).
pub fn verify_suid_context() -> Result<(), String> {
    let euid = unsafe { libc::geteuid() };
    let ruid = unsafe { libc::getuid() };
    if euid == 0 {
        return Err("refusing to run as root — install setuid as session-proxy, not root".into());
    }
    if euid == ruid {
        return Err("not running setuid — install with setuid bit".into());
    }
    Ok(())
}

pub fn harden_proxy() -> Result<(), String> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) } != 0 {
        return Err(format!(
            "PR_SET_DUMPABLE: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Yama LSM may not be present
    if unsafe { libc::prctl(libc::PR_SET_PTRACER, 0_u64, 0_u64, 0_u64, 0_u64) } != 0 {
        eprintln!(
            "epitropos: PR_SET_PTRACER: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Forcibly terminate the recorded shell at teardown. SIGKILL cannot be
/// trapped or ignored by the recorded user. Sends it to the
/// process group (to catch session children) and to the pid directly (which
/// tears down the shell's PID namespace when isolation is active). Errors
/// (e.g. the target is already gone) are ignored.
pub fn terminate_shell(shell_pid: libc::pid_t) {
    unsafe {
        libc::kill(-shell_pid, libc::SIGKILL);
        libc::kill(shell_pid, libc::SIGKILL);
    }
}

/// Drop the shell child back to the real user identity.
/// Uses initgroups+setresgid+setresuid to irrevocably drop all privilege.
pub fn drop_to_real_user() -> Result<(), String> {
    let ruid = unsafe { libc::getuid() };
    let rgid = unsafe { libc::getgid() };

    // Reset supplementary groups to match the real user.
    let pw = unsafe { libc::getpwuid(ruid) };
    if !pw.is_null() {
        let username = unsafe { (*pw).pw_name };
        if unsafe { libc::initgroups(username, rgid) } < 0 {
            return Err(format!(
                "initgroups failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    if unsafe { libc::setresgid(rgid, rgid, rgid) } < 0 {
        return Err(format!(
            "setresgid failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setresuid(ruid, ruid, ruid) } < 0 {
        return Err(format!(
            "setresuid failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Verify
    if unsafe { libc::getuid() } != ruid
        || unsafe { libc::geteuid() } != ruid
        || unsafe { libc::getgid() } != rgid
        || unsafe { libc::getegid() } != rgid
    {
        return Err("privilege drop verification failed".into());
    }
    Ok(())
}

/// Create an exec-sync pipe. Returns `(read_end, write_end)`; both `O_CLOEXEC`.
/// A forked child keeps the write end until it `execv`s — a successful exec
/// auto-closes it (`O_CLOEXEC`), so the parent's read sees EOF = success. On an
/// exec failure the child calls [`exec_sync_report_failure`] first.
fn exec_sync_pipe() -> Result<(RawFd, RawFd), String> {
    let mut fds: [RawFd; 2] = [-1, -1];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(format!(
            "exec-sync pipe2 failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((fds[0], fds[1]))
}

/// Child side: signal to the parent that `execv` failed. Best-effort single
/// byte, called immediately before `_exit` on the exec-failure path. `write`
/// is async-signal-safe, so this is sound in the post-fork child.
fn exec_sync_report_failure(write_fd: RawFd) {
    let byte = [1u8];
    unsafe {
        libc::write(write_fd, byte.as_ptr() as *const libc::c_void, 1);
    }
}

/// Parent side: block until the child either exec's (EOF) or reports failure
/// (one byte). `Ok(())` = exec succeeded; `Err` = the child failed to exec. The
/// caller MUST have already closed its own copy of the write end, or this never
/// sees EOF.
fn exec_sync_wait(read_fd: RawFd) -> Result<(), String> {
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(read_fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("exec-sync read failed: {err}"));
        }
        if n == 0 {
            return Ok(()); // EOF: write end closed by a successful execv
        }
        return Err("child process failed to exec".to_string());
    }
}

pub fn spawn_katagrapho(
    katagrapho_path: &str,
    session_id: &str,
    recipient_file: Option<&str>,
) -> Result<(libc::pid_t, RawFd), String> {
    let mut fds: [RawFd; 2] = [-1, -1];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(format!("pipe2 failed: {}", std::io::Error::last_os_error()));
    }
    let (pipe_read, pipe_write) = (fds[0], fds[1]);

    // Make ONLY the write end non-blocking so a stalled-but-alive katagrapho
    // cannot freeze the proxy's single-threaded event loop: FlushBuffer then
    // degrades to buffering and, past its cap, fails the recording instead
    // of blocking. The read end (katagrapho's stdin, a
    // separate open file description) stays blocking.
    unsafe {
        let fl = libc::fcntl(pipe_write, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(pipe_write, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }

    // Exec-sync pipe: detect a failed katagrapho execv deterministically
    // (fail-closed) instead of returning Ok for a child that silently _exit(1)s.
    let (sync_read, sync_write) = match exec_sync_pipe() {
        Ok(p) => p,
        Err(e) => {
            unsafe {
                libc::close(pipe_read);
                libc::close(pipe_write);
            }
            return Err(e);
        }
    };

    let c_path = CString::new(katagrapho_path).map_err(|_| "null byte in path")?;
    let c_session_id = CString::new(session_id).map_err(|_| "null byte in session_id")?;

    let encryption_args: Vec<CString> = if let Some(rf) = recipient_file {
        vec![
            CString::new("--recipient-file").unwrap(),
            CString::new(rf).map_err(|_| "null byte in recipient_file")?,
        ]
    } else {
        vec![CString::new("--no-encrypt").unwrap()]
    };

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            unsafe {
                libc::close(pipe_read);
                libc::close(pipe_write);
                libc::close(sync_read);
                libc::close(sync_write);
            }
            Err(format!("fork failed: {}", std::io::Error::last_os_error()))
        }
        0 => unsafe {
            if libc::dup2(pipe_read, libc::STDIN_FILENO) < 0 {
                exec_sync_report_failure(sync_write);
                libc::_exit(1);
            }
            // Close every inherited fd except stdin and the exec-sync write end
            // (which must survive until execv, then auto-closes via O_CLOEXEC).
            crate::pty::close_fds_above(libc::STDIN_FILENO + 1, Some(sync_write));
            let arg_flag = CString::new("--session-id").unwrap();
            let mut argv_owned: Vec<&CStr> = vec![
                c_path.as_c_str(),
                arg_flag.as_c_str(),
                c_session_id.as_c_str(),
            ];
            for arg in &encryption_args {
                argv_owned.push(arg.as_c_str());
            }
            let mut argv_ptrs: Vec<*const libc::c_char> =
                argv_owned.iter().map(|c| c.as_ptr()).collect();
            argv_ptrs.push(std::ptr::null());
            libc::execv(c_path.as_ptr(), argv_ptrs.as_ptr());
            // execv returned → it failed. Tell the parent, fail-closed.
            exec_sync_report_failure(sync_write);
            libc::_exit(1);
        },
        child_pid => {
            unsafe {
                libc::close(pipe_read);
                libc::close(sync_write); // parent only reads the sync pipe
            }
            match exec_sync_wait(sync_read) {
                Ok(()) => {
                    unsafe { libc::close(sync_read) };
                    // Keep O_CLOEXEC on pipe_write — managed explicitly so it
                    // does not leak to failure-hook children.
                    Ok((child_pid, pipe_write))
                }
                Err(e) => {
                    unsafe {
                        libc::close(sync_read);
                        libc::close(pipe_write);
                        // Reap the failed child so it does not linger as a zombie.
                        let mut status: libc::c_int = 0;
                        libc::waitpid(child_pid, &mut status, 0);
                    }
                    Err(format!("katagrapho failed to start: {e}"))
                }
            }
        }
    }
}

/// How to handle PID-namespace isolation at startup, given whether the
/// `epitropos-ns-exec` helper is available and whether the operator requires
/// isolation (`requirePidIsolation`). Pure decision — unit-testable.
#[derive(Debug, PartialEq, Eq)]
pub enum IsolationDecision {
    /// Helper available → run the shell inside a PID namespace.
    Use,
    /// Helper unavailable but not required → warn and proceed unisolated.
    ProceedWithout,
    /// Helper unavailable and required → fail closed (deny the session).
    Deny,
}

pub fn resolve_isolation(ns_exec_available: bool, require: bool) -> IsolationDecision {
    match (ns_exec_available, require) {
        (true, _) => IsolationDecision::Use,
        (false, true) => IsolationDecision::Deny,
        (false, false) => IsolationDecision::ProceedWithout,
    }
}

pub fn spawn_shell(
    slave_fd: RawFd,
    shell_path: &str,
    shell_env: &[(String, String)],
    command: Option<&str>,
    ns_exec_path: Option<&str>,
) -> Result<libc::pid_t, String> {
    let c_shell = CString::new(shell_path.as_bytes()).map_err(|_| "null byte in shell path")?;

    let (argv0, extra_args) = if let Some(cmd) = command {
        let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
        (
            CString::new(base).unwrap_or_else(|_| CString::new("sh").unwrap()),
            vec![
                CString::new("-c").unwrap(),
                CString::new(cmd).unwrap_or_default(),
            ],
        )
    } else {
        let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
        (
            CString::new(format!("-{base}")).unwrap_or_else(|_| CString::new("-sh").unwrap()),
            vec![],
        )
    };

    // Exec-sync pipe: the parent must learn if the child fails to reach a
    // successful execv — setsid/TIOCSCTTY/dup2/drop, or a failed ns_exec — so
    // it can fail closed instead of believing the shell started.
    let (sync_read, sync_write) = exec_sync_pipe()?;

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            unsafe {
                libc::close(sync_read);
                libc::close(sync_write);
            }
            Err(format!("fork failed: {}", std::io::Error::last_os_error()))
        }
        0 => unsafe {
            if libc::setsid() < 0 {
                exec_sync_report_failure(sync_write);
                libc::_exit(1);
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                exec_sync_report_failure(sync_write);
                libc::_exit(1);
            }
            if libc::dup2(slave_fd, 0) < 0
                || libc::dup2(slave_fd, 1) < 0
                || libc::dup2(slave_fd, 2) < 0
            {
                exec_sync_report_failure(sync_write);
                libc::_exit(1);
            }
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            // Keep the exec-sync write end across the fd sweep (auto-closes on
            // a successful execv via O_CLOEXEC).
            crate::pty::close_fds_above(3, Some(sync_write));

            // Irrevocably drop to the real user.
            if drop_to_real_user().is_err() {
                exec_sync_report_failure(sync_write);
                libc::_exit(1);
            }

            // SAFETY (edition 2024): post-fork, single-threaded child. No
            // other thread can race on the env table because fork() copied
            // only the calling thread. These calls are inside the parent
            // `unsafe {}` block and are sound only under that invariant.
            for (key, _) in std::env::vars_os() {
                std::env::remove_var(&key);
            }
            for (k, v) in shell_env {
                std::env::set_var(k, v);
            }

            // Build shell argv
            let mut shell_argv_owned: Vec<CString> = vec![argv0];
            for arg in extra_args {
                shell_argv_owned.push(arg);
            }

            // PID-namespace isolation via the ns-exec helper. When the caller
            // passes Some, isolation is MANDATORY: a failed ns_exec must NOT
            // fall through to an unisolated direct exec — fail closed instead,
            // so the recorded user can never end up in a session the recorder
            // cannot hide its pids from.
            if let Some(ns_path) = ns_exec_path {
                if let Ok(c_ns) = CString::new(ns_path) {
                    // argv: [ns_exec_path, shell_path, argv0, args...]
                    let mut ns_argv: Vec<*const libc::c_char> =
                        vec![c_ns.as_ptr(), c_shell.as_ptr()];
                    for a in &shell_argv_owned {
                        ns_argv.push(a.as_ptr());
                    }
                    ns_argv.push(std::ptr::null());
                    libc::execv(c_ns.as_ptr(), ns_argv.as_ptr());
                    // execv returned → ns_exec failed.
                }
                // ns_exec unusable or failed: do NOT direct-exec unisolated.
                exec_sync_report_failure(sync_write);
                libc::_exit(1);
            }

            // No isolation required (ns_exec_path == None): direct exec.
            let mut argv_ptrs: Vec<*const libc::c_char> = Vec::new();
            for a in &shell_argv_owned {
                argv_ptrs.push(a.as_ptr());
            }
            argv_ptrs.push(std::ptr::null());
            libc::execv(c_shell.as_ptr(), argv_ptrs.as_ptr());
            exec_sync_report_failure(sync_write);
            libc::_exit(1);
        },
        child_pid => {
            unsafe { libc::close(sync_write) };
            match exec_sync_wait(sync_read) {
                Ok(()) => {
                    unsafe { libc::close(sync_read) };
                    Ok(child_pid)
                }
                Err(e) => {
                    unsafe {
                        libc::close(sync_read);
                        let mut status: libc::c_int = 0;
                        libc::waitpid(child_pid, &mut status, 0);
                    }
                    Err(format!("shell failed to start: {e}"))
                }
            }
        }
    }
}

#[cfg(test)]
mod exec_sync_tests {
    use super::*;

    #[test]
    fn isolation_uses_helper_when_available() {
        assert_eq!(resolve_isolation(true, true), IsolationDecision::Use);
        assert_eq!(resolve_isolation(true, false), IsolationDecision::Use);
    }

    #[test]
    fn isolation_denies_when_required_but_unavailable() {
        assert_eq!(resolve_isolation(false, true), IsolationDecision::Deny);
    }

    #[test]
    fn isolation_proceeds_without_when_not_required() {
        assert_eq!(
            resolve_isolation(false, false),
            IsolationDecision::ProceedWithout
        );
    }

    #[test]
    fn terminate_shell_sigkills_the_process() {
        // A forked child in its own session must be
        // SIGKILLed by terminate_shell (SIGKILL cannot be trapped or ignored).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::setsid(); // own session/group so kill(-pid) targets it
                libc::pause(); // block until signalled
                libc::_exit(0); // only reached if NOT killed
            }
        }
        terminate_shell(pid);
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(r, pid, "waitpid should reap the child");
        assert!(
            libc::WIFSIGNALED(status),
            "child must be signalled, not exit normally"
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGKILL,
            "child must be SIGKILLed"
        );
    }

    #[test]
    fn spawn_katagrapho_fails_closed_when_binary_missing() {
        // A nonexistent katagrapho binary must be reported as an error
        // (fail-closed) — NOT a successful spawn whose child silently
        // execv-fails and _exit(1)s while the parent believes recording started.
        let result =
            spawn_katagrapho("/nonexistent/katagrapho-should-not-exist", "test-session", None);
        assert!(
            result.is_err(),
            "expected Err for a missing katagrapho binary, got Ok (fail-open)"
        );
    }
}
