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
            }
            Err(format!("fork failed: {}", std::io::Error::last_os_error()))
        }
        0 => unsafe {
            if libc::dup2(pipe_read, libc::STDIN_FILENO) < 0 {
                libc::_exit(1);
            }
            crate::pty::close_fds_above(libc::STDIN_FILENO + 1);
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
            libc::_exit(1);
        },
        child_pid => {
            unsafe { libc::close(pipe_read) };
            // Keep O_CLOEXEC on pipe_write — we'll manage it explicitly.
            // This prevents leaking to failure hook children.
            Ok((child_pid, pipe_write))
        }
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

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(format!("fork failed: {}", std::io::Error::last_os_error())),
        0 => unsafe {
            if libc::setsid() < 0 {
                libc::_exit(1);
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                libc::_exit(1);
            }
            if libc::dup2(slave_fd, 0) < 0
                || libc::dup2(slave_fd, 1) < 0
                || libc::dup2(slave_fd, 2) < 0
            {
                libc::_exit(1);
            }
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            crate::pty::close_fds_above(3);

            // Irrevocably drop to the real user.
            if drop_to_real_user().is_err() {
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

            // Try PID namespace isolation via helper
            if let Some(ns_path) = ns_exec_path
                && let Ok(c_ns) = CString::new(ns_path)
            {
                // argv: [ns_exec_path, shell_path, argv0, args...]
                let mut ns_argv: Vec<*const libc::c_char> = vec![c_ns.as_ptr(), c_shell.as_ptr()];
                for a in &shell_argv_owned {
                    ns_argv.push(a.as_ptr());
                }
                ns_argv.push(std::ptr::null());
                libc::execv(c_ns.as_ptr(), ns_argv.as_ptr());
                // execv failed — fall through
            }

            // Direct exec (fallback)
            let mut argv_ptrs: Vec<*const libc::c_char> = Vec::new();
            for a in &shell_argv_owned {
                argv_ptrs.push(a.as_ptr());
            }
            argv_ptrs.push(std::ptr::null());
            libc::execv(c_shell.as_ptr(), argv_ptrs.as_ptr());
            libc::_exit(1);
        },
        child_pid => Ok(child_pid),
    }
}
