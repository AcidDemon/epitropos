use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;

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

pub fn try_session_lock(audit_session_id: u32) -> Result<bool, String> {
    let lock_path = format!("{LOCK_DIR}/session.{audit_session_id}.lock");
    let c_path = CString::new(lock_path.as_str()).unwrap();

    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o600,
        )
    };

    if fd >= 0 {
        unsafe { libc::close(fd) };
        Ok(true)
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            Ok(false)
        } else {
            Err(format!("session lock: {err}"))
        }
    }
}

pub fn release_session_lock(audit_session_id: u32) {
    let lock_path = format!("{LOCK_DIR}/session.{audit_session_id}.lock");
    let _ = std::fs::remove_file(lock_path);
}

/// Check if we're inside an existing epitropos session.
/// Uses audit session lock first, falls back to env var.
pub fn is_nested_session(audit_session_id: Option<u32>) -> bool {
    if let Some(asid) = audit_session_id {
        match try_session_lock(asid) {
            Ok(true) => return false, // we got the lock, not nested
            Ok(false) => return true, // lock held, nested
            Err(_) => {}              // fall through to env check
        }
    }
    // Fallback: env var (user can't spoof this in a setuid context because
    // env::sanitize already ran and only passes through known-safe vars)
    std::env::var("EPITROPOS_SESSION_ID").is_ok()
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

/// Harden the proxy process: disable ptrace, core dumps.
pub fn harden_proxy() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64);
        libc::prctl(libc::PR_SET_PTRACER, 0_u64, 0_u64, 0_u64, 0_u64);
    }
}

/// Drop the shell child back to the real user identity.
/// Uses setresuid/setresgid to irrevocably drop all privilege.
pub fn drop_to_real_user() -> Result<(), String> {
    let ruid = unsafe { libc::getuid() };
    let rgid = unsafe { libc::getgid() };

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

            for (key, _) in std::env::vars_os() {
                std::env::remove_var(&key);
            }
            for (k, v) in shell_env {
                std::env::set_var(k, v);
            }

            let mut argv_ptrs: Vec<*const libc::c_char> = vec![argv0.as_ptr()];
            for arg in &extra_args {
                argv_ptrs.push(arg.as_ptr());
            }
            argv_ptrs.push(std::ptr::null());
            libc::execv(c_shell.as_ptr(), argv_ptrs.as_ptr());
            libc::_exit(1);
        },
        child_pid => Ok(child_pid),
    }
}
