use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;

const LOCK_DIR: &str = "/var/run/epitropos";

pub struct UserInfo {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub username: String,
}

/// Open /dev/null on any closed stdin/stdout/stderr to prevent fd hijacking.
pub fn sanitize_std_fds() {
    let devnull = CString::new("/dev/null").unwrap();
    for fd in 0..=2 {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            unsafe {
                libc::open(devnull.as_ptr(), libc::O_RDWR);
            }
        }
    }
}

/// Read audit session ID from /proc/self/sessionid. None if unset.
pub fn get_audit_session_id() -> Option<u32> {
    let content = std::fs::read_to_string("/proc/self/sessionid").ok()?;
    let id: u32 = content.trim().parse().ok()?;
    if id == 4294967295 {
        return None;
    }
    Some(id)
}

/// Acquire exclusive session lock. Ok(true)=acquired, Ok(false)=already held.
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
            Err(format!("session lock at '{}': {}", lock_path, err))
        }
    }
}

/// Remove the session lock file.
pub fn release_session_lock(audit_session_id: u32) {
    let lock_path = format!("{LOCK_DIR}/session.{audit_session_id}.lock");
    let _ = std::fs::remove_file(lock_path);
}

/// Look up the calling user's passwd entry and return a `UserInfo`.
pub fn resolve_caller() -> Result<UserInfo, String> {
    let uid = unsafe { libc::getuid() };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(format!(
            "getpwuid({uid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let pw = unsafe { &*pw };

    let username = unsafe {
        CStr::from_ptr(pw.pw_name)
            .to_str()
            .map_err(|e| format!("pw_name is invalid UTF-8: {e}"))?
            .to_owned()
    };
    Ok(UserInfo {
        uid,
        gid: pw.pw_gid,
        username,
    })
}

/// Resolve a username to a UID.
pub fn resolve_uid(username: &str) -> Result<libc::uid_t, String> {
    let c_name = CString::new(username).map_err(|_| "username contains null byte")?;
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return Err(format!("user '{username}' not found"));
    }
    Ok(unsafe { (*pw).pw_uid })
}

/// Resolve a group name to a GID.
pub fn resolve_gid(group_name: &str) -> Result<libc::gid_t, String> {
    let c_name = CString::new(group_name).map_err(|_| "group name contains null byte")?;
    let gr = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if gr.is_null() {
        return Err(format!("group '{group_name}' not found"));
    }
    Ok(unsafe { (*gr).gr_gid })
}

/// Return `true` if `username` appears in the group membership of `group_name`.
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
        let member = unsafe { CStr::from_ptr(member_ptr) };
        if member.to_str().unwrap_or("") == username {
            return true;
        }
        ptr = unsafe { ptr.add(1) };
    }
    false
}

/// Drop from root to `uid`/`gid`, clear supplementary groups, and disable
/// core dumps via `PR_SET_DUMPABLE`.
pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), String> {
    if unsafe { libc::setgid(gid) } < 0 {
        return Err(format!(
            "setgid({gid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
        return Err(format!(
            "setgroups(0) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if unsafe { libc::setuid(uid) } < 0 {
        return Err(format!(
            "setuid({uid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Verify the drop was effective.
    let actual_uid = unsafe { libc::getuid() };
    let actual_gid = unsafe { libc::getgid() };
    if actual_uid != uid {
        return Err(format!(
            "privilege drop verification failed: uid={actual_uid}, expected {uid}"
        ));
    }
    if actual_gid != gid {
        return Err(format!(
            "privilege drop verification failed: gid={actual_gid}, expected {gid}"
        ));
    }

    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64);
        libc::prctl(libc::PR_SET_PTRACER, 0_u64, 0_u64, 0_u64, 0_u64);
    }

    Ok(())
}

/// Switch to the identity described by `user` (gid, supplementary groups, uid).
pub fn become_user(user: &UserInfo) -> Result<(), String> {
    if unsafe { libc::setgid(user.gid) } < 0 {
        return Err(format!(
            "setgid({}) failed: {}",
            user.gid,
            std::io::Error::last_os_error()
        ));
    }

    let c_username =
        CString::new(user.username.as_bytes()).map_err(|e| format!("invalid username: {e}"))?;
    if unsafe { libc::initgroups(c_username.as_ptr(), user.gid) } < 0 {
        return Err(format!(
            "initgroups({}) failed: {}",
            user.username,
            std::io::Error::last_os_error()
        ));
    }

    if unsafe { libc::setuid(user.uid) } < 0 {
        return Err(format!(
            "setuid({}) failed: {}",
            user.uid,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Spawn `katagrapho` with its stdin connected to a pipe.
///
/// Returns `(child_pid, pipe_write_fd)`.  The write end has O_CLOEXEC cleared
/// so the caller can keep it open across future exec calls if needed.
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

    let c_path =
        CString::new(katagrapho_path).map_err(|e| format!("invalid katagrapho path: {e}"))?;
    let c_session_id = CString::new(session_id).map_err(|e| format!("invalid session_id: {e}"))?;

    // Build argv depending on encryption mode.
    let encryption_args: Vec<CString> = if let Some(rf) = recipient_file {
        vec![
            CString::new("--recipient-file").unwrap(),
            CString::new(rf).map_err(|e| format!("invalid recipient_file: {e}"))?,
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
        0 => {
            // Child: wire pipe_read to stdin, then exec katagrapho.
            unsafe {
                if libc::dup2(pipe_read, libc::STDIN_FILENO) < 0 {
                    libc::_exit(1);
                }

                // Build owned argv — all CStrings must live until execv.
                let arg_session_flag = CString::new("--session-id").unwrap();
                let mut argv_owned: Vec<&CStr> = vec![
                    c_path.as_c_str(),
                    arg_session_flag.as_c_str(),
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
            }
        }
        child_pid => {
            // Parent: close the read end; we only need the write end.
            unsafe { libc::close(pipe_read) };

            // Clear O_CLOEXEC from the write end so it survives a future exec
            // in the parent if needed.
            let flags = unsafe { libc::fcntl(pipe_write, libc::F_GETFD) };
            if flags >= 0 {
                unsafe {
                    libc::fcntl(pipe_write, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
            }

            Ok((child_pid, pipe_write))
        }
    }
}

/// Fork and exec the user's shell with the PTY slave as its controlling
/// terminal.  Returns the child PID.
pub fn spawn_shell(
    slave_fd: RawFd,
    user: &UserInfo,
    shell_path: &str,
    shell_env: &[(String, String)],
    command: Option<&str>,
) -> Result<libc::pid_t, String> {
    let c_shell =
        CString::new(shell_path.as_bytes()).map_err(|e| format!("invalid shell path: {e}"))?;

    // Build argv depending on whether we have a command to run.
    let (argv0, extra_args) = if let Some(cmd) = command {
        // Non-interactive: shell -c "command"
        let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
        (
            CString::new(base).unwrap_or_else(|_| CString::new("sh").unwrap()),
            vec![
                CString::new("-c").unwrap(),
                CString::new(cmd).unwrap_or_else(|_| CString::new("").unwrap()),
            ],
        )
    } else {
        // Interactive: login shell with "-bash" style argv0
        let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
        (
            CString::new(format!("-{base}")).unwrap_or_else(|_| CString::new("-sh").unwrap()),
            vec![],
        )
    };

    // PID namespace: unshare before fork so the child is PID 1 in a new ns.
    // Fail silently if unsupported (UID separation still protects us).
    let has_pidns = unsafe { libc::unshare(libc::CLONE_NEWPID) } == 0;

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(format!("fork failed: {}", std::io::Error::last_os_error())),
        0 => unsafe {
            if has_pidns {
                // Private mount ns so we can remount /proc for the new PID ns.
                if libc::unshare(libc::CLONE_NEWNS) == 0 {
                    let proc = c"/proc";
                    let ptype = c"proc";
                    libc::mount(
                        ptype.as_ptr(),
                        proc.as_ptr(),
                        ptype.as_ptr(),
                        0,
                        std::ptr::null(),
                    );
                }
            }

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

            if become_user(user).is_err() {
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
