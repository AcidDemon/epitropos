mod asciicinema;
mod config;
mod env;
mod event_loop;
mod log;
mod process;
mod pty;
mod session_id;
mod signals;

// epitropos — PTY-proxy for tamper-proof session recording.
//
// Launched by PAM (pam_exec.so) as a session wrapper. Allocates a PTY,
// spawns the user's shell on the slave side, and bridges all I/O while
// generating an asciicinema v2 stream piped to katagrapho for encrypted
// storage.
//
// Runs setuid root during setup to fork the shell as the target user,
// then drops to an unprivileged session-proxy UID. The recorded user
// cannot kill, signal, or ptrace this process.

use std::ffi::CString;
use std::os::unix::io::{FromRawFd, RawFd};

use config::FailMode;

fn main() {
    if let Err(msg) = run() {
        eprintln!("epitropos: {msg}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // 1. Sanitize environment
    env::sanitize();

    // 2. Load configuration
    let cfg = config::load()?;

    // 3. Resolve calling user
    let user = process::resolve_caller()?;

    // 4. Nesting check: if already inside a session and PAM_SERVICE is not
    //    in always_record_services, skip recording and just exec the shell.
    if std::env::var("EPITROPOS_SESSION_ID").is_ok() {
        let pam_service = std::env::var("PAM_SERVICE").unwrap_or_default();
        if !cfg
            .nesting
            .always_record_services
            .iter()
            .any(|s| s == &pam_service)
        {
            let existing_session = std::env::var("EPITROPOS_SESSION_ID").unwrap_or_default();
            log::nesting_skip(&existing_session, &user.username, &pam_service);
            process::become_user(&user)?;
            exec_shell(&user)?;
            unreachable!();
        }
    }

    // 5. Determine fail policy
    let fail_mode = resolve_fail_mode(&cfg.fail_policy, &user.username);

    // 6. Generate session ID
    let session_id = session_id::generate()?;
    log::session_start(&session_id, &user.username);

    // 7. Spawn katagrapho
    let (kata_pid, pipe_write) = match process::spawn_katagrapho(
        &cfg.general.katagrapho_path,
        &session_id,
        &cfg.encryption.recipient_file,
    ) {
        Ok(v) => v,
        Err(reason) => {
            return handle_startup_failure(fail_mode, &user, &reason);
        }
    };

    // 8. Open PTY
    let pty = match pty::Pty::open() {
        Ok(p) => p,
        Err(reason) => {
            unsafe {
                libc::kill(kata_pid, libc::SIGTERM);
                libc::close(pipe_write);
            }
            return handle_startup_failure(fail_mode, &user, &reason);
        }
    };

    // 9. Get terminal size from stdin, set on pty master (default 80x24)
    let (cols, rows) = pty::get_terminal_size(0).unwrap_or((80, 24));
    let _ = pty::set_terminal_size(pty.master, cols, rows);

    // 10. Create recorder and write header to pipe
    let recorder = asciicinema::Recorder::new();
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(pipe_write) };
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
        recorder.write_header(&mut file, cols, rows, &user.shell, &term)?;
        std::mem::forget(file); // Don't close the fd
    }

    // 11. Open slave side of PTY
    let slave_fd = pty.open_slave()?;

    // 12. Set up signal handlers
    let signal_state = signals::SignalState::setup()?;

    // 13. Fork shell
    let shell_env = env::build_shell_env(&session_id);
    let shell_pid = process::spawn_shell(slave_fd, &user, &shell_env)?;

    // 14. Close slave fd in parent
    unsafe {
        libc::close(slave_fd);
    }

    // 15. Drop privileges to session proxy
    process::drop_privileges(cfg.general.session_proxy_uid, cfg.general.session_proxy_gid)?;

    // 16. Set terminal to raw mode
    let saved_termios = set_raw_mode(0)?;

    // 17. Run event loop
    let loop_cfg = event_loop::LoopConfig {
        user_stdin: 0,
        user_stdout: 1,
        pty_master: pty.master,
        pipe_write,
        signal_pipe: signal_state.pipe_read,
        shell_pid,
        record_input: cfg.general.record_input,
    };
    let result = event_loop::run(&loop_cfg, &signal_state, &recorder);

    // 18. Restore terminal
    restore_terminal(0, &saved_termios);

    // 19. Close pipe_write to signal EOF to katagrapho
    unsafe {
        libc::close(pipe_write);
    }

    // 20. Wait for katagrapho to exit
    unsafe {
        let mut status: libc::c_int = 0;
        libc::waitpid(kata_pid, &mut status, 0);
    }

    // 21. If recording failed, log and run failure hook
    if result.recording_failed {
        let reason = result
            .failure_reason
            .as_deref()
            .unwrap_or("unknown error");
        eprintln!("epitropos: recording failed: {reason}");
        log::recording_interrupted(&session_id, &user.username, reason, 0.0);
        run_failure_hook(&cfg, &session_id, &user.username, &result.failure_reason);
    }

    // 22. Exit with shell's exit code
    log::session_end(&session_id, &user.username, 0.0, result.shell_exit_code);
    std::process::exit(result.shell_exit_code);
}

/// Resolve the effective fail mode for the given user based on group membership.
/// closed_for_groups has higher priority than open_for_groups.
fn resolve_fail_mode(policy: &config::FailPolicy, username: &str) -> FailMode {
    // Check closed_for_groups first (higher priority)
    for group in &policy.closed_for_groups {
        if process::user_in_group(username, group) {
            return FailMode::Closed;
        }
    }

    // Then check open_for_groups
    for group in &policy.open_for_groups {
        if process::user_in_group(username, group) {
            return FailMode::Open;
        }
    }

    // Fall back to default
    policy.default.clone()
}

/// Handle a startup failure according to the fail mode policy.
fn handle_startup_failure(
    fail_mode: FailMode,
    user: &process::UserInfo,
    reason: &str,
) -> Result<(), String> {
    match fail_mode {
        FailMode::Closed => Err(format!("session recording failed: {reason}")),
        FailMode::Open => {
            eprintln!("epitropos: warning: recording unavailable ({reason}), proceeding without recording");
            process::become_user(user)?;
            exec_shell(user)?;
            unreachable!();
        }
    }
}

/// Exec the user's shell as a login shell (argv0 = "-bash" style).
fn exec_shell(user: &process::UserInfo) -> Result<(), String> {
    let c_shell =
        CString::new(user.shell.as_bytes()).map_err(|e| format!("invalid shell path: {e}"))?;

    let base = user
        .shell
        .rsplit('/')
        .next()
        .unwrap_or(user.shell.as_str());
    let login_name = format!("-{base}");
    let c_login_name =
        CString::new(login_name.as_bytes()).map_err(|e| format!("invalid login name: {e}"))?;

    let argv: &[*const libc::c_char] = &[c_login_name.as_ptr(), std::ptr::null()];
    unsafe {
        libc::execv(c_shell.as_ptr(), argv.as_ptr());
    }

    Err(format!(
        "execv({}) failed: {}",
        user.shell,
        std::io::Error::last_os_error()
    ))
}

/// Set terminal to raw mode, returning the original termios for later restoration.
fn set_raw_mode(fd: RawFd) -> Result<libc::termios, String> {
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } < 0 {
        return Err(format!(
            "tcgetattr failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut raw = orig;
    unsafe {
        libc::cfmakeraw(&mut raw);
    }

    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } < 0 {
        return Err(format!(
            "tcsetattr failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(orig)
}

/// Restore terminal to the saved termios state.
fn restore_terminal(fd: RawFd, termios: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, termios);
    }
}

/// Run the on_recording_failure hook if configured.
fn run_failure_hook(
    cfg: &config::Config,
    session_id: &str,
    username: &str,
    reason: &Option<String>,
) {
    let hook = &cfg.hooks.on_recording_failure;
    if hook.is_empty() {
        return;
    }

    let c_hook = match CString::new(hook.as_bytes()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let c_session_id_flag = CString::new("--session-id").unwrap();
    let c_session_id = match CString::new(session_id) {
        Ok(s) => s,
        Err(_) => return,
    };
    let c_username_flag = CString::new("--username").unwrap();
    let c_username = match CString::new(username) {
        Ok(s) => s,
        Err(_) => return,
    };
    let c_reason_flag = CString::new("--reason").unwrap();
    let reason_str = reason.as_deref().unwrap_or("unknown");
    let c_reason = match CString::new(reason_str) {
        Ok(s) => s,
        Err(_) => return,
    };

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            eprintln!("epitropos: fork for failure hook failed");
        }
        0 => {
            // Child: exec the hook
            let argv: &[*const libc::c_char] = &[
                c_hook.as_ptr(),
                c_session_id_flag.as_ptr(),
                c_session_id.as_ptr(),
                c_username_flag.as_ptr(),
                c_username.as_ptr(),
                c_reason_flag.as_ptr(),
                c_reason.as_ptr(),
                std::ptr::null(),
            ];
            unsafe {
                libc::execv(c_hook.as_ptr(), argv.as_ptr());
                libc::_exit(1);
            }
        }
        child_pid => {
            // Parent: wait up to 5 seconds
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(5);
            loop {
                let mut status: libc::c_int = 0;
                let ret = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                if ret > 0 {
                    break;
                }
                if ret < 0 {
                    break;
                }
                if start.elapsed() >= timeout {
                    eprintln!("epitropos: failure hook timed out, killing");
                    unsafe {
                        libc::kill(child_pid, libc::SIGKILL);
                        libc::waitpid(child_pid, &mut status, 0);
                    }
                    break;
                }
                // Brief sleep to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}
