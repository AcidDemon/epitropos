mod asciicinema;
mod config;
mod env;
mod event_loop;
mod log;
mod process;
mod pty;
mod rate_limit;
mod session_id;
mod signals;
mod utmp;

// epitropos — PTY-proxy for tamper-proof session recording.
//
// Installed as the user's login shell (replacing /bin/bash etc.).
// When any login process (sshd, login, su, sudo) spawns the "shell",
// it runs epitropos instead. Epitropos allocates a nested PTY, spawns
// the user's real shell (from config) on the slave side, and bridges
// all I/O while generating an asciicinema v2 stream piped to katagrapho.
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
    // 1. Sanitize fds 0/1/2 — prevent fd hijacking if any are closed.
    process::sanitize_std_fds();

    // 2. Sanitize environment
    env::sanitize();

    // 3. Load configuration
    let cfg = config::load()?;

    // 4. Resolve calling user
    let user = process::resolve_caller()?;

    // 5. Duplicate session prevention via Linux audit session ID.
    //    If another epitropos instance already holds the lock for this
    //    audit session, skip recording and exec the real shell directly.
    //    This prevents double-recording for su/sudo/subshells.
    let audit_session_id = process::get_audit_session_id();
    if let Some(asid) = audit_session_id {
        match process::try_session_lock(asid) {
            Ok(true) => {
                // We acquired the lock — proceed with recording.
            }
            Ok(false) => {
                // Lock held by another instance — skip recording.
                let real_shell = cfg.shell.resolve(&user.username);
                log::nesting_skip(&asid.to_string(), &user.username, "audit-session-locked");
                process::become_user(&user)?;
                exec_shell_path(real_shell)?;
                unreachable!();
            }
            Err(e) => {
                // Lock dir missing or other error — proceed anyway (fail-open for locking).
                eprintln!("epitropos: session lock warning: {e}");
            }
        }
    }

    // 6. Determine fail policy
    let fail_mode = resolve_fail_mode(&cfg.fail_policy, &user.username);

    // 7. Generate session ID
    let session_id = session_id::generate()?;
    log::session_start(&session_id, &user.username);

    // 7. Resolve real shell: argv0 symlink encoding overrides config.
    let real_shell =
        decode_shell_from_argv0().unwrap_or_else(|| cfg.shell.resolve(&user.username).to_string());

    // 8. Spawn katagrapho
    let recipient = if cfg.encryption.enabled {
        Some(cfg.encryption.recipient_file.as_str())
    } else {
        None
    };
    let (kata_pid, pipe_write) =
        match process::spawn_katagrapho(&cfg.general.katagrapho_path, &session_id, recipient) {
            Ok(v) => v,
            Err(reason) => {
                return handle_startup_failure(fail_mode, &user, &real_shell, &reason);
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
            return handle_startup_failure(fail_mode, &user, &real_shell, &reason);
        }
    };

    // 9. Get terminal size from stdin, set on pty master (default 80x24)
    let (cols, rows) = pty::get_terminal_size(0).unwrap_or((80, 24));
    let _ = pty::set_terminal_size(pty.master, cols, rows);

    // 10. Print notice banner
    if !cfg.notice.text.is_empty() {
        let is_tty = unsafe { libc::isatty(1) } == 1;
        if is_tty {
            let _ = std::io::Write::write_all(&mut std::io::stderr(), cfg.notice.text.as_bytes());
        }
    }

    // 11. Build recording metadata
    let meta = asciicinema::Metadata {
        hostname: asciicinema::get_hostname(),
        boot_id: asciicinema::get_boot_id(),
        audit_session_id,
        recording_id: session_id.clone(),
    };

    // 12. Create recorder and write header to pipe
    let recorder = asciicinema::Recorder::new();
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(pipe_write) };
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
        recorder.write_header(&mut file, cols, rows, &real_shell, &term, &meta)?;
        std::mem::forget(file);
    }

    // 11. Open slave side of PTY
    let slave_fd = pty.open_slave()?;

    // 12. Set up signal handlers
    let signal_state = signals::SignalState::setup()?;

    // 14. Fork shell
    // Detect command to run: sshd invokes the login shell as "shell -c command",
    // so check argv for -c. Also check SSH_ORIGINAL_COMMAND as fallback.
    let command = detect_command();
    let shell_env = env::build_shell_env(&session_id);
    let shell_pid =
        process::spawn_shell(slave_fd, &user, &real_shell, &shell_env, command.as_deref())?;

    unsafe { libc::close(slave_fd) };
    utmp::add_entry(&user.username, &pty.slave_path, shell_pid);

    let proxy_uid = process::resolve_uid(&cfg.general.session_proxy_user)?;
    let proxy_gid = process::resolve_gid(&cfg.general.session_proxy_group)?;
    process::drop_privileges(proxy_uid, proxy_gid)?;

    // 16. Set terminal to raw mode (only if stdin is a terminal)
    let is_tty = unsafe { libc::isatty(0) } == 1;
    let saved_termios = if is_tty { Some(set_raw_mode(0)?) } else { None };

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
    let mut rate_limiter =
        rate_limit::RateLimiter::new(cfg.limit.rate, cfg.limit.burst, cfg.limit.action.clone());
    let result = event_loop::run(&loop_cfg, &signal_state, &recorder, &mut rate_limiter);

    // 18. Restore terminal (only if we set raw mode)
    if let Some(ref termios) = saved_termios {
        restore_terminal(0, termios);
    }

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
        let reason = result.failure_reason.as_deref().unwrap_or("unknown error");
        eprintln!("epitropos: recording failed: {reason}");
        log::recording_interrupted(&session_id, &user.username, reason, 0.0);
        run_failure_hook(&cfg, &session_id, &user.username, &result.failure_reason);
    }

    // 22. Release session lock
    utmp::remove_entry(&pty.slave_path, shell_pid);
    if let Some(asid) = audit_session_id {
        process::release_session_lock(asid);
    }

    // 23. Exit with shell's exit code
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
    real_shell: &str,
    reason: &str,
) -> Result<(), String> {
    match fail_mode {
        FailMode::Closed => Err(format!("session recording failed: {reason}")),
        FailMode::Open => {
            eprintln!(
                "epitropos: warning: recording unavailable ({reason}), proceeding without recording"
            );
            process::become_user(user)?;
            exec_shell_path(real_shell)?;
            unreachable!();
        }
    }
}

/// Exec a shell as a login shell (argv0 = "-bash" style).
fn exec_shell_path(shell_path: &str) -> Result<(), String> {
    let c_shell =
        CString::new(shell_path.as_bytes()).map_err(|e| format!("invalid shell path: {e}"))?;

    let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
    let login_name = format!("-{base}");
    let c_login_name =
        CString::new(login_name.as_bytes()).map_err(|e| format!("invalid login name: {e}"))?;

    let argv: &[*const libc::c_char] = &[c_login_name.as_ptr(), std::ptr::null()];
    unsafe {
        libc::execv(c_shell.as_ptr(), argv.as_ptr());
    }

    Err(format!(
        "execv({}) failed: {}",
        shell_path,
        std::io::Error::last_os_error()
    ))
}

/// Decode shell path from argv[0] if it contains "-shell-".
/// e.g. "epitropos-shell-bin-zsh" -> "/bin/zsh"
/// Encoding: / becomes -, literal - is \-, literal \ is \\.
fn decode_shell_from_argv0() -> Option<String> {
    let argv0 = std::env::args().next()?;
    let basename = argv0.rsplit('/').next().unwrap_or(&argv0);
    let marker = "-shell-";
    let idx = basename.find(marker)?;
    let encoded = &basename[idx + marker.len()..];
    if encoded.is_empty() {
        return None;
    }

    let mut decoded = String::new();
    let mut chars = encoded.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    decoded.push(next);
                    chars.next();
                }
            }
            '-' => decoded.push('/'),
            _ => decoded.push(ch),
        }
    }
    Some(decoded)
}

/// Detect if we were invoked with a command to run.
/// sshd invokes the login shell as: shell -c "command"
/// Also check SSH_ORIGINAL_COMMAND as fallback.
fn detect_command() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    // Check for "-c" "command" in argv (standard shell invocation)
    if args.len() >= 3 && args[1] == "-c" {
        return Some(args[2..].join(" "));
    }
    // Fallback: SSH_ORIGINAL_COMMAND
    std::env::var("SSH_ORIGINAL_COMMAND").ok()
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
