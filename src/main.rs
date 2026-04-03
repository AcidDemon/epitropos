mod asciicinema;
mod backend;
mod buffer;
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
    process::sanitize_std_fds();
    env::sanitize();

    let cfg = config::load()?;
    let user = process::resolve_caller()?;

    // Duplicate session prevention via audit session ID lock files.
    let audit_session_id = process::get_audit_session_id();
    if let Some(asid) = audit_session_id {
        match process::try_session_lock(asid) {
            Ok(true) => {}
            Ok(false) => {
                let real_shell = cfg.shell.resolve(&user.username);
                log::nesting_skip(&asid.to_string(), &user.username, "audit-session-locked");
                process::become_user(&user)?;
                exec_shell_path(real_shell)?;
                unreachable!();
            }
            Err(e) => {
                eprintln!("epitropos: session lock warning: {e}");
            }
        }
    }

    let fail_mode = resolve_fail_mode(&cfg.fail_policy, &user.username);
    let session_id = session_id::generate()?;
    log::session_start(&session_id, &user.username);

    // argv0 symlink encoding overrides config shell.
    let real_shell =
        decode_shell_from_argv0().unwrap_or_else(|| cfg.shell.resolve(&user.username).to_string());

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

    let (cols, rows) = pty::get_terminal_size(0).unwrap_or((80, 24));
    let _ = pty::set_terminal_size(pty.master, cols, rows);

    if !cfg.notice.text.is_empty() && unsafe { libc::isatty(1) } == 1 {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), cfg.notice.text.as_bytes());
    }

    let meta = asciicinema::Metadata {
        hostname: asciicinema::get_hostname(),
        boot_id: asciicinema::get_boot_id(),
        audit_session_id,
        recording_id: session_id.clone(),
    };

    let recorder = asciicinema::Recorder::new();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
    {
        // Write header to pipe (katagrapho).
        let mut file = unsafe { std::fs::File::from_raw_fd(pipe_write) };
        recorder.write_header(&mut file, cols, rows, &real_shell, &term, &meta)?;
        std::mem::forget(file);
    }

    // Write header to additional backends.
    for wc in &cfg.writers {
        let mut w: Box<dyn std::io::Write> = match wc {
            config::WriterConfig::Syslog { facility } => {
                let fac = match facility.as_str() {
                    "auth" => libc::LOG_AUTH,
                    "authpriv" => libc::LOG_AUTHPRIV,
                    "local0" => libc::LOG_LOCAL0,
                    "local1" => libc::LOG_LOCAL1,
                    "local2" => libc::LOG_LOCAL2,
                    "local3" => libc::LOG_LOCAL3,
                    "local4" => libc::LOG_LOCAL4,
                    "local5" => libc::LOG_LOCAL5,
                    "local6" => libc::LOG_LOCAL6,
                    "local7" => libc::LOG_LOCAL7,
                    _ => libc::LOG_AUTHPRIV,
                };
                Box::new(backend::SyslogWriter::new("epitropos", fac))
            }
            config::WriterConfig::Journal { identifier } => {
                Box::new(backend::JournaldWriter::new(identifier))
            }
            config::WriterConfig::File { path } => match backend::FileWriter::new(path) {
                Ok(fw) => Box::new(fw),
                Err(e) => {
                    eprintln!("epitropos: backend file {path}: {e}");
                    continue;
                }
            },
        };
        let _ = recorder.write_header(&mut *w, cols, rows, &real_shell, &term, &meta);
    }

    let slave_fd = pty.open_slave()?;
    let signal_state = signals::SignalState::setup()?;

    let command = detect_command();
    let shell_env = env::build_shell_env(&session_id);
    let shell_pid =
        process::spawn_shell(slave_fd, &user, &real_shell, &shell_env, command.as_deref())?;

    unsafe { libc::close(slave_fd) };
    utmp::add_entry(&user.username, &pty.slave_path, shell_pid);

    let proxy_uid = process::resolve_uid(&cfg.general.session_proxy_user)?;
    let proxy_gid = process::resolve_gid(&cfg.general.session_proxy_group)?;
    process::drop_privileges(proxy_uid, proxy_gid)?;

    let is_tty = unsafe { libc::isatty(0) } == 1;
    let saved_termios = if is_tty { Some(set_raw_mode(0)?) } else { None };

    let loop_cfg = event_loop::LoopConfig {
        user_stdin: 0,
        user_stdout: 1,
        pty_master: pty.master,
        signal_pipe: signal_state.pipe_read,
        shell_pid,
        record_input: cfg.general.record_input,
    };
    let mut rate_limiter =
        rate_limit::RateLimiter::new(cfg.limit.rate, cfg.limit.burst, cfg.limit.action.clone());
    let latency = cfg.general.latency.unwrap_or(10);
    let mut write_buf = buffer::FlushBuffer::new(pipe_write, latency);
    let result = event_loop::run(
        &loop_cfg,
        &signal_state,
        &recorder,
        &mut rate_limiter,
        &mut write_buf,
    );

    if let Some(ref termios) = saved_termios {
        restore_terminal(0, termios);
    }

    unsafe { libc::close(pipe_write) };
    unsafe {
        let mut status: libc::c_int = 0;
        libc::waitpid(kata_pid, &mut status, 0);
    }

    if result.recording_failed {
        let reason = result.failure_reason.as_deref().unwrap_or("unknown error");
        eprintln!("epitropos: recording failed: {reason}");
        log::recording_interrupted(&session_id, &user.username, reason, 0.0);
        run_failure_hook(&cfg, &session_id, &user.username, &result.failure_reason);
    }

    utmp::remove_entry(&pty.slave_path, shell_pid);
    if let Some(asid) = audit_session_id {
        process::release_session_lock(asid);
    }

    log::session_end(&session_id, &user.username, 0.0, result.shell_exit_code);
    std::process::exit(result.shell_exit_code);
}

fn resolve_fail_mode(policy: &config::FailPolicy, username: &str) -> FailMode {
    for group in &policy.closed_for_groups {
        if process::user_in_group(username, group) {
            return FailMode::Closed;
        }
    }
    for group in &policy.open_for_groups {
        if process::user_in_group(username, group) {
            return FailMode::Open;
        }
    }
    policy.default.clone()
}

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

fn exec_shell_path(shell_path: &str) -> Result<(), String> {
    let c_shell =
        CString::new(shell_path.as_bytes()).map_err(|e| format!("invalid shell path: {e}"))?;
    let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
    let login_name = format!("-{base}");
    let c_login_name =
        CString::new(login_name.as_bytes()).map_err(|e| format!("invalid login name: {e}"))?;

    let argv: &[*const libc::c_char] = &[c_login_name.as_ptr(), std::ptr::null()];
    unsafe { libc::execv(c_shell.as_ptr(), argv.as_ptr()) };
    Err(format!(
        "execv({}) failed: {}",
        shell_path,
        std::io::Error::last_os_error()
    ))
}

/// Decode shell from argv0: "epitropos-shell-bin-zsh" → "/bin/zsh"
fn decode_shell_from_argv0() -> Option<String> {
    let argv0 = std::env::args().next()?;
    let basename = argv0.rsplit('/').next().unwrap_or(&argv0);
    let idx = basename.find("-shell-")?;
    let encoded = &basename[idx + 7..];
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

fn detect_command() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "-c" {
        return Some(args[2..].join(" "));
    }
    std::env::var("SSH_ORIGINAL_COMMAND").ok()
}

fn set_raw_mode(fd: RawFd) -> Result<libc::termios, String> {
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } < 0 {
        return Err(format!(
            "tcgetattr failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut raw = orig;
    unsafe { libc::cfmakeraw(&mut raw) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } < 0 {
        return Err(format!(
            "tcsetattr failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(orig)
}

fn restore_terminal(fd: RawFd, termios: &libc::termios) {
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, termios) };
}

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
    let c_sid_flag = CString::new("--session-id").unwrap();
    let c_sid = match CString::new(session_id) {
        Ok(s) => s,
        Err(_) => return,
    };
    let c_user_flag = CString::new("--username").unwrap();
    let c_user = match CString::new(username) {
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
        -1 => {}
        0 => {
            let argv: &[*const libc::c_char] = &[
                c_hook.as_ptr(),
                c_sid_flag.as_ptr(),
                c_sid.as_ptr(),
                c_user_flag.as_ptr(),
                c_user.as_ptr(),
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
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(5);
            loop {
                let mut status: libc::c_int = 0;
                let ret = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                if ret != 0 {
                    break;
                }
                if start.elapsed() >= timeout {
                    unsafe {
                        libc::kill(child_pid, libc::SIGKILL);
                        libc::waitpid(child_pid, &mut status, 0);
                    }
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}
