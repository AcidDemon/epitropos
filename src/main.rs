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
mod seccomp;
mod session_id;
mod signals;
mod utmp;

use std::ffi::CString;
use std::os::unix::io::{FromRawFd, RawFd};

use config::FailMode;

// Pre-forked hook runner. Spawned before seccomp so the helper process
// can fork+exec without needing those syscalls in the sandbox.
struct HookRunner {
    pipe_write: RawFd,
    pid: libc::pid_t,
}

impl HookRunner {
    fn spawn(cfg: &config::Config, session_id: &str, username: &str) -> Option<Self> {
        let hook = &cfg.hooks.on_recording_failure;
        if hook.is_empty() {
            return None;
        }

        let mut fds: [RawFd; 2] = [-1, -1];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return None;
        }
        let (pipe_read, pipe_write) = (fds[0], fds[1]);

        let c_hook = match CString::new(hook.as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                unsafe { libc::close(pipe_read); libc::close(pipe_write); }
                return None;
            }
        };
        let c_sid = CString::new(session_id).ok()?;
        let c_user = CString::new(username).ok()?;

        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                unsafe { libc::close(pipe_read); libc::close(pipe_write); }
                None
            }
            0 => unsafe {
                libc::close(pipe_write);

                if crate::process::drop_to_real_user().is_err() {
                    libc::_exit(1);
                }

                let mut reason_buf = [0u8; 256];
                let n = libc::read(pipe_read, reason_buf.as_mut_ptr() as *mut libc::c_void, reason_buf.len());
                libc::close(pipe_read);

                if n <= 0 {
                    libc::_exit(0);
                }

                let reason = std::str::from_utf8(&reason_buf[..n as usize]).unwrap_or("unknown");
                let c_reason_flag = CString::new("--reason").unwrap();
                let c_reason = CString::new(reason).unwrap_or_default();
                let c_sid_flag = CString::new("--session-id").unwrap();
                let c_user_flag = CString::new("--username").unwrap();

                crate::pty::close_fds_above(3);

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
                libc::execv(c_hook.as_ptr(), argv.as_ptr());
                libc::_exit(1);
            },
            child_pid => {
                unsafe { libc::close(pipe_read) };
                Some(HookRunner { pipe_write, pid: child_pid })
            }
        }
    }

    fn trigger(&self, reason: &str) {
        let bytes = reason.as_bytes();
        let len = bytes.len().min(256);
        unsafe {
            libc::write(self.pipe_write, bytes.as_ptr() as *const libc::c_void, len);
        }
    }
}

impl Drop for HookRunner {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.pipe_write);
            let mut status: libc::c_int = 0;
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(5);
            loop {
                let ret = libc::waitpid(self.pid, &mut status, libc::WNOHANG);
                if ret != 0 { break; }
                if start.elapsed() >= timeout {
                    libc::kill(self.pid, libc::SIGKILL);
                    libc::waitpid(self.pid, &mut status, 0);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

fn main() {
    if let Err(msg) = run() {
        eprintln!("epitropos: {msg}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    process::sanitize_std_fds();
    process::verify_suid_context()?;
    env::sanitize();

    let cfg = config::load()?;
    let user = process::resolve_caller()?;

    // Nesting: flock-based audit session lock.
    let audit_session_id = process::get_audit_session_id();
    let _session_lock = match process::is_nested_session(audit_session_id) {
        Some(guard) => Some(guard),
        None if audit_session_id.is_some() => {
            let real_shell = cfg.shell.resolve(&user.username);
            log::nesting_skip(
                &audit_session_id.map_or("none".into(), |id| id.to_string()),
                &user.username,
                "nested",
            );
            process::drop_to_real_user()?;
            exec_shell_path(real_shell)?;
            unreachable!();
        }
        None => None,
    };

    let fail_mode = resolve_fail_mode(&cfg.fail_policy, &user.username);
    let session_id = session_id::generate()?;
    log::session_start(&session_id, &user.username);

    // Shell resolution: argv0 symlink > config. Validate against allowlist.
    let real_shell = resolve_shell(&cfg, &user.username);

    let recipient = if cfg.encryption.enabled {
        Some(cfg.encryption.recipient_file.as_str())
    } else {
        None
    };
    let (kata_pid, pipe_write) =
        match process::spawn_katagrapho(&cfg.general.katagrapho_path, &session_id, recipient) {
            Ok(v) => v,
            Err(reason) => {
                return handle_startup_failure(fail_mode, &real_shell, &reason);
            }
        };

    let pty = match pty::Pty::open() {
        Ok(p) => p,
        Err(reason) => {
            unsafe {
                libc::kill(kata_pid, libc::SIGTERM);
                libc::close(pipe_write);
            }
            return handle_startup_failure(fail_mode, &real_shell, &reason);
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

    // Write header to pipe. Use dup to avoid ownership issues.
    let header_fd = unsafe { libc::dup(pipe_write) };
    if header_fd >= 0 {
        let mut file = unsafe { std::fs::File::from_raw_fd(header_fd) };
        let _ = recorder.write_header(&mut file, cols, rows, &real_shell, &term, &meta);
        // file drops here, closing header_fd (which is the dup, not pipe_write)
    }

    let mut extra_writers: Vec<Box<dyn std::io::Write>> = Vec::new();
    for wc in &cfg.writers {
        let w: Box<dyn std::io::Write> = match wc {
            config::WriterConfig::Syslog { facility } => Box::new(backend::SyslogWriter::new(
                "epitropos",
                parse_syslog_facility(facility),
            )),
            config::WriterConfig::Journal { identifier } => {
                Box::new(backend::JournaldWriter::new(identifier))
            }
            config::WriterConfig::File { path } => match backend::FileWriter::new(path) {
                Ok(fw) => Box::new(fw),
                Err(e) => {
                    eprintln!("epitropos: backend {path}: {e}");
                    continue;
                }
            },
        };
        extra_writers.push(w);
    }
    let mut extra = backend::MultiWriter::new(extra_writers);
    let _ = recorder.write_header(&mut extra, cols, rows, &real_shell, &term, &meta);

    let slave_fd = pty.open_slave()?;
    let signal_state = signals::SignalState::setup()?;

    let command = detect_command();
    let shell_env = env::build_shell_env(&session_id);
    let ns_exec = if std::path::Path::new(&cfg.general.ns_exec_path).exists() {
        Some(cfg.general.ns_exec_path.as_str())
    } else {
        eprintln!("epitropos: ns_exec not found at {}, no PID isolation", cfg.general.ns_exec_path);
        None
    };
    let shell_pid = process::spawn_shell(slave_fd, &real_shell, &shell_env, command.as_deref(), ns_exec)?;

    unsafe { libc::close(slave_fd) };
    utmp::add_entry(&user.username, &pty.slave_path, shell_pid);

    // Spawn hook runner BEFORE seccomp so it can fork+exec.
    let hook_runner = HookRunner::spawn(&cfg, &session_id, &user.username);

    // Proxy already runs as session-proxy (setuid). Just harden.
    process::harden_proxy()?;

    seccomp::install_filter();

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
        &mut extra,
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
        let reason = result.failure_reason.as_deref().unwrap_or("unknown");
        eprintln!("epitropos: recording failed: {reason}");
        log::recording_interrupted(&session_id, &user.username, reason, 0.0);
        if let Some(ref runner) = hook_runner {
            runner.trigger(reason);
        }
    }

    utmp::remove_entry(&pty.slave_path, shell_pid);
    // _session_lock OwnedFd drops here, releasing the flock automatically.

    log::session_end(&session_id, &user.username, 0.0, result.shell_exit_code);
    std::process::exit(result.shell_exit_code);
}

/// Resolve shell from argv0 symlink or config, validate against allowed shells.
fn resolve_shell(cfg: &config::Config, username: &str) -> String {
    if let Some(decoded) = decode_shell_from_argv0() {
        if !decoded.starts_with('/') {
            eprintln!("epitropos: ignoring non-absolute argv0 shell: {decoded}");
        } else if decoded.contains("..") {
            eprintln!("epitropos: ignoring argv0 shell with ..: {decoded}");
        } else {
            // Validate: must be the default shell or in the per-user map.
            let allowed =
                cfg.shell.default == decoded || cfg.shell.users.values().any(|s| s == &decoded);
            if allowed {
                return decoded;
            }
            eprintln!("epitropos: argv0 shell not in config allowlist: {decoded}");
        }
    }
    cfg.shell.resolve(username).to_string()
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
    real_shell: &str,
    reason: &str,
) -> Result<(), String> {
    match fail_mode {
        FailMode::Closed => Err(format!("recording failed: {reason}")),
        FailMode::Open => {
            eprintln!("epitropos: proceeding without recording ({reason})");
            process::drop_to_real_user()?;
            exec_shell_path(real_shell)?;
            unreachable!();
        }
    }
}

fn exec_shell_path(shell_path: &str) -> Result<(), String> {
    process::drop_to_real_user().ok();
    let c_shell = CString::new(shell_path.as_bytes()).map_err(|_| "null byte in shell")?;
    let base = shell_path.rsplit('/').next().unwrap_or(shell_path);
    let c_argv0 = CString::new(format!("-{base}")).map_err(|_| "null byte in argv0")?;
    let argv: &[*const libc::c_char] = &[c_argv0.as_ptr(), std::ptr::null()];
    unsafe { libc::execv(c_shell.as_ptr(), argv.as_ptr()) };
    Err(format!("execv failed: {}", std::io::Error::last_os_error()))
}

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

fn parse_syslog_facility(s: &str) -> libc::c_int {
    match s {
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
    }
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
        return Err(format!("tcgetattr: {}", std::io::Error::last_os_error()));
    }
    let mut raw = orig;
    unsafe { libc::cfmakeraw(&mut raw) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } < 0 {
        return Err(format!("tcsetattr: {}", std::io::Error::last_os_error()));
    }
    Ok(orig)
}

fn restore_terminal(fd: RawFd, termios: &libc::termios) {
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, termios) };
}

