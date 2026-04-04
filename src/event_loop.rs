use std::os::unix::io::RawFd;

use crate::asciicinema::Recorder;
use crate::buffer::FlushBuffer;
use crate::rate_limit::RateLimiter;
use crate::signals::SignalState;

pub struct LoopConfig {
    pub user_stdin: RawFd,
    pub user_stdout: RawFd,
    pub pty_master: RawFd,
    pub signal_pipe: RawFd,
    pub shell_pid: libc::pid_t,
    pub record_input: bool,
}

pub struct LoopResult {
    pub shell_exit_code: i32,
    pub recording_failed: bool,
    pub failure_reason: Option<String>,
}

/// Write all `data` bytes to `fd`, retrying on partial writes.
fn write_all_fd(fd: RawFd, data: &[u8]) -> Result<(), ()> {
    let mut offset = 0;
    while offset < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[offset..].as_ptr() as *const libc::c_void,
                data.len() - offset,
            )
        };
        if n <= 0 {
            return Err(());
        }
        offset += n as usize;
    }
    Ok(())
}

/// Drain all available output from `pty_master` and forward it to `user_stdout`
/// and the recorder, used before breaking on POLLHUP.
#[allow(clippy::collapsible_if)]
fn drain_pty(
    pty_master: RawFd,
    user_stdout: RawFd,
    writer: &mut FlushBuffer,
    recorder: &Recorder,
    recording_failed: &mut bool,
    failure_reason: &mut Option<String>,
) {
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(pty_master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let data = &buf[..n as usize];
        let _ = write_all_fd(user_stdout, data);
        if !*recording_failed {
            if let Err(e) = recorder.write_output(writer, data) {
                *recording_failed = true;
                *failure_reason = Some(e);
            }
        }
    }
}

/// Reap the shell process, returning its exit code.
fn reap_shell(shell_pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(shell_pid, &mut status, libc::WNOHANG) };
    if ret > 0 {
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        }
    } else {
        1
    }
}

#[allow(clippy::collapsible_if)]
pub fn run(
    cfg: &LoopConfig,
    signals: &SignalState,
    recorder: &Recorder,
    rate_limiter: &mut RateLimiter,
    writer: &mut FlushBuffer,
    extra: &mut dyn std::io::Write,
) -> LoopResult {
    let mut shell_exit_code: i32 = 0;
    let mut recording_failed = false;
    let mut failure_reason: Option<String> = None;
    let mut shell_exited = false;

    // pollfds[0] = user_stdin, pollfds[1] = pty_master, pollfds[2] = signal_pipe
    let mut pollfds = [
        libc::pollfd {
            fd: cfg.user_stdin,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cfg.pty_master,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cfg.signal_pipe,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    'event_loop: loop {
        // Reset revents before polling.
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
        }

        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, -1) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // Unexpected poll error — bail.
            break;
        }

        // --- Signal pipe (pollfds[2]) ---
        if pollfds[2].revents & libc::POLLIN != 0 {
            let (winch, chld, term) = signals.drain();

            if winch {
                // Propagate terminal resize to the PTY.
                if let Ok((cols, rows)) = crate::pty::get_terminal_size(cfg.user_stdin) {
                    let _ = crate::pty::set_terminal_size(cfg.pty_master, cols, rows);
                    if !recording_failed {
                        if let Err(e) = recorder.write_resize(writer, cols, rows) {
                            recording_failed = true;
                            failure_reason = Some(e);
                            break 'event_loop;
                        }
                        let _ = recorder.write_resize(extra, cols, rows);
                    }
                }
            }

            if chld {
                shell_exit_code = reap_shell(cfg.shell_pid);
                shell_exited = true;
            }

            if term {
                // Forward SIGTERM to the shell's entire process group.
                unsafe {
                    libc::kill(-cfg.shell_pid, libc::SIGTERM);
                }
                shell_exited = true;
            }

            if shell_exited {
                break 'event_loop;
            }
        }

        // --- PTY master (pollfds[1]) ---
        // Check POLLHUP before POLLIN so we can drain and then break.
        if pollfds[1].revents & libc::POLLHUP != 0 {
            drain_pty(
                cfg.pty_master,
                cfg.user_stdout,
                writer,
                recorder,
                &mut recording_failed,
                &mut failure_reason,
            );
            // Mark that we still need to reap (blocking wait at end of loop).
            break 'event_loop;
        }

        if pollfds[1].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 65536];
            let n = unsafe {
                libc::read(
                    cfg.pty_master,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                // Shell exited or PTY closed.
                if !shell_exited {
                    shell_exit_code = reap_shell(cfg.shell_pid);
                }
                break 'event_loop;
            }
            let data = &buf[..n as usize];
            let _ = write_all_fd(cfg.user_stdout, data);
            if !recording_failed {
                if rate_limiter.check(data.len()) {
                    if let Err(e) = recorder.write_output(writer, data) {
                        recording_failed = true;
                        failure_reason = Some(e);
                        break 'event_loop;
                    }
                    let _ = recorder.write_output(extra, data);
                } else {
                    let _ = recorder
                        .write_output(writer, b"[epitropos: output suppressed by rate limit]\r\n");
                }
            }
        }

        // --- User stdin (pollfds[0]) ---
        if pollfds[0].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 65536];
            let n = unsafe {
                libc::read(
                    cfg.user_stdin,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n == 0 {
                // EOF / user disconnected.
                break 'event_loop;
            }
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break 'event_loop;
            }
            let data = &buf[..n as usize];
            let _ = write_all_fd(cfg.pty_master, data);
            if cfg.record_input && !recording_failed && rate_limiter.check(data.len()) {
                if let Err(e) = recorder.write_input(writer, data) {
                    recording_failed = true;
                    failure_reason = Some(e);
                    break 'event_loop;
                }
                let _ = recorder.write_input(extra, data);
            }
        }

        if writer.should_flush() {
            let _ = writer.flush();
        }
    }

    // Blocking wait for shell if not yet reaped.
    if !shell_exited {
        let mut status: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(cfg.shell_pid, &mut status, 0) };
        if ret > 0 {
            shell_exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            };
        }
    }

    let _ = writer.flush();

    LoopResult {
        shell_exit_code,
        recording_failed,
        failure_reason,
    }
}
