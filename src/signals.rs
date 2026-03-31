use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{O_CLOEXEC, O_NONBLOCK};

pub static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);
pub static SIGCHLD_RECEIVED: AtomicBool = AtomicBool::new(false);
pub static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Write end of the self-pipe; set during `SignalState::setup()`.
static SIGNAL_PIPE_WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Async-signal-safe handler: set the relevant flag and wake the event loop.
pub extern "C" fn signal_handler(sig: libc::c_int) {
    match sig {
        libc::SIGWINCH => {
            SIGWINCH_RECEIVED.store(true, Ordering::Relaxed);
        }
        libc::SIGCHLD => {
            SIGCHLD_RECEIVED.store(true, Ordering::Relaxed);
        }
        libc::SIGTERM | libc::SIGHUP => {
            SIGTERM_RECEIVED.store(true, Ordering::Relaxed);
        }
        _ => {}
    }
    // Write a single byte to wake any poll/select waiting on the read end.
    // EAGAIN is fine — the pipe already has a byte pending.
    let wfd = SIGNAL_PIPE_WRITE.load(Ordering::Relaxed);
    if wfd >= 0 {
        let byte: u8 = sig as u8;
        unsafe {
            libc::write(wfd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

pub struct SignalState {
    pub pipe_read: RawFd,
    pub pipe_write: RawFd,
}

impl SignalState {
    /// Create the self-pipe and install signal handlers for SIGWINCH, SIGCHLD,
    /// SIGTERM, and SIGHUP.  SIGPIPE is set to SIG_IGN.
    pub fn setup() -> Result<Self, String> {
        let mut fds: [RawFd; 2] = [-1, -1];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) } < 0 {
            return Err(format!(
                "pipe2 failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let (pipe_read, pipe_write) = (fds[0], fds[1]);

        // Publish the write end so the handler can use it.
        SIGNAL_PIPE_WRITE.store(pipe_write, Ordering::Relaxed);

        // Install the handler for each signal we care about.
        for &sig in &[libc::SIGWINCH, libc::SIGCHLD, libc::SIGTERM, libc::SIGHUP] {
            let sa = libc::sigaction {
                sa_sigaction: signal_handler as *const () as libc::sighandler_t,
                sa_mask: unsafe {
                    let mut mask = std::mem::zeroed();
                    libc::sigemptyset(&mut mask);
                    mask
                },
                sa_flags: libc::SA_RESTART,
                sa_restorer: None,
            };
            if unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) } < 0 {
                unsafe {
                    libc::close(pipe_read);
                    libc::close(pipe_write);
                }
                return Err(format!(
                    "sigaction({sig}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        // Ignore SIGPIPE so that writes to closed pipes return EPIPE instead
        // of killing the process.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        Ok(SignalState {
            pipe_read,
            pipe_write,
        })
    }

    /// Drain all pending bytes from the read end of the self-pipe, swap the
    /// atomic flags, and return `(winch, chld, term)`.
    pub fn drain(&self) -> (bool, bool, bool) {
        // Drain the pipe (non-blocking).
        let mut buf = [0u8; 64];
        loop {
            let n =
                unsafe { libc::read(self.pipe_read, buf.as_mut_ptr() as *mut libc::c_void, 64) };
            if n <= 0 {
                break;
            }
        }

        let winch = SIGWINCH_RECEIVED.swap(false, Ordering::AcqRel);
        let chld = SIGCHLD_RECEIVED.swap(false, Ordering::AcqRel);
        let term = SIGTERM_RECEIVED.swap(false, Ordering::AcqRel);
        (winch, chld, term)
    }
}

impl Drop for SignalState {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.pipe_read);
            libc::close(self.pipe_write);
        }
        SIGNAL_PIPE_WRITE.store(-1, Ordering::Relaxed);
    }
}
