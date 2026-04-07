//! RAII wrapper that restores the terminal mode on drop, including on
//! panic. Replaces the previous manual `set_raw_mode` / `restore_terminal`
//! pair which leaked raw mode if anything between them panicked.

use std::io;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

pub struct TerminalGuard {
    saved: libc::termios,
    fd: RawFd,
}

impl TerminalGuard {
    /// Capture the current terminal attributes on `fd` and put it into
    /// raw mode. The original attributes are restored on drop, including
    /// when the current thread panics.
    pub fn enter_raw(fd: RawFd) -> io::Result<Self> {
        let mut saved = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr writes a full termios into the destination.
        let rc = unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: tcgetattr succeeded, so saved is initialized.
        let saved = unsafe { saved.assume_init() };

        let mut raw = saved;
        // SAFETY: cfmakeraw writes through the pointer in-place.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: tcsetattr reads raw, does not store the pointer.
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { saved, fd })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // SAFETY: same fd we opened with; saved remains valid until drop.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}
