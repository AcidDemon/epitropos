use std::ffi::CStr;
use std::fs;
use std::os::unix::io::RawFd;

use libc::{F_GETFD, F_SETFD, FD_CLOEXEC, O_NOCTTY, O_RDWR};

pub struct Pty {
    pub master: RawFd,
    pub slave_path: String,
}

impl Pty {
    /// Allocate a new PTY pair, returning a `Pty` with the master fd and
    /// slave device path.
    pub fn open() -> Result<Self, String> {
        // Open a new PTY master.
        let master = unsafe { libc::posix_openpt(O_RDWR | O_NOCTTY) };
        if master < 0 {
            return Err(format!(
                "posix_openpt failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set O_CLOEXEC on the master fd so it does not leak across exec.
        let flags = unsafe { libc::fcntl(master, F_GETFD) };
        if flags < 0 {
            unsafe { libc::close(master) };
            return Err(format!(
                "fcntl(F_GETFD) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(master, F_SETFD, flags | FD_CLOEXEC) } < 0 {
            unsafe { libc::close(master) };
            return Err(format!(
                "fcntl(F_SETFD, O_CLOEXEC) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Grant access to the slave device.
        if unsafe { libc::grantpt(master) } < 0 {
            unsafe { libc::close(master) };
            return Err(format!(
                "grantpt failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Unlock the slave device so it can be opened.
        if unsafe { libc::unlockpt(master) } < 0 {
            unsafe { libc::close(master) };
            return Err(format!(
                "unlockpt failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Retrieve the path of the slave device.
        let slave_path = unsafe {
            let ptr = libc::ptsname(master);
            if ptr.is_null() {
                libc::close(master);
                return Err(format!(
                    "ptsname failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            CStr::from_ptr(ptr)
                .to_str()
                .map_err(|e| {
                    libc::close(master);
                    format!("ptsname returned invalid UTF-8: {e}")
                })?
                .to_owned()
        };

        Ok(Pty { master, slave_path })
    }

    /// Open the slave side of the PTY pair and return its fd.
    pub fn open_slave(&self) -> Result<RawFd, String> {
        let path = std::ffi::CString::new(self.slave_path.as_bytes())
            .map_err(|e| format!("invalid slave path: {e}"))?;
        let fd = unsafe { libc::open(path.as_ptr(), O_RDWR | O_NOCTTY) };
        if fd < 0 {
            return Err(format!(
                "open slave PTY '{}' failed: {}",
                self.slave_path,
                std::io::Error::last_os_error()
            ));
        }
        Ok(fd)
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.master);
        }
    }
}

/// Query the terminal dimensions for `fd`.  Returns `(cols, rows)`.
pub fn get_terminal_size(fd: RawFd) -> Result<(u16, u16), String> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } < 0 {
        return Err(format!(
            "ioctl(TIOCGWINSZ) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((ws.ws_col, ws.ws_row))
}

/// Set the terminal dimensions for `fd`.
pub fn set_terminal_size(fd: RawFd, cols: u16, rows: u16) -> Result<(), String> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } < 0 {
        return Err(format!(
            "ioctl(TIOCSWINSZ) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Close all file descriptors >= `min_fd` by enumerating `/proc/self/fd`.
pub fn close_fds_above(min_fd: RawFd) {
    let dir = match fs::read_dir("/proc/self/fd") {
        Ok(d) => d,
        Err(_) => return,
    };
    // Collect into a Vec first so we are not iterating the directory while
    // closing the fd that backs the directory stream.
    let fds: Vec<RawFd> = dir
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let s = name.to_str()?;
            s.parse::<RawFd>().ok()
        })
        .filter(|&fd| fd >= min_fd)
        .collect();

    for fd in fds {
        unsafe {
            libc::close(fd);
        }
    }
}
