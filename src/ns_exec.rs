// epitropos-ns-exec — PID namespace helper.
// Creates PID + mount namespaces, remounts /proc, drops caps, execs shell.
// Deployed with cap_sys_admin+ep file capability.

use std::ffi::CString;

fn die(msg: &str) -> ! {
    eprintln!("epitropos-ns-exec: {msg}");
    std::process::exit(1);
}

fn has_cap_sys_admin() -> bool {
    // CAP_SYS_ADMIN = 21. Check effective set via prctl.
    // prctl(PR_CAPBSET_READ, cap) returns 1 if in bounding set.
    unsafe { libc::prctl(libc::PR_CAPBSET_READ, 21, 0, 0, 0) == 1 }
}

fn drop_all_caps() {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];

    unsafe {
        libc::syscall(libc::SYS_capset, &header, data.as_ptr());
    }

    // Drop bounding set caps
    for cap in 0..64u64 {
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
    }

    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        die("usage: epitropos-ns-exec <shell-path> <argv0> [args...]");
    }

    let shell_path = &args[1];
    let argv: Vec<CString> = args[2..]
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| die("null byte in arg")))
        .collect();

    if !has_cap_sys_admin() {
        die("CAP_SYS_ADMIN not present — install with file capabilities");
    }

    // Create new PID and mount namespaces for future children.
    if unsafe { libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) } < 0 {
        die(&format!("unshare: {}", std::io::Error::last_os_error()));
    }

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => die(&format!("fork: {}", std::io::Error::last_os_error())),
        0 => {
            // Child — PID 1 in new namespace.
            // Remount /proc to reflect the new PID namespace.
            let proc_path = CString::new("/proc").unwrap();
            let proc_type = CString::new("proc").unwrap();
            let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            if unsafe {
                libc::mount(
                    proc_type.as_ptr(),
                    proc_path.as_ptr(),
                    proc_type.as_ptr(),
                    flags,
                    std::ptr::null(),
                )
            } < 0
            {
                die(&format!("mount /proc: {}", std::io::Error::last_os_error()));
            }

            drop_all_caps();

            let c_shell = CString::new(shell_path.as_bytes())
                .unwrap_or_else(|_| die("null byte in shell path"));
            let argv_ptrs: Vec<*const libc::c_char> =
                argv.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

            unsafe { libc::execv(c_shell.as_ptr(), argv_ptrs.as_ptr()) };
            die(&format!("execv: {}", std::io::Error::last_os_error()));
        }
        child_pid => {
            // Parent — wait for child, propagate exit status.
            drop_all_caps();
            let mut status: libc::c_int = 0;
            loop {
                let ret = unsafe { libc::waitpid(child_pid, &mut status, 0) };
                if ret < 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    die(&format!("waitpid: {}", std::io::Error::last_os_error()));
                }
                break;
            }
            if libc::WIFEXITED(status) {
                std::process::exit(libc::WEXITSTATUS(status));
            }
            // Killed by signal — exit with 128 + signal
            if libc::WIFSIGNALED(status) {
                std::process::exit(128 + libc::WTERMSIG(status));
            }
            std::process::exit(1);
        }
    }
}
